// Tripwire listeners: log the first bytes of any connection and close. See tripwire.h.

#include "tripwire.h"
#include "trap_listen.h"
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "detect.h"             // detect_note_logged(): no probe event besides ours
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "TRIPWIRE";

// ── Services ──────────────────────────────────────────────────────────────────

// MySQL 5.7 initial handshake (protocol 10): version "5.7.44", connection id
// 11, a fixed 20-byte salt, capabilities 0x81fff7ff (CLIENT_SSL cleared, so the
// client sends its login packet in clear), utf8_general_ci, autocommit, and
// mysql_native_password. Constant bytes; nothing the client sends is parsed.
static const uint8_t MYSQL_GREETING[] = {
    0x4a, 0x00, 0x00, 0x00,                                 // length 74, sequence 0
    0x0a,                                                   // protocol 10
    '5', '.', '7', '.', '4', '4', 0x00,                     // server version
    0x0b, 0x00, 0x00, 0x00,                                 // connection id
    0x2f, 0x51, 0x6b, 0x3a, 0x5d, 0x27, 0x62, 0x41,         // salt, part 1
    0x00,                                                   // filler
    0xff, 0xf7,                                             // capabilities, low
    0x21,                                                   // utf8_general_ci
    0x02, 0x00,                                             // SERVER_STATUS_AUTOCOMMIT
    0xff, 0x81,                                             // capabilities, high
    0x15,                                                   // salt length 21
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                           // reserved
    0x4c, 0x6e, 0x23, 0x59, 0x7a, 0x31, 0x58, 0x6f, 0x5e, 0x46, 0x2c, 0x70, 0x00,  // salt, part 2
    'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_',
    'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00,
};
_Static_assert(sizeof(MYSQL_GREETING) == 4 + 0x4a, "MYSQL_GREETING: length field");

static const char VNC_BANNER[] = "RFB 003.008\n";

typedef struct {
    const char    *name;          // short, fixed: goes into the payload and the SD line
    uint16_t       port;          // 0 = disabled
    const uint8_t *banner;        // server-first bytes, NULL if the client speaks first
    uint8_t        banner_len;
} trip_svc_t;

// Append new services at the end; the index is only used inside this task.
static const trip_svc_t SVC[] = {
    { "RDP",       TRIPWIRE_RDP_PORT,       NULL, 0 },
    { "VNC",       TRIPWIRE_VNC_PORT,       (const uint8_t *)VNC_BANNER, sizeof(VNC_BANNER) - 1 },
    { "SMB",       TRIPWIRE_SMB_PORT,       NULL, 0 },
    { "Redis",     TRIPWIRE_REDIS_PORT,     NULL, 0 },
    { "MySQL",     TRIPWIRE_MYSQL_PORT,     MYSQL_GREETING, sizeof(MYSQL_GREETING) },
    { "MSSQL",     TRIPWIRE_MSSQL_PORT,     NULL, 0 },
    { "JetDirect", TRIPWIRE_JETDIRECT_PORT, NULL, 0 },
};
#define SVC_N ((int)(sizeof(SVC) / sizeof(SVC[0])))

const char *tripwire_service_key(const char *payload)
{
    if (!payload) return NULL;
    for (int i = 0; i < SVC_N; i++) {
        size_t n = strlen(SVC[i].name);
        if (strncmp(payload, SVC[i].name, n) == 0 && strncmp(payload + n, " on ", 4) == 0)
            return SVC[i].name;
    }
    return NULL;
}

// ── Rate limit: one event per source and service per TRIPWIRE_HOLD_S ─────────

typedef struct {
    uint32_t ip;
    uint32_t last_ms;             // when the last event for this key was logged
    uint16_t held;                // connections since then, not logged
    uint8_t  svc;
    uint8_t  used;
} hold_t;

static hold_t s_hold[TRIPWIRE_HOLD_SLOTS];

static inline uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

// True if this connection gets an event; *held is the count to report with it.
static bool hold_check(uint32_t ip, uint8_t svc, uint32_t now, uint16_t *held)
{
    hold_t *slot = NULL, *oldest = &s_hold[0];
    for (int i = 0; i < TRIPWIRE_HOLD_SLOTS; i++) {
        hold_t *h = &s_hold[i];
        if (!h->used) { if (!slot) slot = h; continue; }
        if (h->ip == ip && h->svc == svc) {
            if (now - h->last_ms < TRIPWIRE_HOLD_S * 1000u) {
                if (h->held < UINT16_MAX) h->held++;
                return false;
            }
            *held = h->held;
            h->held = 0;
            h->last_ms = now;
            return true;
        }
        if (now - h->last_ms > now - oldest->last_ms) oldest = h;
    }
    if (!slot) slot = oldest;   // full: forget the stalest key (its held count is lost)
    *slot = (hold_t){ .ip = ip, .last_ms = now, .svc = svc, .used = 1 };
    *held = 0;
    return true;
}

// ── One connection ────────────────────────────────────────────────────────────

static uint8_t      s_rx[TRIPWIRE_RX_MAX];
static char         s_hex[TRIPWIRE_RX_MAX * 2 + 1];
static attack_log_t s_ev;
static uint32_t     s_stack_low = UINT32_MAX;

// One recv() of up to len bytes, waiting at most wait_ms but never past deadline.
static int rx_once(int sock, uint8_t *buf, size_t len, uint32_t wait_ms, int64_t deadline_us)
{
    int64_t left_us = deadline_us - esp_timer_get_time();
    if (left_us <= 0 || len == 0) return 0;
    int64_t to_us = (int64_t)wait_ms * 1000;
    if (to_us > left_us) to_us = left_us;
    if (to_us < 1000) to_us = 1000;
    struct timeval tv = { .tv_sec = to_us / 1000000, .tv_usec = to_us % 1000000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int r = recv(sock, buf, len, 0);
    return r > 0 ? r : 0;
}

static void hex_of(const uint8_t *b, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[b[i] >> 4];
        out[2 * i + 1] = H[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static void handle_client(int sock, int idx, const struct sockaddr_in *addr)
{
    const trip_svc_t *svc = &SVC[idx];
    int64_t deadline_us = esp_timer_get_time() + (int64_t)TRIPWIRE_CONN_MS * 1000;

    // A client that never reads must not pin the task in send().
    struct timeval stv = { .tv_sec = TRIPWIRE_SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
    if (svc->banner_len) send(sock, svc->banner, svc->banner_len, 0);   // one try, a few bytes

    int n = rx_once(sock, s_rx, sizeof(s_rx), TRIPWIRE_FIRST_MS, deadline_us);
    if (n > 0 && n < (int)sizeof(s_rx))
        n += rx_once(sock, s_rx + n, sizeof(s_rx) - (size_t)n, TRIPWIRE_MORE_MS, deadline_us);

    char ip[16];
    strlcpy(ip, inet_ntoa(addr->sin_addr), sizeof(ip));
    hex_of(s_rx, (size_t)n, s_hex);

    uint16_t held = 0;
    if (!hold_check(addr->sin_addr.s_addr, (uint8_t)idx, now_ms(), &held)) {
        ESP_LOGI(TAG, "[%s] %s on %u, %d B (held, not logged): %s",
                 ip, svc->name, (unsigned)svc->port, n, n ? s_hex : "no data");
        return;
    }

    memset(&s_ev, 0, sizeof(s_ev));
    s_ev.type      = ATTACK_TRIPWIRE;
    s_ev.src_ip    = addr->sin_addr.s_addr;
    s_ev.timestamp = (uint32_t)time(NULL);
    wifi_manager_lookup_mac(addr->sin_addr.s_addr, s_ev.src_mac);

    char held_s[16] = "";
    if (held) snprintf(held_s, sizeof(held_s), " (+%u held)", (unsigned)held);
    int o = snprintf(s_ev.payload, sizeof(s_ev.payload), "%s on %u%s: ",
                     svc->name, (unsigned)svc->port, held_s);
    if (o < 0) o = 0;
    if (o > (int)sizeof(s_ev.payload) - 1) o = (int)sizeof(s_ev.payload) - 1;
    if (n == 0) {
        strlcpy(s_ev.payload + o, "no data", sizeof(s_ev.payload) - (size_t)o);
    } else {
        size_t fit = (sizeof(s_ev.payload) - 1 - (size_t)o) / 2;    // whole bytes only
        if (fit > (size_t)n) fit = (size_t)n;
        memcpy(s_ev.payload + o, s_hex, fit * 2);
        s_ev.payload[o + fit * 2] = '\0';
    }

    ESP_LOGW(TAG, "[%s] %s on %u%s, %d B: %s",
             ip, svc->name, (unsigned)svc->port, held_s, n, n ? s_hex : "no data");
    log_store_append(&s_ev);
    telegram_notify(&s_ev);

    uint32_t hw = (uint32_t)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    if (hw < s_stack_low) {
        s_stack_low = hw;
        ESP_LOGI(TAG, "stack high-water %lu B free of %d", (unsigned long)hw, TRIPWIRE_TASK_STACK);
    }
}

// ── Task ──────────────────────────────────────────────────────────────────────

void tripwire_task(void *arg)
{
    (void)arg;
    int      srv[SVC_N];
    uint16_t ports[SVC_N];
    static char list[160];          // startup line only: off the stack
    size_t   lo = 0;
    int      open = 0;

    list[0] = '\0';
    for (int i = 0; i < SVC_N; i++) {
        ports[i] = SVC[i].port;
        srv[i]   = trap_listen(SVC[i].port, TRIPWIRE_BACKLOG);
        if (srv[i] < 0) continue;
        open++;
        if (lo < sizeof(list)) {
            int w = snprintf(list + lo, sizeof(list) - lo, "%s%s %u",
                             lo ? ", " : "", SVC[i].name, (unsigned)SVC[i].port);
            if (w > 0) lo += (size_t)w;
        }
    }
    if (!open) {
        ESP_LOGW(TAG, "No tripwire port open, task ends");
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "Listening on %s (first bytes %d ms, %d B max, one event per source and service per %d s)",
             list, TRIPWIRE_FIRST_MS, TRIPWIRE_RX_MAX, TRIPWIRE_HOLD_S);

    while (1) {
        struct sockaddr_in client;
        uint16_t port = 0;
        int csock = trap_accept_any(srv, ports, SVC_N, &client, &port);
        if (csock < 0) continue;
        int idx = -1;
        for (int i = 0; i < SVC_N; i++) if (srv[i] >= 0 && ports[i] == port) { idx = i; break; }
        if (idx >= 0) {
            detect_note_logged(client.sin_addr.s_addr, port);    // logged or counted below, always
            handle_client(csock, idx, &client);
        }
        close(csock);
    }
}
