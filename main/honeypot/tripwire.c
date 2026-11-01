// Tripwire listeners: log the first bytes of any connection and close. See tripwire.h.

#include "tripwire.h"
#include "trap_listen.h"
#include "mikrotik.h"           // MikroTik decoys: raw TCP listeners, datagram ring, readers
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "detect.h"             // detect_note_logged(): no probe event besides ours
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <errno.h>
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

// How a service is served.
enum {
    TW_SOCK,        // a listen socket here; first bytes as hex
    TW_WINBOX,      // MikroTik decoys, served by mikrotik.c without sockets
    TW_API,
    TW_BTEST,
    TW_MNDP,
    TW_MACTELNET,
};

typedef struct {
    const char    *name;          // short, fixed: goes into the payload and the SD line
    uint16_t       port;          // 0 = disabled
    const uint8_t *banner;        // server-first bytes, NULL if the client speaks first
    uint8_t        banner_len;
    uint8_t        kind;          // TW_*
} trip_svc_t;

// Append new services at the end; the index is only used inside this task.
// describe.c gives each name its code.
static const trip_svc_t SVC[] = {
    { "RDP",            TRIPWIRE_RDP_PORT,       NULL, 0, TW_SOCK },
    { "VNC",            TRIPWIRE_VNC_PORT,       (const uint8_t *)VNC_BANNER, sizeof(VNC_BANNER) - 1, TW_SOCK },
    { "SMB",            TRIPWIRE_SMB_PORT,       NULL, 0, TW_SOCK },
    { "Redis",          TRIPWIRE_REDIS_PORT,     NULL, 0, TW_SOCK },
    { "MySQL",          TRIPWIRE_MYSQL_PORT,     MYSQL_GREETING, sizeof(MYSQL_GREETING), TW_SOCK },
    { "MSSQL",          TRIPWIRE_MSSQL_PORT,     NULL, 0, TW_SOCK },
    { "JetDirect",      TRIPWIRE_JETDIRECT_PORT, NULL, 0, TW_SOCK },
    { "Winbox",         TRIPWIRE_WINBOX_PORT,    NULL, 0, TW_WINBOX },
    { "RouterOS API",   TRIPWIRE_ROSAPI_PORT,    NULL, 0, TW_API },
    { "Bandwidth test", TRIPWIRE_BTEST_PORT,     NULL, 0, TW_BTEST },      // mikrotik.c sends the hello
    { "MNDP",           TRIPWIRE_MNDP_PORT,      NULL, 0, TW_MNDP },
    { "MAC-Telnet",     TRIPWIRE_MACTELNET_PORT, NULL, 0, TW_MACTELNET },
};
#define SVC_N ((int)(sizeof(SVC) / sizeof(SVC[0])))
_Static_assert(SVC_N <= 255, "hold_t.svc is a uint8_t");

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

static int svc_of_kind(uint8_t kind)
{
    for (int i = 0; i < SVC_N; i++) if (SVC[i].kind == kind) return i;
    return -1;
}

// ── Rate limit: one event per source and service per hold time ───────────────

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
static bool hold_check(uint32_t ip, uint8_t svc, uint32_t now, uint32_t hold_s, uint16_t *held)
{
    hold_t *slot = NULL, *oldest = &s_hold[0];
    for (int i = 0; i < TRIPWIRE_HOLD_SLOTS; i++) {
        hold_t *h = &s_hold[i];
        if (!h->used) { if (!slot) slot = h; continue; }
        if (h->ip == ip && h->svc == svc) {
            if (now - h->last_ms < hold_s * 1000u) {
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

// ── Events ────────────────────────────────────────────────────────────────────

static uint8_t      s_rx[TRIPWIRE_RX_MAX];
static char         s_hex[TRIPWIRE_RX_MAX * 2 + 1];
static char         s_lead[128];            // readable part of the payload, before any hex
static attack_log_t s_ev;
static uint32_t     s_stack_low = UINT32_MAX;

static void hex_of(const uint8_t *b, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[b[i] >> 4];
        out[2 * i + 1] = H[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static void ip_text(uint32_t ip, char *buf, size_t len)
{
    struct in_addr a = { .s_addr = ip };
    strlcpy(buf, inet_ntoa(a), len);
}

// One event: "<service> on <port>[ (+N held)]: <lead><hex>", the hex cut at
// whole bytes to the payload; the console line has all of it. hex may be "".
static void emit(int idx, uint32_t ip, const uint8_t *mac, uint16_t held,
                 const char *user, const char *lead, const char *hex)
{
    const trip_svc_t *svc = &SVC[idx];
    memset(&s_ev, 0, sizeof(s_ev));
    s_ev.type      = ATTACK_TRIPWIRE;
    s_ev.src_ip    = ip;
    s_ev.timestamp = (uint32_t)time(NULL);
    if (mac) memcpy(s_ev.src_mac, mac, 6);
    else if (ip) wifi_manager_lookup_mac(ip, s_ev.src_mac);
    if (user && user[0]) strlcpy(s_ev.username, user, sizeof(s_ev.username));

    char held_s[16] = "";
    if (held) snprintf(held_s, sizeof(held_s), " (+%u held)", (unsigned)held);
    int o = snprintf(s_ev.payload, sizeof(s_ev.payload), "%s on %u%s: %s",
                     svc->name, (unsigned)svc->port, held_s, lead);
    if (o < 0) o = 0;
    if (o > (int)sizeof(s_ev.payload) - 1) o = (int)sizeof(s_ev.payload) - 1;
    size_t hn = strlen(hex) / 2;
    size_t fit = (sizeof(s_ev.payload) - 1 - (size_t)o) / 2;           // whole bytes only
    if (fit > hn) fit = hn;
    memcpy(s_ev.payload + o, hex, fit * 2);
    s_ev.payload[o + fit * 2] = '\0';

    char ips[16];
    ip_text(ip, ips, sizeof(ips));
    ESP_LOGW(TAG, "[%s] %s on %u%s: %s%s", ips, svc->name, (unsigned)svc->port, held_s, lead, hex);
    log_store_append(&s_ev);
    telegram_notify(&s_ev);

    uint32_t hw = (uint32_t)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    if (hw < s_stack_low) {
        s_stack_low = hw;
        ESP_LOGI(TAG, "stack high-water %lu B free of %d", (unsigned long)hw, TRIPWIRE_TASK_STACK);
    }
}

// The rate limit, then the event or a console line for a held one.
static void report(int idx, uint32_t ip, const uint8_t *mac, uint32_t hold_s, int n,
                   const char *user, bool quiet_when_held)
{
    uint16_t held = 0;
    if (!hold_check(ip, (uint8_t)idx, now_ms(), hold_s, &held)) {
        if (!quiet_when_held) {
            char ips[16];
            ip_text(ip, ips, sizeof(ips));
            ESP_LOGI(TAG, "[%s] %s on %u, %d B (held, not logged): %s%s",
                     ips, SVC[idx].name, (unsigned)SVC[idx].port, n, s_lead, s_hex);
        }
        return;
    }
    emit(idx, ip, mac, held, user, s_lead, s_hex);
}

// ── Socket tripwires: one connection ──────────────────────────────────────────

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

    hex_of(s_rx, (size_t)n, s_hex);
    strlcpy(s_lead, n ? "" : "no data", sizeof(s_lead));
    report(idx, addr->sin_addr.s_addr, NULL, TRIPWIRE_HOLD_S, n, NULL, false);
}

// ── MikroTik decoys ───────────────────────────────────────────────────────────

static uint8_t   s_my_mac[6];
static uint32_t  s_wl_hits, s_mt_other;     // whitelisted datagrams, others' MAC-Telnet sessions
static uint32_t  s_cnt_seen[3];             // drop counters last reported
static uint32_t  s_cnt_ms;
static mt_mndp_t s_mndp;

#define UDP_HEX_MAX 32                      // bytes of hex for a datagram we cannot read
#define CNT_REPORT_MS 60000                 // drop counters: at most one line a minute

// A finished TCP decoy connection from mikrotik.c.
static void handle_tcp(const mt_tcp_result_t *r)
{
    static const uint8_t KIND[MT_TCP_N] = { [MT_TCP_WINBOX] = TW_WINBOX, [MT_TCP_API] = TW_API,
                                            [MT_TCP_BTEST] = TW_BTEST };
    if (r->kind >= MT_TCP_N) return;
    int idx = svc_of_kind(KIND[r->kind]);
    if (idx < 0) return;
    size_t n = r->n <= TRIPWIRE_RX_MAX ? r->n : TRIPWIRE_RX_MAX;
    const char *user = NULL;
    s_hex[0] = '\0';
    if (n == 0) {
        strlcpy(s_lead, "no data", sizeof(s_lead));
    } else if (r->kind == MT_TCP_API) {
        // Only the command word and the user name ever reach this task.
        if (!r->api_ok)
            snprintf(s_lead, sizeof(s_lead), "not API words, %u B", (unsigned)n);
        else if (r->api.user[0])
            snprintf(s_lead, sizeof(s_lead), "%.24s as %.24s, %u B", r->api.cmd, r->api.user, (unsigned)n);
        else
            snprintf(s_lead, sizeof(s_lead), "%.24s, %u B", r->api.cmd, (unsigned)n);
        if (r->api_ok && r->api.user[0]) user = r->api.user;
    } else {
        hex_of(r->data, n, s_hex);
        if (r->kind == MT_TCP_WINBOX) {
            bool more = r->total > TRIPWIRE_FRAME_MAX;
            snprintf(s_lead, sizeof(s_lead), "frame %lu%s B: ",
                     (unsigned long)(more ? TRIPWIRE_FRAME_MAX : r->total), more ? "+" : "");
        } else {
            char lab[16];
            if (mikrotik_btest_label(r->data, n, lab, sizeof(lab)))
                snprintf(s_lead, sizeof(s_lead), "%s, %u B: ", lab, (unsigned)n);
            else
                snprintf(s_lead, sizeof(s_lead), "%u B: ", (unsigned)n);
        }
    }
    report(idx, r->ip, NULL, TRIPWIRE_HOLD_S, (int)n, user, false);
}

// A whitelisted sender: counted; the first one is said on the console once,
// so the gateway's own MNDP announcement can be seen being skipped.
static void wl_note(const trip_svc_t *svc, const uint8_t mac[6])
{
    if (s_wl_hits++) return;
    char ms[18];
    uint8_t gw[6];
    wifi_manager_format_mac(mac, ms, sizeof(ms));
    bool is_gw = mikrotik_gateway_mac(gw) && !memcmp(gw, mac, 6);
    ESP_LOGI(TAG, "%s from %s (%s): whitelisted, counted, not reported (said once)",
             svc->name, ms, is_gw ? "the gateway" : "TRIPWIRE_MT_WHITELIST");
}

// A datagram from the ring (mikrotik.c's frame tap); d->mac is the frame's source.
static void handle_datagram(const mt_dgram_t *d)
{
    int idx = -1;
    for (int i = 0; i < SVC_N; i++)
        if ((SVC[i].kind == TW_MNDP || SVC[i].kind == TW_MACTELNET) && SVC[i].port == d->dport) { idx = i; break; }
    if (idx < 0) return;
    const trip_svc_t *svc = &SVC[idx];
    size_t n = d->len <= TRIPWIRE_UDP_RX_MAX ? d->len : TRIPWIRE_UDP_RX_MAX;
    s_hex[0] = '\0';

    if (mikrotik_whitelisted(d->mac)) { wl_note(svc, d->mac); return; }
    if (svc->kind == TW_MNDP) {
        switch (mikrotik_mndp_parse(d->data, n, &s_mndp)) {
        case MT_MNDP_SOLICIT:
            snprintf(s_lead, sizeof(s_lead), "solicitation, %u B", (unsigned)d->full_len);
            break;
        case MT_MNDP_ANNOUNCE:
            snprintf(s_lead, sizeof(s_lead), "announcement %.32s, %.32s, %.32s",
                     s_mndp.identity[0] ? s_mndp.identity : "?",
                     s_mndp.version[0] ? s_mndp.version : "?",
                     s_mndp.board[0] ? s_mndp.board : "?");
            break;
        default:
            snprintf(s_lead, sizeof(s_lead), "other, %u B: ", (unsigned)d->full_len);
            hex_of(d->data, n < UDP_HEX_MAX ? n : UDP_HEX_MAX, s_hex);
            break;
        }
    } else {
        mt_mactelnet_t m;
        if (!mikrotik_mactelnet_parse(d->data, n, &m)) {
            snprintf(s_lead, sizeof(s_lead), "other, %u B: ", (unsigned)d->full_len);
            hex_of(d->data, n < UDP_HEX_MAX ? n : UDP_HEX_MAX, s_hex);
        } else if (memcmp(m.dst, s_my_mac, 6)) {
            // Someone else's session (mactelnet broadcasts them): counted only.
            if (s_mt_other++ == 0) {
                char dm[18];
                wifi_manager_format_mac(m.dst, dm, sizeof(dm));
                ESP_LOGI(TAG, "MAC-Telnet %s for %s, not this device: counted, not reported (said once)",
                         mikrotik_mactelnet_ptype(m.ptype), dm);
            }
            return;
        } else {
            snprintf(s_lead, sizeof(s_lead), "%s to this device, %u B",
                     mikrotik_mactelnet_ptype(m.ptype), (unsigned)d->full_len);
        }
    }
    report(idx, d->ip, d->mac, TRIPWIRE_UDP_HOLD_S, (int)n, NULL, true);    // held ones only counted
}

static void decoys_drain(void)
{
    static mt_tcp_result_t r;               // off the 3 KB stack
    while (mikrotik_tcp_next(&r)) {
        handle_tcp(&r);
        memset(&r, 0, sizeof(r));
    }
    const mt_dgram_t *d;
    for (int k = 0; k < MT_UDP_SLOTS && (d = mikrotik_udp_peek()) != NULL; k++) {
        handle_datagram(d);
        mikrotik_udp_pop();
    }
    uint32_t c[3];
    mikrotik_counters(&c[0], &c[1], &c[2]);
    uint32_t t = now_ms();
    if (memcmp(c, s_cnt_seen, sizeof(c)) && t - s_cnt_ms >= CNT_REPORT_MS) {
        s_cnt_ms = t;
        memcpy(s_cnt_seen, c, sizeof(c));
        ESP_LOGW(TAG, "MikroTik decoys: %lu results dropped (queue full), %lu connections refused "
                 "(%d at once), %lu datagrams dropped (ring full), since boot",
                 (unsigned long)c[0], (unsigned long)c[1], MT_RAW_CONN_MAX, (unsigned long)c[2]);
    }
}

// ── Task ──────────────────────────────────────────────────────────────────────

void tripwire_task(void *arg)
{
    (void)arg;
    int      sock[SVC_N];
    static char list[320];          // startup line only: off the stack
    size_t   lo = 0;
    int      open = 0;

    esp_wifi_get_mac(WIFI_IF_STA, s_my_mac);
    int wl = mikrotik_whitelist_init();
    bool decoys = mikrotik_init();
    bool udp_on = mikrotik_udp_on();

    list[0] = '\0';
    for (int i = 0; i < SVC_N; i++) {
        uint8_t k = SVC[i].kind;
        bool up;
        sock[i] = -1;
        if (k == TW_SOCK) {
            sock[i] = trap_listen(SVC[i].port, TRIPWIRE_BACKLOG);
            up = sock[i] >= 0;
        } else if (k == TW_MNDP || k == TW_MACTELNET) {
            up = udp_on && SVC[i].port;
        } else {
            up = mikrotik_tcp_listening(k == TW_WINBOX ? MT_TCP_WINBOX : k == TW_API ? MT_TCP_API : MT_TCP_BTEST);
        }
        if (!up) continue;
        open++;
        if (lo < sizeof(list)) {
            int w = snprintf(list + lo, sizeof(list) - lo, "%s%s %s%u", lo ? ", " : "", SVC[i].name,
                             (k == TW_MNDP || k == TW_MACTELNET) ? "UDP " : "", (unsigned)SVC[i].port);
            if (w > 0) lo += (size_t)w;
        }
    }
    if (!open) {
        ESP_LOGW(TAG, "No tripwire port open, task ends");
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "Listening on %s (first bytes %d ms, %d B max, one event per source and service per %d s, "
             "UDP %d s; %d whitelisted MAC%s besides the gateway's)",
             list, TRIPWIRE_FIRST_MS, TRIPWIRE_RX_MAX, TRIPWIRE_HOLD_S, TRIPWIRE_UDP_HOLD_S,
             wl, wl == 1 ? "" : "s");

    while (1) {
        fd_set rd;
        FD_ZERO(&rd);
        int maxfd = -1;
        for (int i = 0; i < SVC_N; i++) {
            if (sock[i] < 0) continue;
            FD_SET(sock[i], &rd);
            if (sock[i] > maxfd) maxfd = sock[i];
        }
        // The decoys post to a queue and a ring, so wake up to drain them.
        struct timeval tv = { .tv_sec = 0, .tv_usec = TRIPWIRE_POLL_MS * 1000 };
        int r = 0;
        if (maxfd >= 0) r = select(maxfd + 1, &rd, NULL, NULL, decoys ? &tv : NULL);
        else vTaskDelay(pdMS_TO_TICKS(TRIPWIRE_POLL_MS));
        if (decoys) decoys_drain();
        if (r <= 0) continue;

        for (int i = 0; i < SVC_N; i++) {
            if (sock[i] < 0 || !FD_ISSET(sock[i], &rd)) continue;
            struct sockaddr_in client;
            socklen_t clen = sizeof(client);
            int csock = accept(sock[i], (struct sockaddr *)&client, &clen);
            if (csock < 0) {
                // Out of sockets (CONFIG_LWIP_MAX_SOCKETS): the connection stays
                // pending and select() stays ready, so back off instead of spinning.
                ESP_LOGW(TAG, "accept on port %u failed: errno %d", (unsigned)SVC[i].port, errno);
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }
            detect_note_logged(client.sin_addr.s_addr, SVC[i].port);   // logged or counted below, always
            handle_client(csock, i, &client);
            close(csock);
        }
    }
}
