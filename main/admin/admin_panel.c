#include "admin_panel.h"
#include "json_esc.h"
#include "alarm.h"
#include "settings.h"
#include "api_ext.h"
#include "notify.h"
#include "api_cam.h"
#include "api_devices.h"
#include "api_oui.h"
#include "api_devlog.h"
#include "api_tasks.h"
#include "api_crash.h"
#include "crash.h"
#include "wifi_roam.h"
#include "web_assets.h"
#include "api_pihole.h"
#include "sd_log.h"
#include "ws_server.h"
#include "log_store.h"
#include "wifi_manager.h"
#include "geoip.h"
#include "ignore.h"
#include "describe.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "mbedtls/base64.h"
#include "esp_ota_ops.h"
#include "esp_heap_caps.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

static const char *TAG = "ADMIN";

// Dashboard HTML: served gzip-compressed by web_assets.c (fork).

// ── JSON helper ───────────────────────────────────────────────────────────────

// Escape a string for use as a JSON string value (between the double-quotes):
// json_esc() (fork), which also turns bytes that are not UTF-8 into U+FFFD.
// Returns number of bytes written (excluding null terminator).
static int json_escape_str(const char *src, char *dst, size_t dstlen)
{
    return (int)json_esc(src, (size_t)-1, dst, dstlen);
}

// ── Authentication ────────────────────────────────────────────────────────────

static bool check_auth(const char *req)
{
    const char *p = strstr(req, "Authorization: Basic ");
    if (!p) return false;
    p += 21;

    char b64[128] = {0};
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < sizeof(b64) - 1)
        b64[i++] = *p++;

    unsigned char decoded[128] = {0};
    size_t olen = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded), &olen,
                              (const unsigned char *)b64, i) != 0)
        return false;

    // Build expected "admin:<password>" and compare.
    // ADMIN_PASSWORD is never written to the log anywhere in this file.
    char expected[128];
    settings_t st;
    settings_copy(&st);
    int elen = snprintf(expected, sizeof(expected), "admin:%s", st.admin_password);
    memset(&st, 0, sizeof(st));
    bool ok = elen > 0 && (size_t)elen < sizeof(expected) &&
              (int)olen == elen && memcmp(decoded, expected, (size_t)olen) == 0;
    memset(expected, 0, sizeof(expected));
    memset(decoded, 0, sizeof(decoded));
    return ok;
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

static void send_401(int sock)
{
    const char resp[] =
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"ShadowSentry\"\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

static void send_204(int sock)
{
    const char resp[] =
        "HTTP/1.1 204 No Content\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

static void send_404(int sock)
{
    const char resp[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

// ── Route handlers ────────────────────────────────────────────────────────────

static void serve_status_json(int sock)
{
    int8_t rssi = 0;
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        rssi = ap.rssi;

    alarm_info_t a;
    alarm_get(&a);
    // PSRAM, made once: the admin task serves one client at a time.
    enum { ALARM_J = WS_ALARM_JSON_MAX, EXT_J = 512, JSON_MAX = WS_ALARM_JSON_MAX + EXT_J + 384 };
    static char *alarm_j, *json, *ext_j;
    if (!alarm_j) alarm_j = heap_caps_malloc(ALARM_J, MALLOC_CAP_SPIRAM);
    if (!json)    json    = heap_caps_malloc(JSON_MAX, MALLOC_CAP_SPIRAM);
    if (!ext_j)   ext_j   = heap_caps_malloc(EXT_J, MALLOC_CAP_SPIRAM);
    if (!alarm_j || !json || !ext_j) { send_404(sock); return; }
    ws_format_alarm_json(&a, alarm_j, ALARM_J);

    // Fork: the newest crash record (storage/crash.c) and the Wi-Fi link
    // (wifi_roam.c), each string escaped.
    {
        char e1[128], e2[64];
        int o = 0;
        crash_summary_t c;
        if (crash_last(&c)) {
            json_escape_str(c.cause, e1, sizeof(e1));
            json_escape_str(c.task, e2, sizeof(e2));
            o = snprintf(ext_j, EXT_J,
                ",\"last_crash\":{\"ts\":%lu,\"cause\":\"%s\",\"pc\":\"0x%08lx\",\"task\":\"%s\"}",
                (unsigned long)c.ts, e1, (unsigned long)c.pc, e2);
            if (o < 0 || o >= EXT_J) o = 0;
        }
        wifi_link_t w;
        wifi_roam_link(&w);
        char bssid[18] = "";
        if (w.up) wifi_manager_format_mac(w.bssid, bssid, sizeof(bssid));
        json_escape_str(w.ssid, e1, sizeof(e1));
        int k = snprintf(ext_j + o, EXT_J - o,
            ",\"wifi\":{\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%u,\"rssi\":%d,\"roams\":%lu}",
            e1, bssid, (unsigned)w.channel, (int)w.rssi, (unsigned long)w.roams);
        if (k < 0 || k >= EXT_J - o) ext_j[o] = '\0';
    }

    // No serial console on the board any more: the reset reason and the
    // internal heap figures come from here instead.
    int len = snprintf(json, JSON_MAX,
        "{\"uptime_s\":%llu,\"free_heap\":%lu,\"rssi\":%d,"
        "\"reset_reason\":\"%s\",\"internal_free\":%lu,\"internal_min\":%lu,"
        "\"internal_after_boot\":%lu,\"alarm\":%s%s}",
        (unsigned long long)(esp_timer_get_time() / 1000000ULL),
        (unsigned long)esp_get_free_heap_size(),
        (int)rssi, notify_boot_reason(),
        (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        (unsigned long)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
        (unsigned long)notify_boot_heap(), alarm_j, ext_j);

    char hdr[160];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        len);
    send(sock, hdr, hdr_len, 0);
    send(sock, json, len, 0);
}

static void serve_attacks_json(int sock)
{
    // Static, not stack: ADMIN_MAX_LOG_ENTRIES × sizeof(attack_log_t) is ~12 KB,
    // which alone overflows the admin task stack. Safe because the accept loop is
    // single-threaded — only one client is served at a time on Core 1 (same
    // reasoning as the static json[] buffer below).
    // PSRAM, allocated once (PlatformIO can't link EXT_RAM_BSS_ATTR).
    static attack_log_t *entries;
    static char         *json;
    if (!entries) entries = heap_caps_malloc(ADMIN_MAX_LOG_ENTRIES * sizeof(*entries), MALLOC_CAP_SPIRAM);
    if (!json)    json    = heap_caps_malloc(ADMIN_JSON_BUF_SIZE, MALLOC_CAP_SPIRAM);
    if (!entries || !json) { send_404(sock); return; }
    static uint32_t     seen_ips[ADMIN_MAX_LOG_ENTRIES];
    int      n      = log_store_get_recent(entries, ADMIN_MAX_LOG_ENTRIES);
    uint32_t total  = log_store_total_count();

    // Compute per-type counts and unique-IP count from the current window
    int      unique   = 0;
    int      by_type[ATTACK_TYPE_COUNT] = {0};   // index attack_type_t

    for (int i = 0; i < n; i++) {
        if ((unsigned)entries[i].type < ATTACK_TYPE_COUNT)
            by_type[(int)entries[i].type]++;

        bool dup = false;
        for (int j = 0; j < unique; j++) {
            if (seen_ips[j] == entries[i].src_ip) { dup = true; break; }
        }
        if (!dup && unique < ADMIN_MAX_LOG_ENTRIES)
            seen_ips[unique++] = entries[i].src_ip;
    }

    // Static buffer — safe because the accept loop is single-threaded
    // (only one client is processed at a time on Core 1).
    int pos = 0;
    int remaining = ADMIN_JSON_BUF_SIZE;

#define JPRINTF(...)  do { \
    int _n = snprintf(json + pos, (size_t)remaining, __VA_ARGS__); \
    /* snprintf returns the untruncated length: clamp, so a long entry can't */ \
    /* push pos past the buffer and the next call write out of bounds.     */ \
    if (_n >= remaining) _n = remaining > 0 ? remaining - 1 : 0; \
    if (_n > 0) { pos += _n; remaining -= _n; } \
} while(0)

    JPRINTF("{\"total\":%lu,\"unique_ips\":%d,\"by_type\":[", (unsigned long)total, unique);
    for (int t = 0; t < ATTACK_TYPE_COUNT; t++) JPRINTF("%s%d", t ? "," : "", by_type[t]);
    JPRINTF("],\"entries\":[");

    for (int i = 0; i < n && remaining > 680; i++) {
        // Escape all attacker-supplied strings before embedding in JSON
        char user_j[96],  pass_j[192], pay_j[512], hl[DESCRIBE_MAX], hl_j[2 * DESCRIBE_MAX];
        json_escape_str(entries[i].username, user_j, sizeof(user_j));
        json_escape_str(entries[i].password, pass_j, sizeof(pass_j));
        json_escape_str(entries[i].payload,  pay_j,  sizeof(pay_j));
        describe_event(&entries[i], hl, sizeof(hl));        // computed when served
        json_escape_str(hl, hl_j, sizeof(hl_j));

        // MAC + vendor: both from local sources (ARP / built-in OUI table),
        // plain ASCII with no JSON metacharacters — safe to embed directly.
        char mac_j[WIFI_MAC_STR_LEN];
        wifi_manager_format_mac(entries[i].src_mac, mac_j, sizeof(mac_j));
        const char *vendor_j = wifi_manager_mac_vendor(entries[i].src_mac);

        // Threat-intel enrichment (cache lookup; empty fields if not yet resolved).
        // country/org are API-supplied → JSON-escaped; cc/asn/tag are safe tokens.
        geoip_info_t gi;
        char ctry_j[40] = "", org_j2[100] = "";
        if (geoip_lookup(entries[i].src_ip, &gi)) {
            json_escape_str(gi.country, ctry_j,  sizeof(ctry_j));
            json_escape_str(gi.org,     org_j2,  sizeof(org_j2));
        } else {
            gi.cc[0] = gi.asn[0] = gi.tag[0] = '\0';
        }

        if (i > 0) JPRINTF(",");
        // "ign": the source is on the ignore list now (logged, never alarms).
        JPRINTF("{\"ts\":%lu,\"ip\":%lu,\"type\":%d,\"ign\":%s,"
                "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\","
                "\"mac\":\"%s\",\"vendor\":\"%s\","
                "\"cc\":\"%s\",\"country\":\"%s\",\"org\":\"%s\","
                "\"asn\":\"%s\",\"geotag\":\"%s\",\"headline\":\"%s\",\"tier\":\"%s\",\"code\":\"%s\"}",
                (unsigned long)entries[i].timestamp,
                (unsigned long)entries[i].src_ip,
                (int)entries[i].type,
                ignore_match(entries[i].src_ip, entries[i].src_mac, describe_code(&entries[i])) ? "true" : "false",
                user_j, pass_j, pay_j,
                mac_j, vendor_j,
                gi.cc, ctry_j, org_j2, gi.asn, gi.tag,
                hl_j, describe_tier_key(describe_tier(&entries[i])), describe_code(&entries[i]));
    }

    JPRINTF("]}");
#undef JPRINTF

    char hdr[160];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        pos);
    send(sock, hdr, hdr_len, 0);
    send(sock, json, pos, 0);
}

// ── Request dispatch ──────────────────────────────────────────────────────────

// ── OTA firmware update ───────────────────────────────────────────────────────
//
// POST /api/ota with the raw app image (.pio/build/<env>/firmware.bin) as the
// body. Streams into the inactive OTA slot, validates the image, switches the
// boot slot and restarts. The new image must mark itself valid once Wi-Fi is
// up (main.c), or the bootloader rolls back on the next reset.

#define OTA_CHUNK 4096

static void send_text(int sock, const char *status, const char *msg)
{
    char hdr[160];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\nContent-Type: text/plain\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n",
        status, (int)strlen(msg));
    send(sock, hdr, n, 0);
    send(sock, msg, strlen(msg), 0);
}

static long header_content_length(const char *req)
{
    for (const char *p = req; (p = strchr(p, '\n')) != NULL; ) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) return strtol(p + 15, NULL, 10);
        if (*p == '\r' || *p == '\n') break;            // end of headers
    }
    return -1;
}

static void handle_ota(int sock, const char *req, int req_len)
{
    long total = header_content_length(req);
    const char *body = strstr(req, "\r\n\r\n");
    const esp_partition_t *slot = esp_ota_get_next_update_partition(NULL);
    if (total <= 0 || !body || !slot || total > (long)slot->size) {
        send_text(sock, "400 Bad Request", "need Content-Length and an image that fits the OTA slot\n");
        return;
    }
    body += 4;

    esp_ota_handle_t ota;
    if (esp_ota_begin(slot, (size_t)total, &ota) != ESP_OK) {
        send_text(sock, "500 Internal Server Error", "esp_ota_begin failed\n");
        return;
    }
    ESP_LOGW(TAG, "OTA: receiving %ld bytes into %s", total, slot->label);

    // Bytes of the body that arrived with the headers.
    long got = req_len - (long)(body - req);
    esp_err_t err = got > 0 ? esp_ota_write(ota, body, (size_t)got) : ESP_OK;

    struct timeval tv = {.tv_sec = 15, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    static char *chunk;   // PSRAM, allocated once; single-threaded accept loop
    if (!chunk) chunk = heap_caps_malloc(OTA_CHUNK, MALLOC_CAP_SPIRAM);
    if (!chunk) err = ESP_ERR_NO_MEM;
    while (err == ESP_OK && got < total) {
        int n = recv(sock, chunk, OTA_CHUNK, 0);
        if (n <= 0) { err = ESP_FAIL; break; }
        err = esp_ota_write(ota, chunk, (size_t)n);
        got += n;
    }

    if (err != ESP_OK) {
        esp_ota_abort(ota);
        ESP_LOGE(TAG, "OTA: transfer failed after %ld/%ld bytes", got, total);
        send_text(sock, "500 Internal Server Error", "transfer failed\n");
        return;
    }
    if (esp_ota_end(ota) != ESP_OK || esp_ota_set_boot_partition(slot) != ESP_OK) {
        ESP_LOGE(TAG, "OTA: image rejected");
        send_text(sock, "500 Internal Server Error", "image failed validation\n");
        return;
    }
    ESP_LOGW(TAG, "OTA: %ld bytes written to %s, restarting", total, slot->label);
    send_text(sock, "200 OK", "ok, restarting\n");
    sd_log_flush();                     // save the summary metrics first
    shutdown(sock, SHUT_RDWR);
    close(sock);
    vTaskDelay(pdMS_TO_TICKS(500));
    notify_restart_intent(NOTIFY_RESTART_OTA);     // the next boot's online message says so
    esp_restart();
}

static void handle_request(int sock, char *buf, int len);

// The request headers can exceed one TCP segment (a browser POST with all its
// headers runs to ~1 KB), so read until the blank line or the buffer is full.
#define ADMIN_REQ_MAX 2048

// ── Connections (fork) ────────────────────────────────────────────────────────
//
// Browsers open speculative (preconnect) sockets that send nothing for a
// while. Read with a blocking recv() one connection at a time, each of those
// held the loop for up to ADMIN_RECV_TIMEOUT_S while real requests queued
// behind it. Now up to ADMIN_CONN_MAX accepted connections are held at once
// and read without blocking under select(); whichever has a complete request
// head is handled. Handlers still run one at a time on this task (they share
// static and PSRAM buffers), so a long one (OTA, a device-log scan of 3 s at
// most) still holds the loop while it runs, but nothing waits on an idle socket.
#ifndef ADMIN_CONN_MAX
#define ADMIN_CONN_MAX      4       // held at once; counted in CONFIG_LWIP_MAX_SOCKETS
#endif
#define ADMIN_IDLE_MS       2000    // no new byte this long, head not complete: closed
#define ADMIN_EVICT_MS      500     // all slots busy: a silent one this old makes room
#define ADMIN_POLL_MS       200

typedef struct {
    int     fd;                     // -1: free
    int     len;                    // head bytes so far
    int64_t opened, last;           // accepted, last byte (esp_timer, us)
    char   *buf;                    // ADMIN_REQ_MAX, PSRAM
} admin_conn_t;

static admin_conn_t s_conn[ADMIN_CONN_MAX];

static void conn_close(admin_conn_t *c)
{
    memset(c->buf, 0, (size_t)c->len + 1);  // it held the Authorization header, maybe passwords
    close(c->fd);
    c->fd = -1;
    c->len = 0;
}

// A complete head: blocking reads with the usual timeout again (handlers read
// request bodies), then handled inline.
static void conn_serve(admin_conn_t *c)
{
    struct timeval tv = {.tv_sec = ADMIN_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    c->buf[c->len] = '\0';
    handle_request(c->fd, c->buf, c->len);
    conn_close(c);
}

// Take what is waiting, without blocking; serve or close as it turns out.
static void conn_read(admin_conn_t *c, int64_t now)
{
    int n = recv(c->fd, c->buf + c->len, ADMIN_REQ_MAX - 1 - c->len, MSG_DONTWAIT);
    if (n > 0) {
        c->len += n;
        c->buf[c->len] = '\0';
        c->last = now;
        if (strstr(c->buf, "\r\n\r\n") || c->len >= ADMIN_REQ_MAX - 1) conn_serve(c);
        return;
    }
    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) conn_close(c);
}

static void handle_request(int sock, char *buf, int len)
{
    if (!check_auth(buf)) {
        ESP_LOGD(TAG, "Auth failed");
        send_401(sock);
        return;
    }
    if (strncmp(buf, "POST", 4) == 0 && !api_ext_csrf_ok(buf)) {
        send_text(sock, "403 Forbidden", "POST needs an X-ShadowSentry header\n");
        return;
    }
    if (api_ext_handle(sock, buf, len)) return;   // fork routes (settings, logs, ...)
    if (api_cam_handle(sock, buf, len)) return;   // camera snapshot routes
    if (api_devices_handle(sock, buf, len)) return;   // LAN discovery table
    if (api_oui_handle(sock, buf, len)) return;       // vendor database upload and status
    if (api_devlog_handle(sock, buf, len)) return;    // one device's log lines
    if (api_tasks_handle(sock, buf, len)) return;     // per-task CPU share (no console)
    if (api_crash_handle(sock, buf, len)) return;     // crash records, debug crash
    if (api_pihole_handle(sock, buf, len)) return;    // Pi-hole status, test, refresh, device
    if (web_assets_handle(sock, buf, len)) return;    // device page, analysis.js (gzip)

    if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/attacks")) {
        serve_attacks_json(sock);
    } else if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/status")) {
        serve_status_json(sock);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/ota")) {
        handle_ota(sock, buf, len);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/clear")) {
        log_store_clear();
        ESP_LOGI(TAG, "Logs cleared via admin panel");
        send_204(sock);
    } else if (strncmp(buf, "GET", 3) == 0) {
        web_assets_dashboard(sock, buf);
    } else {
        send_404(sock);
    }
}

// ── Task entry point ──────────────────────────────────────────────────────────

void admin_panel_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(ADMIN_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, ADMIN_BACKLOG) == 0);

    // Password intentionally omitted from log — visible on the serial monitor
    // only to someone with physical access to the device.
    ESP_LOGI(TAG, "Admin panel on port %d (user: admin) — "
                  "http://<device-ip>:%d", ADMIN_PORT, ADMIN_PORT);

    for (int i = 0; i < ADMIN_CONN_MAX; i++) {
        s_conn[i].fd = -1;
        s_conn[i].buf = heap_caps_calloc(1, ADMIN_REQ_MAX, MALLOC_CAP_SPIRAM);
        configASSERT(s_conn[i].buf);
    }
    while (1) {
        int64_t now = esp_timer_get_time();
        fd_set rd;
        FD_ZERO(&rd);
        int maxfd = -1, slot = -1, evict = -1;
        for (int i = 0; i < ADMIN_CONN_MAX; i++) {
            admin_conn_t *c = &s_conn[i];
            if (c->fd < 0) { if (slot < 0) slot = i; continue; }
            FD_SET(c->fd, &rd);
            if (c->fd > maxfd) maxfd = c->fd;
            if (!c->len && now - c->opened > ADMIN_EVICT_MS * 1000LL &&
                (evict < 0 || c->opened < s_conn[evict].opened)) evict = i;
        }
        // Listen only when a connection can be taken, so a full table never spins.
        if (slot >= 0 || evict >= 0) {
            FD_SET(srv, &rd);
            if (srv > maxfd) maxfd = srv;
        }
        struct timeval tv = {.tv_sec = 0, .tv_usec = ADMIN_POLL_MS * 1000};
        int n = select(maxfd + 1, &rd, NULL, NULL, &tv);
        if (n < 0) { vTaskDelay(pdMS_TO_TICKS(ADMIN_POLL_MS)); continue; }

        if (n > 0 && FD_ISSET(srv, &rd)) {
            if (slot < 0) {                                 // make room: the oldest silent one
                ESP_LOGD(TAG, "Admin: dropped a connection that sent nothing");
                conn_close(&s_conn[evict]);
                slot = evict;
            }
            struct sockaddr_in client;
            socklen_t clen = sizeof(client);
            int csock = accept(srv, (struct sockaddr *)&client, &clen);
            if (csock >= 0) {
                ESP_LOGD(TAG, "Admin connection from %s", inet_ntoa(client.sin_addr));
                admin_conn_t *c = &s_conn[slot];
                c->fd = csock;
                c->len = 0;
                c->opened = c->last = esp_timer_get_time();
            }
        }
        for (int i = 0; i < ADMIN_CONN_MAX; i++) {
            admin_conn_t *c = &s_conn[i];
            if (c->fd < 0) continue;
            int64_t t = esp_timer_get_time();       // a handler above may have taken a while
            bool stale = t - c->last > ADMIN_IDLE_MS * 1000LL ||
                         t - c->opened > ADMIN_RECV_TIMEOUT_S * 1000000LL;
            // Read when select says so, and once more before closing a stale one
            // (bytes may have come in while a handler ran).
            if ((n > 0 && FD_ISSET(c->fd, &rd)) || stale) conn_read(c, t);
            if (c->fd >= 0 && (t - c->last > ADMIN_IDLE_MS * 1000LL ||
                               t - c->opened > ADMIN_RECV_TIMEOUT_S * 1000000LL)) conn_close(c);
        }
    }
}
