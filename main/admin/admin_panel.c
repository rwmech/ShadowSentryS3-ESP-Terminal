#include "admin_panel.h"
#include "alarm.h"
#include "settings.h"
#include "api_ext.h"
#include "discord.h"
#include "sd_log.h"
#include "ws_server.h"
#include "log_store.h"
#include "wifi_manager.h"
#include "geoip.h"
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

static const char *TAG = "ADMIN";

// Dashboard HTML — linked by CMake EMBED_TXTFILES directive in main/CMakeLists.txt
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

// ── JSON helper ───────────────────────────────────────────────────────────────

// Escape a string for use as a JSON string value (between the double-quotes).
// Handles: " \ \n \r \t and ASCII control chars < 0x20.
// Returns number of bytes written (excluding null terminator).
static int json_escape_str(const char *src, char *dst, size_t dstlen)
{
    size_t pos = 0;
    for (; *src && pos < dstlen - 2; src++) {
        unsigned char c = (unsigned char)*src;
        switch (c) {
            case '"':  dst[pos++] = '\\'; dst[pos++] = '"';  break;
            case '\\': dst[pos++] = '\\'; dst[pos++] = '\\'; break;
            case '\n': dst[pos++] = '\\'; dst[pos++] = 'n';  break;
            case '\r': dst[pos++] = '\\'; dst[pos++] = 'r';  break;
            case '\t': dst[pos++] = '\\'; dst[pos++] = 't';  break;
            default:
                if (c < 0x20) {
                    if (pos + 6 >= dstlen) goto done;
                    pos += snprintf(dst + pos, dstlen - pos, "\\u%04x", c);
                } else {
                    dst[pos++] = (char)c;
                }
        }
    }
done:
    dst[pos] = '\0';
    return (int)pos;
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
    char alarm_j[256];
    ws_format_alarm_json(&a, alarm_j, sizeof(alarm_j));

    char json[400];
    int len = snprintf(json, sizeof(json),
        "{\"uptime_s\":%llu,\"free_heap\":%lu,\"rssi\":%d,\"alarm\":%s}",
        (unsigned long long)(esp_timer_get_time() / 1000000ULL),
        (unsigned long)esp_get_free_heap_size(),
        (int)rssi, alarm_j);

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

static void serve_dashboard(int sock)
{
    size_t html_len = (size_t)(index_html_end - index_html_start);
    char hdr[256];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "X-Frame-Options: DENY\r\n"                             // no clickjacking
        "Content-Security-Policy: frame-ancestors 'none'\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        html_len);
    send(sock, hdr, hdr_len, 0);
    send(sock, index_html_start, html_len, 0);
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
    int      by_type[8] = {0};   // RTSP,HTTP,Telnet,SSH,FTP,ARP,WiFi,Shell

    for (int i = 0; i < n; i++) {
        if ((int)entries[i].type < 8)
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
    if (_n > 0) { pos += _n; remaining -= _n; } \
} while(0)

    JPRINTF("{\"total\":%lu,\"unique_ips\":%d,"
            "\"by_type\":[%d,%d,%d,%d,%d,%d,%d,%d],\"entries\":[",
            (unsigned long)total, unique,
            by_type[0], by_type[1], by_type[2], by_type[3],
            by_type[4], by_type[5], by_type[6], by_type[7]);

    for (int i = 0; i < n && remaining > 480; i++) {
        // Escape all attacker-supplied strings before embedding in JSON
        char user_j[96],  pass_j[192], pay_j[512];
        json_escape_str(entries[i].username, user_j, sizeof(user_j));
        json_escape_str(entries[i].password, pass_j, sizeof(pass_j));
        json_escape_str(entries[i].payload,  pay_j,  sizeof(pay_j));

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
        JPRINTF("{\"ts\":%lu,\"ip\":%lu,\"type\":%d,"
                "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\","
                "\"mac\":\"%s\",\"vendor\":\"%s\","
                "\"cc\":\"%s\",\"country\":\"%s\",\"org\":\"%s\","
                "\"asn\":\"%s\",\"geotag\":\"%s\"}",
                (unsigned long)entries[i].timestamp,
                (unsigned long)entries[i].src_ip,
                (int)entries[i].type,
                user_j, pass_j, pay_j,
                mac_j, vendor_j,
                gi.cc, ctry_j, org_j2, gi.asn, gi.tag);
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
    esp_restart();
}

static void handle_request(int sock, char *buf, int len);

// The request headers can exceed one TCP segment (a browser POST with all its
// headers runs to ~1 KB), so read until the blank line or the buffer is full.
#define ADMIN_REQ_MAX 2048

static void handle_client(int sock)
{
    static char *buf;   // PSRAM, allocated once; single-threaded accept loop
    if (!buf) buf = heap_caps_malloc(ADMIN_REQ_MAX, MALLOC_CAP_SPIRAM);
    if (!buf) return;
    struct timeval tv = {.tv_sec = ADMIN_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int len = 0;
    int64_t deadline = esp_timer_get_time() + ADMIN_RECV_TIMEOUT_S * 1000000LL;
    while (len < ADMIN_REQ_MAX - 1 && esp_timer_get_time() < deadline) {
        int n = recv(sock, buf + len, ADMIN_REQ_MAX - 1 - len, 0);
        if (n <= 0) break;
        len += n;
        buf[len] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (len <= 0) return;
    buf[len] = '\0';

    handle_request(sock, buf, len);
    memset(buf, 0, (size_t)len);   // it held the Authorization header, maybe passwords
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

    if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/attacks")) {
        serve_attacks_json(sock);
    } else if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/status")) {
        serve_status_json(sock);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/ota")) {
        handle_ota(sock, buf, len);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/ack")) {
        discord_note_dashboard_ack();   // so the Discord embed can say where
        alarm_ack();
        ESP_LOGI(TAG, "Incident acknowledged via admin panel");
        send_204(sock);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/clear")) {
        log_store_clear();
        ESP_LOGI(TAG, "Logs cleared via admin panel");
        send_204(sock);
    } else if (strncmp(buf, "GET", 3) == 0) {
        serve_dashboard(sock);
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

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) continue;

        ESP_LOGD(TAG, "Admin connection from %s", inet_ntoa(client.sin_addr));
        handle_client(csock);
        close(csock);
    }
}
