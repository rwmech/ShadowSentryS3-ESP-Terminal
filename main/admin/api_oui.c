// Vendor database routes on the admin port. See api_oui.h.
//
// The body is untrusted: its length is capped before anything is allocated and
// the header is checked against that length before the card is touched.

#include "api_oui.h"
#include "oui.h"
#include "sd_log.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "API_OUI";

#define SEND_TIMEOUT_S  10
#define RECV_TIMEOUT_S  15
#define RECV_CHUNK      4096

static bool send_all(int sock, const void *p, size_t n)
{
    const char *c = p;
    while (n) {
        int r = send(sock, c, n, 0);
        if (r <= 0) return false;
        c += r;
        n -= (size_t)r;
    }
    return true;
}

static void send_json(int sock, const char *status, const char *body)
{
    char hdr[256];
    size_t len = strlen(body);
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, (unsigned)len);
    if (n > 0 && n < (int)sizeof(hdr) && send_all(sock, hdr, (size_t)n)) send_all(sock, body, len);
}

static long content_length(const char *req)
{
    for (const char *p = req; (p = strchr(p, '\n')) != NULL; ) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            char *end;
            long v = strtol(p + 15, &end, 10);
            return end == p + 15 ? -1 : v;
        }
        if (*p == '\r' || *p == '\n') break;
    }
    return -1;
}

static void get_status(int sock)
{
    oui_status_t s;
    oui_status(&s);
    sd_status_t sd;
    sd_log_status(&sd);
    char b[256];
    snprintf(b, sizeof(b),
        "{\"present\":%s,\"count\":%lu,\"build_ts\":%lu,\"size\":%lu,\"lookups\":%lu,\"hits\":%lu,"
        "\"queued\":%lu,\"pool_used\":%lu,\"card\":%s}",
        s.present ? "true" : "false", (unsigned long)s.count, (unsigned long)s.build_ts,
        (unsigned long)s.size, (unsigned long)s.lookups, (unsigned long)s.hits,
        (unsigned long)s.misses_queued, (unsigned long)s.pool_used, sd.mounted ? "true" : "false");
    send_json(sock, "200 OK", b);
}

static void post_upload(int sock, const char *req, int req_len)
{
    long total = content_length(req);
    const char *body = strstr(req, "\r\n\r\n");
    if (total <= 0 || !body) { send_json(sock, "411 Length Required", "{\"error\":\"need Content-Length\"}"); return; }
    if ((unsigned long)total > OUI_MAX_BYTES) { send_json(sock, "413 Payload Too Large", "{\"error\":\"over 4 MB\"}"); return; }
    if ((unsigned long)total < OUI_HDR_SIZE) { send_json(sock, "400 Bad Request", "{\"error\":\"not a vendor database\"}"); return; }
    sd_status_t sd;
    sd_log_status(&sd);
    if (!sd.mounted) { send_json(sock, "503 Service Unavailable", "{\"error\":\"no microSD card\"}"); return; }
    if (heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) < (size_t)total + 64 * 1024) {
        send_json(sock, "503 Service Unavailable", "{\"error\":\"not enough PSRAM\"}");
        return;
    }
    uint8_t *buf = heap_caps_malloc((size_t)total, MALLOC_CAP_SPIRAM);
    if (!buf) { send_json(sock, "503 Service Unavailable", "{\"error\":\"out of memory\"}"); return; }

    body += 4;
    long got = req_len - (long)(body - req);
    if (got < 0) got = 0;
    if (got > total) got = total;
    memcpy(buf, body, (size_t)got);
    struct timeval tv = { .tv_sec = RECV_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (got < total) {
        size_t want = (size_t)(total - got);
        if (want > RECV_CHUNK) want = RECV_CHUNK;
        int n = recv(sock, buf + got, want, 0);
        if (n <= 0) break;
        got += n;
    }
    uint32_t count = 0, built = 0;
    if (got != total) {
        free(buf);
        ESP_LOGW(TAG, "Vendor database upload cut off at %ld of %ld B", got, total);
        send_json(sock, "400 Bad Request", "{\"error\":\"upload cut off\"}");
        return;
    }
    if (!oui_header_ok(buf, (size_t)total, &count, &built)) {
        free(buf);
        send_json(sock, "400 Bad Request", "{\"error\":\"not a vendor database (header or size wrong)\"}");
        return;
    }
    if (!sd_log_write_file(OUI_PATH, buf, (size_t)total)) {     // owns buf from here, either way
        send_json(sock, "503 Service Unavailable", "{\"error\":\"card writer busy, try again\"}");
        return;
    }
    oui_invalidate();
    ESP_LOGI(TAG, "Vendor database: %lu prefixes, %ld B queued for %s", (unsigned long)count, total, OUI_PATH);
    char b[128];
    snprintf(b, sizeof(b), "{\"ok\":true,\"count\":%lu,\"build_ts\":%lu,\"size\":%ld}",
             (unsigned long)count, (unsigned long)built, total);
    send_json(sock, "200 OK", b);
}

bool api_oui_handle(int sock, const char *req, int req_len)
{
    bool get = !strncmp(req, "GET /api/oui", 12), post = !strncmp(req, "POST /api/oui", 13);
    if (!get && !post) return false;
    const char *p = req + (get ? 12 : 13);
    if (*p != ' ' && *p != '?') return false;
    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (get) get_status(sock);
    else     post_upload(sock, req, req_len);
    return true;
}
