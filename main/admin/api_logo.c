// Panel logo routes on the admin port. See api_logo.h.
//
// The body is untrusted: its length is capped before anything is allocated and
// the PNG signature and IHDR are checked, bounded by that length, before the
// card is touched. The panel checks the file again before it decodes it.

#include "api_logo.h"
#include "ui_logo.h"
#include "sd_log.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

static const char *TAG = "API_LOGO";

#define SEND_TIMEOUT_S  10
#define RECV_TIMEOUT_S  15
#define RECV_CHUNK      4096
#define SEND_CHUNK      4096

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

static bool send_head(int sock, const char *status, const char *ctype, size_t len, const char *source)
{
    char hdr[288];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "%s%s%s"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, ctype, (unsigned)len,
        source ? "X-Logo-Source: " : "", source ? source : "", source ? "\r\n" : "");
    if (n <= 0 || n >= (int)sizeof(hdr)) return false;
    return send_all(sock, hdr, (size_t)n);
}

static void send_json(int sock, const char *status, const char *body)
{
    size_t len = strlen(body);
    if (send_head(sock, status, "application/json", len, NULL)) send_all(sock, body, len);
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

// ── GET ───────────────────────────────────────────────────────────────────────

// The card's file, streamed, if it is there and its header checks out.
static bool send_card(int sock)
{
    sd_status_t sd;
    sd_log_status(&sd);
    if (!sd.mounted) return false;
    struct stat st;
    if (stat(UI_LOGO_PATH, &st) != 0 || st.st_size < 33 || st.st_size > UI_LOGO_MAX_BYTES) return false;
    FILE *f = fopen(UI_LOGO_PATH, "rb");
    if (!f) return false;
    uint8_t *buf = heap_caps_malloc(SEND_CHUNK, MALLOC_CAP_SPIRAM);
    if (!buf) { fclose(f); return false; }
    bool valid = fread(buf, 1, 33, f) == 33 && ui_logo_png_ok(buf, 33, NULL, NULL);
    if (valid) {                        // answered from here (a short read ends the body early)
        size_t total = (size_t)st.st_size, sent = 33;
        bool ok = send_head(sock, "200 OK", "image/png", total, "card") && send_all(sock, buf, 33);
        while (ok && sent < total) {
            size_t want = total - sent > SEND_CHUNK ? SEND_CHUNK : total - sent;
            size_t n = fread(buf, 1, want, f);
            if (n == 0) break;
            ok = send_all(sock, buf, n);
            sent += n;
        }
    }
    free(buf);
    fclose(f);
    return valid;
}

static void get_logo(int sock)
{
    if (send_card(sock)) return;
    size_t len;
    const uint8_t *png = ui_logo_builtin(&len);
    if (send_head(sock, "200 OK", "image/png", len, "built-in")) send_all(sock, png, len);
}

// ── POST ──────────────────────────────────────────────────────────────────────

static void post_logo(int sock, const char *req, int req_len)
{
    long total = content_length(req);
    const char *body = strstr(req, "\r\n\r\n");
    if (total <= 0 || !body) { send_json(sock, "411 Length Required", "{\"error\":\"need Content-Length\"}"); return; }
    if (total > UI_LOGO_MAX_BYTES) { send_json(sock, "413 Payload Too Large", "{\"error\":\"over 200 KB\"}"); return; }
    if (total < 33) { send_json(sock, "400 Bad Request", "{\"error\":\"not a PNG\"}"); return; }
    sd_status_t sd;
    sd_log_status(&sd);
    if (!sd.mounted) { send_json(sock, "503 Service Unavailable", "{\"error\":\"no microSD card\"}"); return; }
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
    if (got != total) {
        free(buf);
        ESP_LOGW(TAG, "Logo upload cut off at %ld of %ld B", got, total);
        send_json(sock, "400 Bad Request", "{\"error\":\"upload cut off\"}");
        return;
    }
    uint16_t w = 0, h = 0;
    if (!ui_logo_png_ok(buf, (size_t)total, &w, &h)) {
        free(buf);
        send_json(sock, "400 Bad Request", "{\"error\":\"not a PNG of at most 240 x 240 px\"}");
        return;
    }
    if (!sd_log_write_file(UI_LOGO_PATH, buf, (size_t)total)) {     // owns buf from here, either way
        send_json(sock, "503 Service Unavailable", "{\"error\":\"card writer busy, try again\"}");
        return;
    }
    ESP_LOGI(TAG, "Panel logo: %u x %u px, %ld B queued for %s (used from the next boot)",
             w, h, total, UI_LOGO_PATH);
    char b[96];
    snprintf(b, sizeof(b), "{\"ok\":true,\"width\":%u,\"height\":%u,\"size\":%ld}", w, h, total);
    send_json(sock, "200 OK", b);
}

bool api_logo_handle(int sock, const char *req, int req_len)
{
    bool get = !strncmp(req, "GET /api/ui/logo", 16), post = !strncmp(req, "POST /api/ui/logo", 17);
    if (!get && !post) return false;
    const char *p = req + (get ? 16 : 17);
    if (*p != ' ' && *p != '?') return false;
    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (get) get_logo(sock);
    else     post_logo(sock, req, req_len);
    return true;
}
