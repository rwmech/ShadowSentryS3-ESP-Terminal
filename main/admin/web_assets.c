// The admin port's gzip-compressed web pages. See web_assets.h.

#include "web_assets.h"
#include "lwip/sockets.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

// EMBED_FILES (binary, no NUL added): main/gz/<name>.gz.
extern const uint8_t index_gz_start[]    asm("_binary_index_html_gz_start");
extern const uint8_t index_gz_end[]      asm("_binary_index_html_gz_end");
extern const uint8_t device_gz_start[]   asm("_binary_device_html_gz_start");
extern const uint8_t device_gz_end[]     asm("_binary_device_html_gz_end");
extern const uint8_t analysis_gz_start[] asm("_binary_analysis_js_gz_start");
extern const uint8_t analysis_gz_end[]   asm("_binary_analysis_js_gz_end");

#define SEND_TIMEOUT_S  10      // a client that stops reading can't hold the admin task

typedef struct {
    const uint8_t *start, *end;
    const char    *type;
    char           etag[12];    // "\"xxxxxxxx\"", worked out on first use
} asset_t;

static asset_t s_index    = { index_gz_start,    index_gz_end,    "text/html; charset=utf-8", "" };
static asset_t s_device   = { device_gz_start,   device_gz_end,   "text/html; charset=utf-8", "" };
static asset_t s_analysis = { analysis_gz_start, analysis_gz_end, "text/javascript; charset=utf-8", "" };

// ── Request headers ───────────────────────────────────────────────────────────

// The value of header name (case-insensitive) in the request head, up to the
// end of its line: pointer and length, or NULL.
static const char *header_value(const char *req, const char *name, size_t *len)
{
    size_t nl = strlen(name);
    for (const char *p = strchr(req, '\n'); p; p = strchr(p, '\n')) {
        p++;
        if (*p == '\r' || *p == '\n' || !*p) break;                 // end of the head
        if (strncasecmp(p, name, nl) != 0 || p[nl] != ':') continue;
        const char *v = p + nl + 1;
        while (*v == ' ' || *v == '\t') v++;
        const char *e = v;
        while (*e && *e != '\r' && *e != '\n') e++;
        *len = (size_t)(e - v);
        return v;
    }
    return NULL;
}

static bool contains_ci(const char *s, size_t n, const char *word)
{
    size_t w = strlen(word);
    for (size_t i = 0; i + w <= n; i++)
        if (strncasecmp(s + i, word, w) == 0) return true;
    return false;
}

static bool accepts_gzip(const char *req)
{
    size_t n;
    const char *v = header_value(req, "Accept-Encoding", &n);
    return v && contains_ci(v, n, "gzip") && !contains_ci(v, n, "gzip;q=0");
}

// ── Sending ───────────────────────────────────────────────────────────────────

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

static void send_asset(int sock, const char *req, asset_t *a)
{
    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    size_t len = (size_t)(a->end - a->start);
    if (!a->etag[0]) {                                  // FNV-1a over the compressed bytes
        uint32_t h = 2166136261u;
        for (size_t i = 0; i < len; i++) h = (h ^ a->start[i]) * 16777619u;
        snprintf(a->etag, sizeof(a->etag), "\"%08lx\"", (unsigned long)h);
    }
    char hdr[400];
    int n;
    if (!accepts_gzip(req)) {
        static const char msg[] = "This page is served gzip-compressed: use a browser, or curl --compressed.\n";
        n = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 406 Not Acceptable\r\nContent-Type: text/plain\r\nContent-Length: %u\r\n"
            "Connection: close\r\n\r\n", (unsigned)(sizeof(msg) - 1));
        if (n > 0 && n < (int)sizeof(hdr) && send_all(sock, hdr, (size_t)n)) send_all(sock, msg, sizeof(msg) - 1);
        return;
    }
    size_t il;
    const char *inm = header_value(req, "If-None-Match", &il);
    bool fresh = inm && il >= strlen(a->etag) && contains_ci(inm, il, a->etag);
    n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: %u\r\n"
        "ETag: %s\r\n"
        "Cache-Control: no-cache\r\n"
        "Vary: Accept-Encoding\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"                             // no clickjacking
        "Content-Security-Policy: frame-ancestors 'none'\r\n"
        "Connection: close\r\n\r\n",
        fresh ? "304 Not Modified" : "200 OK", a->type, fresh ? 0u : (unsigned)len, a->etag);
    if (n <= 0 || n >= (int)sizeof(hdr) || !send_all(sock, hdr, (size_t)n) || fresh) return;
    send_all(sock, a->start, len);
}

// ── Routes ────────────────────────────────────────────────────────────────────

// "GET <path>" followed by ' ' or '?'.
static bool is_get(const char *req, int req_len, const char *path)
{
    size_t pl = strlen(path);
    if (req_len < (int)(4 + pl + 1) || strncmp(req, "GET ", 4) != 0 || strncmp(req + 4, path, pl) != 0) return false;
    return req[4 + pl] == ' ' || req[4 + pl] == '?';
}

bool web_assets_handle(int sock, const char *req, int req_len)
{
    if (is_get(req, req_len, "/device"))      { send_asset(sock, req, &s_device);   return true; }
    if (is_get(req, req_len, "/analysis.js")) { send_asset(sock, req, &s_analysis); return true; }
    return false;
}

void web_assets_dashboard(int sock, const char *req)
{
    send_asset(sock, req, &s_index);
}
