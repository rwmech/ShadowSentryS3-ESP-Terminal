// Block list routes, and the router's unauthenticated fetch. See api_block.h.
// Fork addition, Robert Mech.
//
// Runs on the admin task (8 KB internal stack): bodies and replies are PSRAM,
// allocated per request.

#include "api_block.h"
#include "blocklist.h"
#include "router_trip.h"
#include "mikrotik_watch.h"
#include "json_esc.h"
#include "wifi_manager.h"
#include "cJSON.h"
#include "lwip/sockets.h"
#include "lwip/ip4_addr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "BLOCKAPI";

#define BODY_MAX    512
#define LIST_JSON   (16 * 1024)     // 64 entries at about 120 B, the never list, the counters
#define TEXT_MAX    (BLOCK_MAX * 24)

// ── Replies ───────────────────────────────────────────────────────────────────

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

static void send_body(int sock, const char *status, const char *type, const char *body, size_t len)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, type, (unsigned)len);
    if (n <= 0 || n >= (int)sizeof(hdr)) return;
    if (send_all(sock, hdr, (size_t)n) && len) send_all(sock, body, len);
}

static void send_err(int sock, const char *status, const char *msg)
{
    char esc[200], b[240];
    json_esc(msg, 160, esc, sizeof(esc));
    int n = snprintf(b, sizeof(b), "{\"error\":\"%s\"}", esc);
    send_body(sock, status, "application/json", b, (size_t)(n > 0 && n < (int)sizeof(b) ? n : 0));
}

static void ip_s(uint32_t ip, char *b, size_t n) { ip4_addr_t a = { .addr = ip }; ip4addr_ntoa_r(&a, b, (int)n); }

// Strict dotted quad.
static bool parse_ipv4(const char *t, uint32_t *out)
{
    uint8_t b[4];
    if (!t) return false;
    for (int i = 0; i < 4; i++) {
        if (*t < '0' || *t > '9') return false;
        unsigned v = 0, d = 0;
        while (*t >= '0' && *t <= '9') {
            v = v * 10 + (unsigned)(*t++ - '0');
            if (++d > 3 || v > 255) return false;
        }
        b[i] = (uint8_t)v;
        if (i < 3 && *t++ != '.') return false;
    }
    if (*t) return false;
    memcpy(out, b, 4);
    return true;
}

// ── The router's fetch (no auth) ──────────────────────────────────────────────

static bool peer_ip(int sock, uint32_t *ip)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    if (getpeername(sock, (struct sockaddr *)&a, &l) != 0 || a.sin_family != AF_INET) return false;
    *ip = a.sin_addr.s_addr;
    return true;
}

bool api_block_public(int sock, const char *req, int req_len)
{
    (void)req_len;
    static const char PATH[] = "GET /routeros/block.txt";
    if (strncmp(req, PATH, sizeof(PATH) - 1)) return false;
    char c = req[sizeof(PATH) - 1];
    if (c != ' ' && c != '?') return false;

    uint32_t ip = 0, rip = router_trip_router_ip();
    if (!rip) rip = mikrotik_watch_router_ip();
    uint8_t m[6], gw[6];
    bool ok = rip && peer_ip(sock, &ip) && ip == rip && wifi_manager_lookup_mac(ip, m);
    if (ok) {
        uint32_t g;
        ok = router_trip_gateway_mac(gw) || (wifi_manager_get_gateway(&g) && wifi_manager_lookup_mac(g, gw));
        ok = ok && !memcmp(m, gw, 6);
    }
    if (!ok) {
        blocklist_note_fetch(false);
        char a[16] = "?";
        if (ip) ip_s(ip, a, sizeof(a));
        ESP_LOGW(TAG, "block.txt refused to %s (not the router, or not the gateway's MAC)", a);
        send_body(sock, "404 Not Found", "text/plain", "not found\n", 10);
        return true;
    }
    char *buf = heap_caps_malloc(TEXT_MAX, MALLOC_CAP_SPIRAM);
    if (!buf) { send_body(sock, "503 Service Unavailable", "text/plain", "", 0); return true; }
    size_t n = blocklist_text(buf, TEXT_MAX);
    if (n == (size_t)-1) {
        // Never a cut list: the router keeps what it has when the fetch fails.
        send_body(sock, "500 Internal Server Error", "text/plain", "", 0);
    } else {
        send_body(sock, "200 OK", "text/plain; charset=us-ascii", buf, n);
        blocklist_note_fetch(true);
    }
    free(buf);
    return true;
}

// ── Admin routes ──────────────────────────────────────────────────────────────

static const char *header_end(const char *req) { return strstr(req, "\r\n\r\n"); }

static long content_length(const char *req, const char *hend)
{
    for (const char *p = strchr(req, '\n'); p && p < hend; p = strchr(p, '\n')) {
        p++;
        if (p >= hend) break;
        if (strncasecmp(p, "Content-Length:", 15)) continue;
        p += 15;
        while (*p == ' ' || *p == '\t') p++;
        if (*p < '0' || *p > '9') return -1;
        long v = 0;
        for (; *p >= '0' && *p <= '9'; p++) { v = v * 10 + (*p - '0'); if (v > BODY_MAX) return BODY_MAX + 1; }
        return v;
    }
    return -1;
}

// The body into a PSRAM buffer (NUL-terminated). NULL and *err on failure.
static char *read_body(int sock, const char *req, int req_len, const char **status, const char **err)
{
    const char *hend = header_end(req);
    if (!hend) { *status = "431 Request Header Fields Too Large"; *err = "headers too large"; return NULL; }
    long cl = content_length(req, hend);
    if (cl < 0)        { *status = "411 Length Required"; *err = "Content-Length required"; return NULL; }
    if (cl > BODY_MAX) { *status = "413 Payload Too Large"; *err = "body too large"; return NULL; }
    char *b = heap_caps_malloc((size_t)cl + 1, MALLOC_CAP_SPIRAM);
    if (!b) { *status = "503 Service Unavailable"; *err = "out of memory"; return NULL; }
    size_t start = (size_t)(hend + 4 - req);
    size_t have = (req_len > 0 && (size_t)req_len > start) ? (size_t)req_len - start : 0;
    if (have > (size_t)cl) have = (size_t)cl;
    memcpy(b, req + start, have);
    while (have < (size_t)cl) {                     // recv timeout set by admin_panel.c
        int n = recv(sock, b + have, (size_t)cl - have, 0);
        if (n <= 0) { free(b); *status = "408 Request Timeout"; *err = "body incomplete"; return NULL; }
        have += (size_t)n;
    }
    b[have] = '\0';
    return b;
}

typedef struct { char *b; size_t n, cap; bool full; } jb_t;

static void jb_fmt(jb_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_fmt(jb_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(j->b + j->n, j->cap - j->n, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= j->cap - j->n) { j->full = true; j->b[j->n] = '\0'; return; }
    j->n += (size_t)w;
}

static void send_list(int sock)
{
    char *buf = heap_caps_malloc(LIST_JSON, MALLOC_CAP_SPIRAM);
    block_entry_t *e = heap_caps_malloc(BLOCK_MAX * sizeof(*e), MALLOC_CAP_SPIRAM);
    if (!buf || !e) { free(buf); free(e); send_err(sock, "503 Service Unavailable", "out of memory"); return; }
    int n = blocklist_get(e, BLOCK_MAX);
    jb_t j = { .b = buf, .n = 0, .cap = LIST_JSON, .full = false };
    jb_fmt(&j, "{\"entries\":[");
    for (int i = 0; i < n; i++) {
        char a[16], note[2 * BLOCK_NOTE_MAX + 8];
        ip_s(e[i].ip, a, sizeof(a));
        json_esc(e[i].note, BLOCK_NOTE_MAX, note, sizeof(note));
        jb_fmt(&j, "%s{\"ip\":\"%s\",\"kind\":\"%s\",\"note\":\"%s\",\"ts\":%lu}", i ? "," : "", a,
               blocklist_kind_key(e[i].kind), note, (unsigned long)e[i].ts);
    }
    jb_fmt(&j, "],\"max\":%d,\"count\":%d,\"never\":[", BLOCK_MAX, n);
    uint32_t nip[48];
    const char *why[48];
    int nn = blocklist_never_list(nip, why, 48);
    for (int i = 0; i < nn; i++) {
        char a[16];
        ip_s(nip[i], a, sizeof(a));
        jb_fmt(&j, "%s{\"ip\":\"%s\",\"why\":\"%s\"}", i ? "," : "", a, why[i]);     // why: our own fixed text
    }
    uint32_t served, last, refused;
    blocklist_fetch_stats(&served, &last, &refused);
    jb_fmt(&j, "],\"router\":{\"fetches\":%lu,\"last_fetch\":%lu,\"refused\":%lu}}",
           (unsigned long)served, (unsigned long)last, (unsigned long)refused);
    free(e);
    if (j.full) send_err(sock, "500 Internal Server Error", "response too large");
    else send_body(sock, "200 OK", "application/json", buf, j.n);
    free(buf);
}

static void post(int sock, const char *req, int req_len, bool remove)
{
    const char *status = NULL, *err = NULL;
    char *body = read_body(sock, req, req_len, &status, &err);
    if (!body) { send_err(sock, status, err); return; }
    cJSON *o = cJSON_Parse(body);
    free(body);
    if (!o || !cJSON_IsObject(o)) { cJSON_Delete(o); send_err(sock, "400 Bad Request", "body must be a JSON object"); return; }
    const cJSON *ip_j = cJSON_GetObjectItemCaseSensitive(o, "ip");
    const cJSON *kind_j = cJSON_GetObjectItemCaseSensitive(o, "kind");
    const cJSON *note_j = cJSON_GetObjectItemCaseSensitive(o, "note");
    uint32_t ip = 0;
    block_kind_t kind;
    if (!cJSON_IsString(ip_j) || !parse_ipv4(ip_j->valuestring, &ip)) {
        cJSON_Delete(o); send_err(sock, "400 Bad Request", "ip must be a dotted quad"); return;
    }
    if (!cJSON_IsString(kind_j) || !blocklist_kind_parse(kind_j->valuestring, &kind)) {
        cJSON_Delete(o); send_err(sock, "400 Bad Request", "kind must be \"dst\" or \"src\""); return;
    }
    if (note_j && !cJSON_IsNull(note_j) && !cJSON_IsString(note_j)) {
        cJSON_Delete(o); send_err(sock, "400 Bad Request", "note must be a string"); return;
    }
    char note[BLOCK_NOTE_MAX + 1] = "";
    if (cJSON_IsString(note_j)) {
        if (strlen(note_j->valuestring) >= BLOCK_NOTE_MAX) {
            cJSON_Delete(o); send_err(sock, "400 Bad Request", "note: at most 40 printable ASCII characters"); return;
        }
        strlcpy(note, note_j->valuestring, sizeof(note));
    }
    cJSON_Delete(o);

    if (remove) {
        block_result_t r = blocklist_remove(ip, kind);
        if (r == BLOCK_NOT_FOUND) { send_err(sock, "404 Not Found", "not on the block list"); return; }
        if (r != BLOCK_OK) { send_err(sock, "507 Insufficient Storage", "not saved (NVS)"); return; }
        send_list(sock);
        return;
    }
    char why[96] = "";
    block_result_t r = blocklist_add(ip, kind, note, why, sizeof(why));
    switch (r) {
    case BLOCK_OK:
    case BLOCK_UPDATED: send_list(sock); break;
    case BLOCK_NEVER:
    case BLOCK_FULL:    send_err(sock, "409 Conflict", why); break;
    case BLOCK_BAD:     send_err(sock, "400 Bad Request", why); break;
    default:            send_err(sock, "507 Insufficient Storage", why[0] ? why : "not saved (NVS)"); break;
    }
}

bool api_block_handle(int sock, const char *req, int req_len)
{
    bool get = !strncmp(req, "GET ", 4), pst = !strncmp(req, "POST ", 5);
    if (!get && !pst) return false;
    const char *t = req + (get ? 4 : 5), *e = t;
    while (*e && *e != ' ' && *e != '?' && *e != '\r' && *e != '\n') e++;
    size_t pl = (size_t)(e - t);
    bool list = pl == 10 && !strncmp(t, "/api/block", 10);
    bool rm = pl == 17 && !strncmp(t, "/api/block/remove", 17);
    if (!list && !rm) return false;
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (list && get)      send_list(sock);
    else if (list && pst) post(sock, req, req_len, false);
    else if (rm && pst)   post(sock, req, req_len, true);
    else                  send_err(sock, "405 Method Not Allowed", "use POST");
    return true;
}
