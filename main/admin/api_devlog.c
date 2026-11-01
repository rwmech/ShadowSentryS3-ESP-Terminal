// Per-device log routes on the admin port. See api_devlog.h.

#include "api_devlog.h"
#include "sd_log.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "DEVLOG";

// The device page (main/device.html, embedded as text: NUL-terminated).
extern const uint8_t device_html_start[] asm("_binary_device_html_start");
extern const uint8_t device_html_end[]   asm("_binary_device_html_end");

#define SEND_TIMEOUT_S      10      // a client that stops reading can't hold the admin task
#define DEVLOG_LIMIT_DEF    200
#define DEVLOG_LIMIT_MAX    1000
#define DEVLOG_TIME_MS      3000    // the scan's time box, per request
#define DEVLOG_CHUNK        16384   // read piece, and the longest line kept
#define DEVLOG_ARENA        (256 * 1024)    // the matching lines, sent as they are
#define DEVLOG_ARENA_MIN    (32 * 1024)     // if PSRAM is short
#define DEVLOG_QUERY_MAX    200
#define DAY_NAME_LEN        16      // "YYYY-MM-DD.jsonl"
#define CURSOR_MAX          (DAY_NAME_LEN + 1 + 10)
_Static_assert(DEVLOG_CHUNK < DEVLOG_ARENA_MIN, "a kept line must always fit an empty arena");

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

static bool send_head(int sock, const char *status, const char *type, size_t len)
{
    char hdr[320];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Content-Security-Policy: frame-ancestors 'none'\r\n"
        "Connection: close\r\n\r\n",
        status, type, (unsigned)len);
    if (n <= 0 || n >= (int)sizeof(hdr)) return false;
    return send_all(sock, hdr, (size_t)n);
}

static void send_error(int sock, const char *status, const char *msg)
{
    char body[128];
    int n = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", msg);   // msg: our constants only
    if (n <= 0 || n >= (int)sizeof(body)) return;
    if (send_head(sock, status, "application/json", (size_t)n)) send_all(sock, body, (size_t)n);
}

// ── Query ─────────────────────────────────────────────────────────────────────

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// The value of key in the query string q (qn bytes), percent-decoded into out
// (cap bytes, NUL-terminated). False if absent, empty, malformed or too long.
static bool qparam(const char *q, size_t qn, const char *key, char *out, size_t cap)
{
    size_t kn = strlen(key);
    for (size_t i = 0; i < qn; ) {
        size_t j = i;
        while (j < qn && q[j] != '&') j++;
        if (j - i > kn && q[i + kn] == '=' && memcmp(q + i, key, kn) == 0) {
            size_t o = 0;
            for (size_t k = i + kn + 1; k < j; k++) {
                char c = q[k];
                if (c == '%') {
                    if (k + 2 >= j) return false;           // needs two hex digits
                    int h = hexval(q[k + 1]), l = hexval(q[k + 2]);
                    if (h < 0 || l < 0) return false;
                    c = (char)(h * 16 + l);
                    k += 2;
                }
                if (o + 1 >= cap) return false;
                out[o++] = c;
            }
            out[o] = '\0';
            return o > 0;
        }
        i = j + 1;
    }
    return false;
}

// "aa:bb:cc:dd:ee:ff" in any case, into lower case. Not all zero.
static bool valid_mac(const char *s, char out[18])
{
    if (strlen(s) != 17) return false;
    bool nonzero = false;
    for (int i = 0; i < 17; i++) {
        char c = s[i];
        if (i % 3 == 2) { if (c != ':') return false; out[i] = ':'; continue; }
        int v = hexval(c);
        if (v < 0) return false;
        if (v) nonzero = true;
        out[i] = "0123456789abcdef"[v];
    }
    out[17] = '\0';
    return nonzero;
}

// A dotted quad, each part 1 to 3 digits and at most 255, written back the
// way the log writes it (no leading zeros).
static bool valid_ip(const char *s, char out[16])
{
    unsigned part[4];
    const char *p = s;
    for (int i = 0; i < 4; i++) {
        int d = 0;
        unsigned v = 0;
        while (*p >= '0' && *p <= '9' && d < 3) { v = v * 10 + (unsigned)(*p - '0'); p++; d++; }
        if (!d || v > 255) return false;
        part[i] = v;
        if (i < 3) { if (*p != '.') return false; p++; }
    }
    if (*p) return false;
    snprintf(out, 16, "%u.%u.%u.%u", part[0], part[1], part[2], part[3]);
    return true;
}

// 1 to 4 digits; def when absent, clamped to 1..max.
static int num_param(const char *q, size_t qn, const char *key, int def, int max, bool *bad)
{
    char v[8];
    if (!qparam(q, qn, key, v, sizeof(v))) return def;
    int n = 0;
    size_t len = strlen(v);
    if (len > 4) { *bad = true; return def; }
    for (size_t i = 0; i < len; i++) {
        if (v[i] < '0' || v[i] > '9') { *bad = true; return def; }
        n = n * 10 + (v[i] - '0');
    }
    if (n < 1) return def;
    return n > max ? max : n;
}

// ── Day files ─────────────────────────────────────────────────────────────────

static bool dated_name(const char *n)
{
    if (strlen(n) != DAY_NAME_LEN) return false;
    for (int i = 0; i < 10; i++) {
        bool dash = (i == 4 || i == 7);
        if (dash ? n[i] != '-' : (n[i] < '0' || n[i] > '9')) return false;
    }
    return strcmp(n + 10, ".jsonl") == 0;
}

// The newest dated log file older than before (any, if before is NULL) into
// out. ISO dates sort as strings. False if there is none.
static bool older_day(const char *before, char out[DAY_NAME_LEN + 1])
{
    DIR *d = opendir(SD_LOG_DIR);
    if (!d) return false;
    bool found = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!dated_name(de->d_name)) continue;
        if (before && strcmp(de->d_name, before) >= 0) continue;
        if (found && strcmp(de->d_name, out) <= 0) continue;
        memcpy(out, de->d_name, DAY_NAME_LEN + 1);
        found = true;
    }
    closedir(d);
    return found;
}

static bool day_size(const char *name, uint32_t *size)
{
    char path[48];
    struct stat sb;
    snprintf(path, sizeof(path), SD_LOG_DIR "/%s", name);
    if (stat(path, &sb) != 0 || sb.st_size < 0 || (uint64_t)sb.st_size > UINT32_MAX) return false;
    *size = (uint32_t)sb.st_size;
    return true;
}

// "YYYY-MM-DD.jsonl:N": a day file in the log directory and an offset no
// larger than its size.
static bool parse_cursor(const char *c, char name[DAY_NAME_LEN + 1], uint32_t *off)
{
    if (strlen(c) < DAY_NAME_LEN + 2 || strlen(c) > CURSOR_MAX || c[DAY_NAME_LEN] != ':') return false;
    memcpy(name, c, DAY_NAME_LEN);
    name[DAY_NAME_LEN] = '\0';
    if (!dated_name(name)) return false;
    uint64_t v = 0;
    for (const char *p = c + DAY_NAME_LEN + 1; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        v = v * 10 + (uint64_t)(*p - '0');
        if (v > UINT32_MAX) return false;
    }
    uint32_t size;
    if (!day_size(name, &size) || v > size) return false;
    *off = (uint32_t)v;
    return true;
}

// ── Scan ──────────────────────────────────────────────────────────────────────
//
// Each file is read backwards from the cursor (or its end) in DEVLOG_CHUNK
// pieces, so the newest lines come first. The part of a line that runs into
// the piece before it (its start) is kept at the top of the buffer and joined
// to the next piece read. s->res tracks the resume point: every line at or
// after it has been handled, and the byte before it is a newline (or it is
// the cursor the scan started from).

typedef struct {
    char    *buf;               // DEVLOG_CHUNK, the read buffer
    char    *arena;             // the matching lines, newline-terminated, newest first
    size_t   arena_cap, arena_used;
    int      limit, matched;
    char     nip[32], nmac[32];
    size_t   lip, lmac;
    int64_t  deadline;
    bool     timed_out, full;   // full: the limit or the arena stopped the scan
    uint32_t res;               // resume offset in the file being scanned
    unsigned long long_skipped;
    uint64_t scanned;
} scan_t;

static bool has(const char *p, size_t n, const char *needle, size_t m)
{
    if (!m || m > n) return false;
    const char *end = p + n - m;
    for (const char *c = p; c <= end; c++) {
        c = memchr(c, needle[0], (size_t)(end - c) + 1);
        if (!c) return false;
        if (memcmp(c, needle, m) == 0) return true;
    }
    return false;
}

// A key with its quotes cannot occur inside a JSON string value (the log
// escapes '"'), so this only matches the line's own "ip" or "mac".
static bool line_matches(const scan_t *s, const char *p, size_t n)
{
    return (s->lip && has(p, n, s->nip, s->lip)) || (s->lmac && has(p, n, s->nmac, s->lmac));
}

// One complete line (no newline): copied into the arena when it matches.
// False only when it matched and did not fit (s->full, not handled).
static bool take_line(scan_t *s, const char *p, size_t n)
{
    if (n && p[n - 1] == '\r') n--;
    if (!n || !line_matches(s, p, n)) return true;
    if (s->arena_used + n + 1 > s->arena_cap) { s->full = true; return false; }
    memcpy(s->arena + s->arena_used, p, n);
    s->arena[s->arena_used + n] = '\n';
    s->arena_used += n + 1;
    if (++s->matched >= s->limit) s->full = true;     // stop here: older lines may match too
    return true;
}

// One file, from start back toward offset 0. Bytes after the last newline
// below start (a line being written) are left out; a line longer than the
// buffer is skipped whole and counted. True when the file was read back to
// its start; otherwise s->res is where to resume.
static bool scan_file(scan_t *s, const char *name, uint32_t start)
{
    char path[48];
    snprintf(path, sizeof(path), SD_LOG_DIR "/%s", name);
    s->res = start;
    FILE *f = fopen(path, "rb");
    if (!f) return true;                    // gone (deleted meanwhile): go on to the next
    char *b = s->buf;
    const size_t cap = DEVLOG_CHUNK;
    uint32_t pos = start;                   // file offset of the next byte below what we hold
    size_t frag = 0;                        // the pending line's start-side part, at b[cap - frag .. cap)
    bool have_end = false;                  // the pending line ends in a newline (complete)
    bool skipping = false;                  // inside a line too long to keep
    bool done = false;
    while (!s->full) {
        // The time box, once the resume point has moved, so every request
        // gets at least one line further back.
        if (s->res != start && esp_timer_get_time() > s->deadline) { s->timed_out = true; break; }
        if (frag == cap) {                  // a whole buffer and no newline: too long
            if (!skipping) s->long_skipped++;
            skipping = true;
            frag = 0;
        }
        if (pos == 0) {                     // the file's first line
            if (have_end && !skipping && !take_line(s, b + cap - frag, frag)) break;
            done = true;
            break;
        }
        size_t want = cap - frag;
        if (want > pos) want = pos;
        size_t s0 = cap - frag - want;      // the new piece goes just below the fragment
        if (fseek(f, (long)(pos - want), SEEK_SET) != 0 || fread(b + s0, 1, want, f) != want) {
            ESP_LOGW(TAG, "read failed in %s at %lu", name, (unsigned long)(pos - want));
            done = true;                    // don't resume into a bad spot for ever
            break;
        }
        pos -= (uint32_t)want;
        s->scanned += want;
        // Newlines in the new piece, highest first; the fragment holds none.
        size_t stop = cap;                  // end (exclusive) of the pending line
        for (size_t j = s0 + want; j-- > s0; ) {
            if (b[j] != '\n') continue;
            if (have_end && !skipping && !take_line(s, b + j + 1, stop - (j + 1))) break;
            have_end = true;
            skipping = false;
            stop = j;
            s->res = pos + (uint32_t)(j - s0) + 1;
            if (s->full) break;
        }
        // What is left below the lowest newline is the start-side part of a
        // line that began further back: keep it at the top of the buffer.
        frag = stop - s0;
        memmove(b + cap - frag, b + s0, frag);
    }
    fclose(f);
    return done;
}

// ── Routes ────────────────────────────────────────────────────────────────────

static void serve_device_page(int sock)
{
    size_t n = (size_t)(device_html_end - device_html_start);
    if (n && device_html_start[n - 1] == '\0') n--;          // EMBED_TXTFILES adds a NUL
    if (send_head(sock, "200 OK", "text/html; charset=utf-8", n)) send_all(sock, device_html_start, n);
}

static void serve_device_log(int sock, const char *q, size_t qn)
{
    scan_t s;
    memset(&s, 0, sizeof(s));
    char v[CURSOR_MAX + 8], mac[18], ip[16];
    bool bad = false;
    if (qparam(q, qn, "mac", v, sizeof(v))) {
        if (!valid_mac(v, mac)) { send_error(sock, "400 Bad Request", "mac must be aa:bb:cc:dd:ee:ff"); return; }
        s.lmac = (size_t)snprintf(s.nmac, sizeof(s.nmac), "\"mac\":\"%s\"", mac);
    }
    if (qparam(q, qn, "ip", v, sizeof(v))) {
        if (!valid_ip(v, ip)) { send_error(sock, "400 Bad Request", "ip must be a dotted IPv4 address"); return; }
        s.lip = (size_t)snprintf(s.nip, sizeof(s.nip), "\"ip\":\"%s\"", ip);
    }
    if (!s.lmac && !s.lip) { send_error(sock, "400 Bad Request", "give a mac, an ip or both"); return; }
    s.limit = num_param(q, qn, "limit", DEVLOG_LIMIT_DEF, DEVLOG_LIMIT_MAX, &bad);
    if (bad) { send_error(sock, "400 Bad Request", "limit must be a number"); return; }

    sd_status_t st;
    sd_log_status(&st);
    if (!st.mounted) { send_error(sock, "503 Service Unavailable", "no microSD card"); return; }

    // Where to start: the cursor, or the end of the newest day file.
    char cur[DAY_NAME_LEN + 1];
    uint32_t off = 0;
    bool any = true;
    if (qparam(q, qn, "cursor", v, sizeof(v))) {
        if (!parse_cursor(v, cur, &off)) {
            send_error(sock, "400 Bad Request", "cursor must be YYYY-MM-DD.jsonl:offset within that file");
            return;
        }
    } else if (!older_day(NULL, cur) || !day_size(cur, &off)) {
        any = false;                        // no day files: an empty answer
    }

    s.buf = heap_caps_malloc(DEVLOG_CHUNK, MALLOC_CAP_SPIRAM);
    s.arena_cap = DEVLOG_ARENA;
    s.arena = heap_caps_malloc(s.arena_cap, MALLOC_CAP_SPIRAM);
    if (!s.arena) { s.arena_cap = DEVLOG_ARENA_MIN; s.arena = heap_caps_malloc(s.arena_cap, MALLOC_CAP_SPIRAM); }
    if (!s.buf || !s.arena) {
        free(s.buf); free(s.arena);
        send_error(sock, "503 Service Unavailable", "out of memory");
        return;
    }

    int64_t t0 = esp_timer_get_time();
    s.deadline = t0 + DEVLOG_TIME_MS * 1000LL;
    int files = 0;
    char next[CURSOR_MAX + 1] = "";         // "" when the oldest file has been read to its start
    char first[DAY_NAME_LEN + 1] = "";
    while (any) {
        if (!first[0]) memcpy(first, cur, sizeof(first));
        bool done = scan_file(&s, cur, off);
        files++;
        if (!done) {
            snprintf(next, sizeof(next), "%s:%lu", cur, (unsigned long)s.res);
            break;
        }
        char older[DAY_NAME_LEN + 1];
        if (!older_day(cur, older) || !day_size(older, &off)) break;      // the oldest is done
        memcpy(cur, older, sizeof(cur));
        if (s.full || esp_timer_get_time() > s.deadline) {
            if (!s.full) s.timed_out = true;
            snprintf(next, sizeof(next), "%s:%lu", cur, (unsigned long)off);
            break;
        }
    }

    char meta[320];
    int ml = snprintf(meta, sizeof(meta),
        "{\"kind\":\"meta\",\"matched\":%d,\"files\":%d,\"from\":\"%s\",\"limit\":%d,"
        "\"cursor\":\"%s\",\"more\":%s,\"timed_out\":%s,\"scanned_bytes\":%llu,\"ms\":%lld,\"long_skipped\":%lu}\n",
        s.matched, files, first, s.limit, next, next[0] ? "true" : "false",
        s.timed_out ? "true" : "false", (unsigned long long)s.scanned,
        (long long)((esp_timer_get_time() - t0) / 1000), s.long_skipped);  // names validated above
    if (ml <= 0 || ml >= (int)sizeof(meta)) ml = 0;
    if (send_head(sock, "200 OK", "application/x-ndjson; charset=utf-8", (size_t)ml + s.arena_used) &&
        send_all(sock, meta, (size_t)ml))
        send_all(sock, s.arena, s.arena_used);
    ESP_LOGI(TAG, "Device log: %d lines from %d files, %llu B read in %lld ms%s",
             s.matched, files, (unsigned long long)s.scanned,
             (long long)((esp_timer_get_time() - t0) / 1000), s.timed_out ? " (time box)" : "");
    free(s.buf);
    free(s.arena);
}

// "GET <path>" followed by ' ' or '?': the query (qn bytes) in *q, "" if none.
// -1 if not this path, 0 if the query is too long, 1 if matched.
static int match_get(const char *req, int req_len, const char *path, const char **q, size_t *qn)
{
    size_t pl = strlen(path);
    if (req_len < 4 + (int)pl + 1 || strncmp(req, "GET ", 4) != 0 || strncmp(req + 4, path, pl) != 0) return -1;
    const char *p = req + 4 + pl;
    if (*p != ' ' && *p != '?') return -1;  // some other path
    *q = "";
    *qn = 0;
    if (*p == '?') {
        const char *stop = req + req_len, *s = p + 1;
        size_t n = 0;
        while (s + n < stop && s[n] != ' ' && s[n] != '\r' && s[n] != '\n') n++;
        if (n > DEVLOG_QUERY_MAX) return 0;
        *q = s;
        *qn = n;
    }
    return 1;
}

bool api_devlog_handle(int sock, const char *req, int req_len)
{
    const char *q;
    size_t qn;
    int m = match_get(req, req_len, "/api/logs/device", &q, &qn);
    int page = m < 0 ? match_get(req, req_len, "/device", &q, &qn) : -1;
    if (m < 0 && page < 0) return false;

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (page >= 0) { serve_device_page(sock); return true; }   // the page reads its own query
    if (m == 0) { send_error(sock, "400 Bad Request", "query too long"); return true; }
    serve_device_log(sock, q, qn);
    return true;
}
