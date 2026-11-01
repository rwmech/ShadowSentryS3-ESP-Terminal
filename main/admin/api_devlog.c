// Per-device log route on the admin port. See api_devlog.h.

#include "api_devlog.h"
#include "json_esc.h"
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

#define SEND_TIMEOUT_S      10      // a client that stops reading can't hold the admin task
#define DEVLOG_DAYS_DEF     2
#define DEVLOG_DAYS_MAX     7
#define DEVLOG_LIMIT_DEF    300
#define DEVLOG_LIMIT_MAX    1000
#define DEVLOG_TIME_MS      3000    // the scan's time box
#define DEVLOG_CHUNK        16384   // read piece, and the longest line kept
#define DEVLOG_ARENA        (256 * 1024)    // the matching lines, sent as they are
#define DEVLOG_ARENA_MIN    (32 * 1024)     // if PSRAM is short
#define DEVLOG_QUERY_MAX    160
#define DAY_NAME_LEN        16      // "YYYY-MM-DD.jsonl"

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
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
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

// The newest max dated log files, newest first (ISO dates sort as strings).
static int list_days(char names[][DAY_NAME_LEN + 1], int max)
{
    DIR *d = opendir(SD_LOG_DIR);
    if (!d) return 0;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!dated_name(de->d_name)) continue;
        int pos = n;
        while (pos > 0 && strcmp(de->d_name, names[pos - 1]) > 0) pos--;
        if (pos >= max) continue;
        int last = n < max ? n : max - 1;
        for (int k = last; k > pos; k--) memcpy(names[k], names[k - 1], DAY_NAME_LEN + 1);
        memcpy(names[pos], de->d_name, DAY_NAME_LEN + 1);
        if (n < max) n++;
    }
    closedir(d);
    return n;
}

// ── Scan ──────────────────────────────────────────────────────────────────────
//
// Each file is read backwards from its end in DEVLOG_CHUNK pieces, so the
// newest lines come first and the time box cuts off the oldest, not the
// newest. The part of a line that runs into the piece before it (its start)
// is kept at the top of the buffer and joined to the next piece read.

typedef struct {
    char    *buf;               // DEVLOG_CHUNK, the read buffer
    char    *arena;             // the matching lines, newline-terminated, newest first
    size_t   arena_cap, arena_used;
    int      limit, matched;
    char     nip[32], nmac[32];
    size_t   lip, lmac;
    int64_t  deadline;
    bool     timed_out, full;   // full: the limit or the arena stopped the scan
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

// One complete line (no newline). Copied into the arena when it matches.
static void take_line(scan_t *s, const char *p, size_t n)
{
    if (n && p[n - 1] == '\r') n--;
    if (!n || !line_matches(s, p, n)) return;
    if (s->arena_used + n + 1 > s->arena_cap) { s->full = true; return; }
    memcpy(s->arena + s->arena_used, p, n);
    utf8_sanitize(s->arena + s->arena_used, n);     // lines written before json_esc() may hold raw bytes
    s->arena[s->arena_used + n] = '\n';
    s->arena_used += n + 1;
    if (++s->matched >= s->limit) s->full = true;     // stop here: older lines may match too
}

// One file, from its size now (the writer may append meanwhile) back to its
// start. The bytes after its last newline (a line being written) are left
// out; a line longer than the buffer is skipped whole and counted.
static void scan_file(scan_t *s, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return;
    struct stat sb;
    if (fstat(fileno(f), &sb) != 0 || sb.st_size <= 0) { fclose(f); return; }
    char *b = s->buf;
    const size_t cap = DEVLOG_CHUNK;
    uint32_t pos = (uint32_t)sb.st_size;    // file offset of the next byte below what we hold
    size_t frag = 0;                        // the pending line's start-side part, at b[cap - frag .. cap)
    bool have_end = false;                  // the pending line ends in a newline (complete)
    bool skipping = false;                  // inside a line too long to keep
    while (!s->full) {
        if (esp_timer_get_time() > s->deadline) { s->timed_out = true; break; }
        if (frag == cap) {                  // a whole buffer and no newline: too long
            if (!skipping) s->long_skipped++;
            skipping = true;
            frag = 0;
        }
        if (pos == 0) {                     // the file's first line
            if (have_end && !skipping) take_line(s, b + cap - frag, frag);
            break;
        }
        size_t want = cap - frag;
        if (want > pos) want = pos;
        size_t s0 = cap - frag - want;      // the new piece goes just below the fragment
        if (fseek(f, (long)(pos - want), SEEK_SET) != 0) break;
        if (fread(b + s0, 1, want, f) != want) break;
        pos -= (uint32_t)want;
        s->scanned += want;
        // Newlines in the new piece, highest first; the fragment holds none.
        size_t stop = cap;                  // end (exclusive) of the pending line
        for (size_t j = s0 + want; j-- > s0; ) {
            if (b[j] != '\n') continue;
            if (have_end && !skipping) take_line(s, b + j + 1, stop - (j + 1));
            if (s->full) break;
            have_end = true;
            skipping = false;
            stop = j;
        }
        // What is left below the lowest newline is the start-side part of a
        // line that began further back: keep it at the top of the buffer.
        frag = stop - s0;
        memmove(b + cap - frag, b + s0, frag);
    }
    fclose(f);
}

// ── Route ─────────────────────────────────────────────────────────────────────

bool api_devlog_handle(int sock, const char *req, int req_len)
{
    static const char pfx[] = "GET /api/logs/device";
    if (req_len < (int)sizeof(pfx) || strncmp(req, pfx, sizeof(pfx) - 1) != 0) return false;
    const char *p = req + sizeof(pfx) - 1;
    if (*p != ' ' && *p != '?') return false;   // some other path

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // The query: between '?' and the space before the HTTP version.
    const char *q = "";
    size_t qn = 0;
    if (*p == '?') {
        q = p + 1;
        const char *stop = req + req_len;
        while (q + qn < stop && q[qn] != ' ' && q[qn] != '\r' && q[qn] != '\n') qn++;
        if (qn > DEVLOG_QUERY_MAX) { send_error(sock, "400 Bad Request", "query too long"); return true; }
    }

    scan_t s;
    memset(&s, 0, sizeof(s));
    char v[24], mac[18], ip[16];
    bool bad = false;
    if (qparam(q, qn, "mac", v, sizeof(v))) {
        if (!valid_mac(v, mac)) { send_error(sock, "400 Bad Request", "mac must be aa:bb:cc:dd:ee:ff"); return true; }
        s.lmac = (size_t)snprintf(s.nmac, sizeof(s.nmac), "\"mac\":\"%s\"", mac);
    }
    if (qparam(q, qn, "ip", v, sizeof(v))) {
        if (!valid_ip(v, ip)) { send_error(sock, "400 Bad Request", "ip must be a dotted IPv4 address"); return true; }
        s.lip = (size_t)snprintf(s.nip, sizeof(s.nip), "\"ip\":\"%s\"", ip);
    }
    if (!s.lmac && !s.lip) { send_error(sock, "400 Bad Request", "give a mac, an ip or both"); return true; }
    int days = num_param(q, qn, "days", DEVLOG_DAYS_DEF, DEVLOG_DAYS_MAX, &bad);
    s.limit  = num_param(q, qn, "limit", DEVLOG_LIMIT_DEF, DEVLOG_LIMIT_MAX, &bad);
    if (bad) { send_error(sock, "400 Bad Request", "days and limit must be numbers"); return true; }

    sd_status_t st;
    sd_log_status(&st);
    if (!st.mounted) { send_error(sock, "503 Service Unavailable", "no microSD card"); return true; }

    s.buf = heap_caps_malloc(DEVLOG_CHUNK, MALLOC_CAP_SPIRAM);
    s.arena_cap = DEVLOG_ARENA;
    s.arena = heap_caps_malloc(s.arena_cap, MALLOC_CAP_SPIRAM);
    if (!s.arena) { s.arena_cap = DEVLOG_ARENA_MIN; s.arena = heap_caps_malloc(s.arena_cap, MALLOC_CAP_SPIRAM); }
    if (!s.buf || !s.arena) {
        free(s.buf); free(s.arena);
        send_error(sock, "503 Service Unavailable", "out of memory");
        return true;
    }

    char names[DEVLOG_DAYS_MAX][DAY_NAME_LEN + 1];
    int nf = list_days(names, days);
    int64_t t0 = esp_timer_get_time();
    s.deadline = t0 + DEVLOG_TIME_MS * 1000LL;
    int scanned_files = 0;
    char path[48];
    for (int fi = 0; fi < nf && !s.full && !s.timed_out; fi++) {
        snprintf(path, sizeof(path), SD_LOG_DIR "/%s", names[fi]);
        scan_file(&s, path);
        scanned_files++;
    }
    bool truncated = s.full || s.timed_out;

    char meta[256];
    int ml = snprintf(meta, sizeof(meta),
        "{\"kind\":\"meta\",\"matched\":%d,\"files\":%d,\"days\":%d,\"limit\":%d,"
        "\"truncated\":%s,\"timed_out\":%s,\"scanned_bytes\":%llu,\"ms\":%lld,\"long_skipped\":%lu}\n",
        s.matched, scanned_files, days, s.limit, truncated ? "true" : "false",
        s.timed_out ? "true" : "false", (unsigned long long)s.scanned,
        (long long)((esp_timer_get_time() - t0) / 1000), s.long_skipped);
    if (ml <= 0 || ml >= (int)sizeof(meta)) ml = 0;
    if (send_head(sock, "200 OK", "application/x-ndjson; charset=utf-8", (size_t)ml + s.arena_used) &&
        send_all(sock, meta, (size_t)ml))
        send_all(sock, s.arena, s.arena_used);
    ESP_LOGI(TAG, "Device log: %d lines from %d of %d files, %llu B read in %lld ms%s",
             s.matched, scanned_files, nf, (unsigned long long)s.scanned,
             (long long)((esp_timer_get_time() - t0) / 1000), s.timed_out ? " (time box)" : "");
    free(s.buf);
    free(s.arena);
    return true;
}
