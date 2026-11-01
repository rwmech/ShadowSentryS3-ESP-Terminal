// Per-device log route on the admin port. See api_devlog.h.

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

#define SEND_TIMEOUT_S      10      // a client that stops reading can't hold the admin task
#define DEVLOG_DAYS_DEF     2
#define DEVLOG_DAYS_MAX     7
#define DEVLOG_LIMIT_DEF    300
#define DEVLOG_LIMIT_MAX    1000
#define DEVLOG_TIME_MS      3000    // the scan's time box
#define DEVLOG_CHUNK        8192    // read chunk, and the longest line kept
#define DEVLOG_QUERY_MAX    160
#define DAY_NAME_LEN        16      // "YYYY-MM-DD.jsonl"

// Where a matching line is: file (index into the day list), offset, length
// without the newline.
typedef struct {
    uint32_t off;
    uint16_t len;
    uint8_t  file;
    uint8_t  pad;
} loc_t;
_Static_assert(DEVLOG_CHUNK <= UINT16_MAX, "a line's length must fit loc_t.len");
_Static_assert(DEVLOG_DAYS_MAX <= UINT8_MAX, "a file index must fit loc_t.file");

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

typedef struct {
    char    *buf;               // DEVLOG_CHUNK
    loc_t   *ring;              // the newest cap matches of the file being scanned
    size_t   cap, pushed;
    char     nip[32], nmac[32];
    size_t   lip, lmac;
    int64_t  deadline;
    bool     timed_out;
    unsigned long long_skipped;
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

static void ring_push(scan_t *s, uint8_t file, uint32_t off, size_t len)
{
    if (!s->cap) { s->pushed++; return; }
    loc_t *l = &s->ring[s->pushed % s->cap];
    l->off = off;
    l->len = (uint16_t)len;
    l->file = file;
    l->pad = 0;
    s->pushed++;
}

// One file, start to its size now (the writer may append meanwhile). A line
// longer than the chunk is skipped whole; a last line with no newline (being
// written) is left out.
static void scan_file(scan_t *s, const char *path, uint8_t file)
{
    FILE *f = fopen(path, "rb");
    if (!f) return;
    struct stat sb;
    if (fstat(fileno(f), &sb) != 0 || sb.st_size <= 0) { fclose(f); return; }
    uint32_t size = (uint32_t)sb.st_size, base = 0;
    size_t have = 0;
    bool skipping = false;
    while (base + have < size) {
        if (esp_timer_get_time() > s->deadline) { s->timed_out = true; break; }
        size_t want = DEVLOG_CHUNK - have;
        uint32_t left = size - (uint32_t)(base + have);
        if (want > left) want = left;
        size_t got = fread(s->buf + have, 1, want, f);
        if (got == 0) break;
        have += got;
        size_t start = 0;
        char *nl;
        while ((nl = memchr(s->buf + start, '\n', have - start)) != NULL) {
            size_t end = (size_t)(nl - s->buf), n = end - start;
            if (!skipping) {
                if (n && s->buf[start + n - 1] == '\r') n--;
                if (n && line_matches(s, s->buf + start, n)) ring_push(s, file, base + (uint32_t)start, n);
            }
            skipping = false;
            start = end + 1;
        }
        if (start == 0 && have == DEVLOG_CHUNK) {       // no newline in a full chunk
            if (!skipping) s->long_skipped++;
            skipping = true;
            start = have;
        }
        memmove(s->buf, s->buf + start, have - start);
        base += (uint32_t)start;
        have -= start;
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
    int days  = num_param(q, qn, "days", DEVLOG_DAYS_DEF, DEVLOG_DAYS_MAX, &bad);
    int limit = num_param(q, qn, "limit", DEVLOG_LIMIT_DEF, DEVLOG_LIMIT_MAX, &bad);
    if (bad) { send_error(sock, "400 Bad Request", "days and limit must be numbers"); return true; }

    sd_status_t st;
    sd_log_status(&st);
    if (!st.mounted) { send_error(sock, "503 Service Unavailable", "no microSD card"); return true; }

    s.buf  = heap_caps_malloc(DEVLOG_CHUNK, MALLOC_CAP_SPIRAM);
    s.ring = heap_caps_malloc(sizeof(loc_t) * (size_t)limit, MALLOC_CAP_SPIRAM);
    loc_t *out = heap_caps_malloc(sizeof(loc_t) * (size_t)limit, MALLOC_CAP_SPIRAM);
    if (!s.buf || !s.ring || !out) {
        free(s.buf); free(s.ring); free(out);
        send_error(sock, "503 Service Unavailable", "out of memory");
        return true;
    }

    char names[DEVLOG_DAYS_MAX][DAY_NAME_LEN + 1];
    int nf = list_days(names, days);
    int64_t t0 = esp_timer_get_time();
    s.deadline = t0 + DEVLOG_TIME_MS * 1000LL;
    size_t outn = 0;
    int scanned = 0;
    bool truncated = false;
    char path[48];

    // Newest file first; each file keeps its newest matches, up to what the
    // limit has left, and adds them newest first.
    for (int fi = 0; fi < nf; fi++) {
        if (outn == (size_t)limit) { truncated = true; break; }   // older files may hold more
        s.cap = (size_t)limit - outn;
        s.pushed = 0;
        snprintf(path, sizeof(path), SD_LOG_DIR "/%s", names[fi]);
        scan_file(&s, path, (uint8_t)fi);
        scanned++;
        size_t kept = s.pushed < s.cap ? s.pushed : s.cap;
        for (size_t k = 0; k < kept; k++) out[outn++] = s.ring[(s.pushed - 1 - k) % s.cap];
        if (s.pushed > s.cap) truncated = true;
        if (s.timed_out) { truncated = true; break; }
        if (s.pushed > s.cap) break;
    }

    char meta[200];
    int ml = snprintf(meta, sizeof(meta),
        "{\"kind\":\"meta\",\"matched\":%u,\"files\":%d,\"days\":%d,\"limit\":%d,"
        "\"truncated\":%s,\"timed_out\":%s,\"long_skipped\":%lu}\n",
        (unsigned)outn, scanned, days, limit, truncated ? "true" : "false",
        s.timed_out ? "true" : "false", s.long_skipped);
    if (ml <= 0 || ml >= (int)sizeof(meta)) ml = 0;
    size_t total = (size_t)ml;
    for (size_t i = 0; i < outn; i++) total += out[i].len + 1u;

    // Send what the scan found. A line that reads short is padded with spaces,
    // so Content-Length holds; the page skips a line it can't parse.
    if (send_head(sock, "200 OK", "application/x-ndjson; charset=utf-8", total) &&
        send_all(sock, meta, (size_t)ml)) {
        FILE *f = NULL;
        int open_fi = -1;
        for (size_t i = 0; i < outn; i++) {
            const loc_t *l = &out[i];
            if (l->file != open_fi) {
                if (f) fclose(f);
                snprintf(path, sizeof(path), SD_LOG_DIR "/%s", names[l->file]);
                f = fopen(path, "rb");
                open_fi = l->file;
            }
            size_t got = 0;
            if (f && fseek(f, (long)l->off, SEEK_SET) == 0) got = fread(s.buf, 1, l->len, f);
            if (got < l->len) memset(s.buf + got, ' ', l->len - got);
            s.buf[l->len] = '\n';
            if (!send_all(sock, s.buf, (size_t)l->len + 1)) break;
        }
        if (f) fclose(f);
    }
    ESP_LOGI(TAG, "Device log: %u lines from %d of %d files in %lld ms%s",
             (unsigned)outn, scanned, nf, (long long)((esp_timer_get_time() - t0) / 1000),
             s.timed_out ? " (time box)" : "");
    free(s.buf);
    free(s.ring);
    free(out);
    return true;
}
