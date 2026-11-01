#include "http_engine.h"
#include "http_trap.h"        // HTTP_BACKLOG, HTTP_RECV_TIMEOUT_S (upstream)
#include "trap_listen.h"
#include "log_store.h"
#include "telegram.h"
#include "sd_log.h"
#include "wifi_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char *TAG = "HTTPENG";

// ── Responses: upstream's, byte for byte (honeypot/http_trap.c, MIT, Rdx1S) ──

// Fake Hikvision NVR login page
static const char FAKE_LOGIN[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Server: App-webs/\r\n"
    "Connection: close\r\n\r\n"
    "<!DOCTYPE html><html><head><meta charset=UTF-8>"
    "<title>Network Camera</title>"
    "<style>"
    "body{background:#111;display:flex;align-items:center;justify-content:center;"
    "height:100vh;margin:0;font-family:Arial,sans-serif}"
    ".box{background:#1e1e1e;border:1px solid #333;padding:36px 40px;border-radius:6px;width:320px;text-align:center}"
    "h2{color:#d4a017;margin:0 0 6px;font-size:1.1rem;letter-spacing:2px}"
    "p{color:#666;font-size:.75rem;margin:0 0 24px}"
    "input{width:100%;padding:10px 12px;margin:6px 0;background:#2a2a2a;border:1px solid #444;"
    "color:#eee;border-radius:4px;box-sizing:border-box;font-size:.9rem}"
    "button{width:100%;padding:11px;background:#d4a017;border:none;color:#111;"
    "font-weight:700;cursor:pointer;border-radius:4px;margin-top:14px;font-size:.9rem}"
    "</style></head><body>"
    "<div class=box>"
    "<h2>&#127909; HIKVISION</h2>"
    "<p>Network Video Recorder</p>"
    "<form method=POST action=/doc/page/login.asp>"
    "<input type=text name=username placeholder=Username autocomplete=off>"
    "<input type=password name=password placeholder=Password>"
    "<button>Login</button>"
    "</form></div></body></html>";

static const char HTTP_REDIRECT[] =
    "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static const char HTTP_404[] =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

// ── Labels ────────────────────────────────────────────────────────────────────

typedef enum {
    CAT_NON_HTTP, CAT_OVERSIZE, CAT_TRAVERSAL, CAT_LOGIN_POST, CAT_DOTFILE,
    CAT_METHOD, CAT_SCANNER_UA, CAT_LIBRARY_UA, CAT_UNCLASSIFIED, CAT_COUNT
} cat_t;

static const struct { const char *key, *label; } CAT[CAT_COUNT] = {
    [CAT_NON_HTTP]     = { "non_http",     "non-HTTP payload" },
    [CAT_OVERSIZE]     = { "oversize",     "oversize request" },
    [CAT_TRAVERSAL]    = { "dotdot_path",  "path with .." },
    [CAT_LOGIN_POST]   = { "login_post",   "login POST" },
    [CAT_DOTFILE]      = { "dotfile_path", "dotfile path" },
    [CAT_METHOD]       = { "odd_method",   "unusual method" },
    [CAT_SCANNER_UA]   = { "scanner_ua",   "scanner UA" },
    [CAT_LIBRARY_UA]   = { "library_ua",   "HTTP library UA" },
    [CAT_UNCLASSIFIED] = { "unclassified", "unclassified" },
};

// Well-known scanner and HTTP client names, matched case-insensitively as
// substrings of the User-Agent.
static const char *const SCANNER_UA[] = {
    "nmap", "masscan", "zgrab", "nuclei", "nikto", "sqlmap", "gobuster",
    "wpscan", "censysinspect",
};
static const char *const LIBRARY_UA[] = {
    "curl/", "wget/", "python-requests", "python-urllib", "python-httpx",
    "aiohttp", "go-http-client", "libwww-perl", "okhttp", "java/",
    "apache-httpclient", "axios", "node-fetch", "powershell",
};

const char *http_engine_category_key(const char *payload)
{
    if (!payload) return NULL;
    for (int i = 0; i < CAT_COUNT; i++) {
        size_t n = strlen(CAT[i].label);
        if (strncmp(payload, CAT[i].label, n) == 0 && strncmp(payload + n, " on ", 4) == 0)
            return CAT[i].key;
    }
    return NULL;
}

// ── Connections (PSRAM) ───────────────────────────────────────────────────────

#define BUF_MAX   (HTTP_ENG_HEAD_MAX + HTTP_ENG_BODY_MAX)
#define DLINE_MAX 4096                    // the microSD "http" line

typedef struct {
    int      sock;                        // -1 = free
    uint16_t port;
    struct sockaddr_in addr;
    int64_t  t_open, t_last;              // ms
    size_t   len;                         // bytes in buf
    size_t   head_len;                    // 0 until the blank line; then the body offset
    size_t   body_need;
    bool     head_over;                   // no blank line within HTTP_ENG_HEAD_MAX
    char     buf[BUF_MAX + 1];
} conn_t;

// Per-request scratch, also PSRAM: keeps the internal stack small.
typedef struct {
    char method[17];
    char target[HTTP_ENG_URL_MAX + 1];    // request-target as sent (may be cut)
    char rline[HTTP_ENG_URL_MAX + 64];    // request line, printable
    char host[96];
    char ua[256];
    char path_dec[HTTP_ENG_URL_MAX + 1];  // path, percent-decoded, query dropped
    char user[32], pass[64];
    char body_txt[HTTP_ENG_LOG_BODY + 1]; // first body bytes, printable
    char dline[DLINE_MAX];
    size_t url_len;
    bool   long_line;
} req_t;

static conn_t  *C;                         // [HTTP_ENG_MAX_CONN]
static req_t   *R;
static uint32_t s_win_start, s_win_events, s_win_dropped, s_win_last_ip;
static uint32_t s_stack_low = UINT32_MAX;

static inline int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

// ── Parsing helpers (all bounded) ─────────────────────────────────────────────

// Upstream's url_decode and extract_field (http_trap.c), unchanged in behaviour.
static void url_decode(char *str)
{
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            char hex[3] = {src[1], src[2], 0};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static bool extract_field(const char *body, const char *field, char *out, size_t outlen)
{
    char key[64];
    snprintf(key, sizeof(key), "%s=", field);
    const char *p = strstr(body, key);
    if (!p) return false;
    p += strlen(key);
    size_t i = 0;
    while (*p && *p != '&' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    url_decode(out);
    return true;
}

// Copy n bytes as printable ASCII (others become '.'), NUL-terminated.
static void printable(const char *in, size_t n, char *out, size_t outlen)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < outlen; i++) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[o] = '\0';
}

static bool ci_contains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++)
        if (strncasecmp(hay, needle, n) == 0) return true;
    return false;
}

// Find "\r\n\r\n" in the first lim bytes; returns the offset after it, or 0.
static size_t find_blank(const char *b, size_t lim)
{
    for (size_t i = 3; i < lim; i++)
        if (b[i] == '\n' && b[i - 1] == '\r' && b[i - 2] == '\n' && b[i - 3] == '\r') return i + 1;
    return 0;
}

// "<METHOD> " with 1..16 upper-case letters, '-' or '_'.
static bool looks_like_http(const char *b, size_t n, bool complete)
{
    size_t i = 0;
    while (i < n && i < 16 && (isupper((unsigned char)b[i]) || b[i] == '-' || b[i] == '_')) i++;
    if (i < n) return i > 0 && b[i] == ' ';
    return !complete && i == n && i < 16;    // still arriving
}

// Header value by name, case-insensitive, within the NUL-terminated head.
static void header(const char *head, const char *name, char *out, size_t outlen)
{
    size_t nlen = strlen(name);
    out[0] = '\0';
    const char *p = strchr(head, '\n');          // skip the request line
    while (p) {
        p++;
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ' || *p == '\t') p++;
            size_t e = strcspn(p, "\r\n");
            printable(p, e, out, outlen);
            return;
        }
        p = strchr(p, '\n');
    }
}

static bool any_line_over(const char *head, size_t max)
{
    for (const char *p = head; *p; ) {
        size_t e = strcspn(p, "\n");
        if (e > max) return true;
        if (!p[e]) break;
        p += e + 1;
    }
    return false;
}

// Percent-decode the path part of target (query and fragment dropped).
static void decode_path(const char *target, char *out, size_t outlen)
{
    size_t e = strcspn(target, "?#");
    size_t o = 0;
    for (size_t i = 0; i < e && o + 1 < outlen; i++) {
        if (target[i] == '%' && i + 2 < e && isxdigit((unsigned char)target[i + 1]) &&
            isxdigit((unsigned char)target[i + 2])) {
            char hex[3] = { target[i + 1], target[i + 2], 0 };
            out[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            out[o++] = target[i];
        }
    }
    out[o] = '\0';
}

// Segment tests on the decoded path, '/' and '\' both separators.
static void path_shape(const char *p, bool *dotdot, bool *dotfile)
{
    *dotdot = *dotfile = false;
    while (*p) {
        while (*p == '/' || *p == '\\') p++;
        size_t n = strcspn(p, "/\\");
        if (n == 2 && p[0] == '.' && p[1] == '.') *dotdot = true;
        else if (n >= 2 && p[0] == '.') *dotfile = true;
        p += n;
    }
}

// JSON-escape into out at *o, bounded; stops cleanly when full.
static void jput(char *out, size_t *o, size_t cap, const char *s)
{
    for (; *s && *o + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { out[(*o)++] = '\\'; out[(*o)++] = (char)c; }
        else if (c < 0x20 || c >= 0x7f) *o += (size_t)snprintf(out + *o, cap - *o, "\\u%04x", c);
        else out[(*o)++] = (char)c;
    }
    out[*o] = '\0';
}

static void jraw(char *out, size_t *o, size_t cap, const char *s)
{
    size_t n = strlcpy(out + *o, s, cap - *o);
    *o += (n < cap - *o) ? n : cap - *o - 1;
}

// ── One request ───────────────────────────────────────────────────────────────

static void send_all(int sock, const char *p, size_t n)
{
    while (n) {
        int w = send(sock, p, n, 0);
        if (w <= 0) return;                     // SO_SNDTIMEO bounds this
        p += w;
        n -= (size_t)w;
    }
}

static void log_detail(const conn_t *c, cat_t cat, size_t body_len)
{
    req_t *r = R;
    char ip[16];
    inet_ntoa_r(c->addr.sin_addr, ip, sizeof(ip));
    size_t o = 0;
    char num[96];
    snprintf(num, sizeof(num), "{\"kind\":\"http\",\"ts\":%lu,\"ip\":\"%s\",\"port\":%u,\"category\":\"",
             (unsigned long)time(NULL), ip, (unsigned)c->port);
    jraw(r->dline, &o, DLINE_MAX, num);
    jraw(r->dline, &o, DLINE_MAX, CAT[cat].key);
    jraw(r->dline, &o, DLINE_MAX, "\",\"request\":\"");
    jput(r->dline, &o, DLINE_MAX, r->rline);
    jraw(r->dline, &o, DLINE_MAX, "\",\"host\":\"");
    jput(r->dline, &o, DLINE_MAX, r->host);
    jraw(r->dline, &o, DLINE_MAX, "\",\"ua\":\"");
    jput(r->dline, &o, DLINE_MAX, r->ua);
    jraw(r->dline, &o, DLINE_MAX, "\",\"body\":\"");
    jput(r->dline, &o, DLINE_MAX, r->body_txt);
    snprintf(num, sizeof(num), "\",\"body_len\":%u,\"head_len\":%u}\n",
             (unsigned)body_len, (unsigned)(c->head_len ? c->head_len : c->len));
    jraw(r->dline, &o, DLINE_MAX, num);
    if (o + 1 >= DLINE_MAX) {           // did not fit (escaped UA or body): a valid line without them
        o = 0;
        jraw(r->dline, &o, DLINE_MAX, "{\"kind\":\"http\",\"cut\":true,\"ip\":\"");
        jraw(r->dline, &o, DLINE_MAX, ip);
        jraw(r->dline, &o, DLINE_MAX, "\",\"category\":\"");
        jraw(r->dline, &o, DLINE_MAX, CAT[cat].key);
        jraw(r->dline, &o, DLINE_MAX, "\",\"request\":\"");
        jput(r->dline, &o, DLINE_MAX / 2, r->rline);
        snprintf(num, sizeof(num), "\",\"ts\":%lu,\"port\":%u,\"body_len\":%u}\n",
                 (unsigned long)time(NULL), (unsigned)c->port, (unsigned)body_len);
        jraw(r->dline, &o, DLINE_MAX, num);
    }

    char *line = heap_caps_malloc(o + 1, MALLOC_CAP_SPIRAM);
    if (!line) return;
    memcpy(line, r->dline, o + 1);
    sd_log_line(line, o);                       // takes the buffer, frees it
}

static void emit_event(const conn_t *c, cat_t cat)
{
    req_t *r = R;
    uint32_t now = (uint32_t)(now_ms() / 1000);
    if (now - s_win_start >= 60) {
        if (s_win_dropped) {
            // Attributed to the last source that was not logged.
            attack_log_t s = { .type = ATTACK_HTTP, .src_ip = s_win_last_ip,
                               .timestamp = (uint32_t)time(NULL) };
            snprintf(s.payload, sizeof(s.payload),
                     "%lu HTTP requests over %d a minute not logged here (console and microSD only)",
                     (unsigned long)s_win_dropped, HTTP_ENG_EVENTS_PER_MIN);
            log_store_append(&s);
        }
        s_win_start = now;
        s_win_events = s_win_dropped = 0;
    }
    if (s_win_events >= HTTP_ENG_EVENTS_PER_MIN) {
        s_win_dropped++;
        s_win_last_ip = c->addr.sin_addr.s_addr;
        return;
    }
    s_win_events++;

    attack_log_t e = {
        .type      = ATTACK_HTTP,
        .src_ip    = c->addr.sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };
    char path[49];
    printable(r->target, strlen(r->target), path, sizeof(path));
    if (cat == CAT_NON_HTTP) {
        char hex[40];
        size_t n = c->len < 12 ? c->len : 12, o = 0;
        for (size_t i = 0; i < n; i++)
            o += (size_t)snprintf(hex + o, sizeof(hex) - o, "%02x", (unsigned char)c->buf[i]);
        hex[o] = '\0';
        snprintf(e.payload, sizeof(e.payload), "%s on %u: %u B, starts %s",
                 CAT[cat].label, (unsigned)c->port, (unsigned)c->len, hex);
    } else if (r->user[0] || r->pass[0]) {
        snprintf(e.payload, sizeof(e.payload), "%s on %u: %s %s %s:%s H=%s UA=%s",
                 CAT[cat].label, (unsigned)c->port, r->method, path, r->user, r->pass, r->host, r->ua);
    } else {
        snprintf(e.payload, sizeof(e.payload), "%s on %u: %s %s H=%s UA=%s",
                 CAT[cat].label, (unsigned)c->port, r->method, path, r->host, r->ua);
    }
    strlcpy(e.username, r->user, sizeof(e.username));
    strlcpy(e.password, r->pass, sizeof(e.password));

    // Resolve the attacker's L2 MAC from ARP (same-LAN host) before storing.
    wifi_manager_lookup_mac(e.src_ip, e.src_mac);
    log_store_append(&e);
    telegram_notify(&e);
}

static void handle(conn_t *c)
{
    req_t *r = R;
    memset(r, 0, offsetof(req_t, dline));
    c->buf[c->len] = '\0';

    size_t head_end = c->head_len ? c->head_len : c->len;
    size_t body_len = c->len - head_end;
    bool http = looks_like_http(c->buf, c->len, true);

    cat_t cat = CAT_UNCLASSIFIED;
    if (!http) {
        cat = CAT_NON_HTTP;
        printable(c->buf, c->len < 64 ? c->len : 64, r->rline, sizeof(r->rline));
    } else {
        char save = c->buf[head_end];
        c->buf[head_end] = '\0';                 // head as one string

        const char *b = c->buf;
        size_t m = strcspn(b, " ");
        printable(b, m < 16 ? m : 16, r->method, sizeof(r->method));
        const char *t = b[m] == ' ' ? b + m + 1 : b + m;
        r->url_len = strcspn(t, " \r\n");
        printable(t, r->url_len, r->target, sizeof(r->target));
        printable(b, strcspn(b, "\r\n"), r->rline, sizeof(r->rline));
        header(b, "Host", r->host, sizeof(r->host));
        header(b, "User-Agent", r->ua, sizeof(r->ua));
        r->long_line = any_line_over(b, HTTP_ENG_LINE_MAX);
        c->buf[head_end] = save;

        bool post = strcmp(r->method, "POST") == 0;
        if (post && body_len) {
            extract_field(c->buf + head_end, "username", r->user, sizeof(r->user));
            extract_field(c->buf + head_end, "password", r->pass, sizeof(r->pass));
        }
        decode_path(r->target, r->path_dec, sizeof(r->path_dec));
        bool dotdot, dotfile;
        path_shape(r->path_dec, &dotdot, &dotfile);

        if (c->head_over || r->long_line || r->url_len > HTTP_ENG_URL_MAX)  cat = CAT_OVERSIZE;
        else if (dotdot)                                                   cat = CAT_TRAVERSAL;
        else if (post && (r->user[0] || r->pass[0]))                      cat = CAT_LOGIN_POST;
        else if (dotfile)                                                  cat = CAT_DOTFILE;
        else if (!post && strcmp(r->method, "GET") && strcmp(r->method, "HEAD")) cat = CAT_METHOD;
        else {
            for (size_t i = 0; cat == CAT_UNCLASSIFIED && i < sizeof(SCANNER_UA) / sizeof(*SCANNER_UA); i++)
                if (ci_contains(r->ua, SCANNER_UA[i])) cat = CAT_SCANNER_UA;
            for (size_t i = 0; cat == CAT_UNCLASSIFIED && i < sizeof(LIBRARY_UA) / sizeof(*LIBRARY_UA); i++)
                if (ci_contains(r->ua, LIBRARY_UA[i])) cat = CAT_LIBRARY_UA;
        }
    }
    if (!r->ua[0])   strlcpy(r->ua, "-", sizeof(r->ua));
    if (!r->host[0]) strlcpy(r->host, "-", sizeof(r->host));
    if (!r->method[0]) strlcpy(r->method, "?", sizeof(r->method));
    size_t bshow = body_len < HTTP_ENG_LOG_BODY ? body_len : HTTP_ENG_LOG_BODY;
    if (http) printable(c->buf + head_end, bshow, r->body_txt, sizeof(r->body_txt));

    // Upstream's replies: GET the login page, POST a redirect, anything else 404.
    if (http && strcmp(r->method, "GET") == 0)       send_all(c->sock, FAKE_LOGIN, sizeof(FAKE_LOGIN) - 1);
    else if (http && strcmp(r->method, "POST") == 0) send_all(c->sock, HTTP_REDIRECT, sizeof(HTTP_REDIRECT) - 1);
    else                                             send_all(c->sock, HTTP_404, sizeof(HTTP_404) - 1);

    char ip[16];
    inet_ntoa_r(c->addr.sin_addr, ip, sizeof(ip));
    ESP_LOGW(TAG, "[%s] :%u %s | %s | Host=%s | UA=%s%s%s", ip, (unsigned)c->port, CAT[cat].label,
             r->rline, r->host, r->ua, r->body_txt[0] ? " | body=" : "", r->body_txt);

    log_detail(c, cat, body_len);
    emit_event(c, cat);

    uint32_t hw = (uint32_t)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    if (hw < s_stack_low) {
        s_stack_low = hw;
        ESP_LOGI(TAG, "stack high-water %lu B free of %d", (unsigned long)hw, HTTP_ENG_TASK_STACK);
    }
}

// ── Connection bookkeeping ────────────────────────────────────────────────────

static void conn_close(conn_t *c)
{
    close(c->sock);
    c->sock = -1;
}

// Read what is there; true when the request is complete (or must be handled now).
static bool conn_read(conn_t *c)
{
    size_t cap = c->head_len ? BUF_MAX : HTTP_ENG_HEAD_MAX;
    if (c->len >= cap) return true;
    int n = recv(c->sock, c->buf + c->len, cap - c->len, MSG_DONTWAIT);
    if (n == 0) {                                                    // peer closed
        if (c->len) return true;
        conn_close(c);
        return false;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        if (c->len) return true;
        conn_close(c);
        return false;
    }
    c->len += (size_t)n;
    c->t_last = now_ms();

    if (!looks_like_http(c->buf, c->len, false)) return true;          // non-HTTP: answer now
    if (!c->head_len) {
        size_t lim = c->len < HTTP_ENG_HEAD_MAX ? c->len : HTTP_ENG_HEAD_MAX;
        c->head_len = find_blank(c->buf, lim);
        if (!c->head_len) {
            if (c->len >= HTTP_ENG_HEAD_MAX) { c->head_over = true; c->head_len = HTTP_ENG_HEAD_MAX; return true; }
            return false;
        }
        char save = c->buf[c->head_len];
        c->buf[c->head_len] = '\0';
        char cl[16];
        header(c->buf, "Content-Length", cl, sizeof(cl));
        c->buf[c->head_len] = save;
        unsigned long v = strtoul(cl, NULL, 10);
        c->body_need = v > HTTP_ENG_BODY_MAX ? HTTP_ENG_BODY_MAX : (size_t)v;
    }
    return c->len - c->head_len >= c->body_need;
}

void http_engine_task(void *arg)
{
    (void)arg;
    C = heap_caps_calloc(HTTP_ENG_MAX_CONN, sizeof(conn_t), MALLOC_CAP_SPIRAM);
    R = heap_caps_calloc(1, sizeof(req_t), MALLOC_CAP_SPIRAM);
    if (!C || !R) {
        ESP_LOGE(TAG, "No PSRAM for connection buffers, HTTP honeypot disabled");
        vTaskDelete(NULL);
    }
    for (int i = 0; i < HTTP_ENG_MAX_CONN; i++) C[i].sock = -1;

    const uint16_t ports[4] = { HTTP_PORT, HTTP_ALT_PORT1, HTTP_ALT_PORT2, HTTP_ALT_PORT3 };
    int srv[4];
    for (int i = 0; i < 4; i++) {
        srv[i] = trap_listen(ports[i], HTTP_BACKLOG);
        if (srv[i] >= 0) ESP_LOGI(TAG, "Honeypot listening on port %u", (unsigned)ports[i]);
    }
    ESP_LOGI(TAG, "%d connections at most, head %d B, body %d B, idle %d s, total %d s",
             HTTP_ENG_MAX_CONN, HTTP_ENG_HEAD_MAX, HTTP_ENG_BODY_MAX, HTTP_RECV_TIMEOUT_S, HTTP_ENG_CONN_S);

    while (1) {
        fd_set rd;
        FD_ZERO(&rd);
        int maxfd = -1, used = 0;
        for (int i = 0; i < HTTP_ENG_MAX_CONN; i++) {
            if (C[i].sock < 0) continue;
            used++;
            FD_SET(C[i].sock, &rd);
            if (C[i].sock > maxfd) maxfd = C[i].sock;
        }
        if (used < HTTP_ENG_MAX_CONN) {           // full: new ones wait in the backlog
            for (int i = 0; i < 4; i++) {
                if (srv[i] < 0) continue;
                FD_SET(srv[i], &rd);
                if (srv[i] > maxfd) maxfd = srv[i];
            }
        }
        if (maxfd < 0) { vTaskDelay(pdMS_TO_TICKS(1000)); continue; }

        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
        int nready = select(maxfd + 1, &rd, NULL, NULL, &tv);
        int64_t now = now_ms();

        if (nready > 0) {
            for (int i = 0; i < 4 && used < HTTP_ENG_MAX_CONN; i++) {
                if (srv[i] < 0 || !FD_ISSET(srv[i], &rd)) continue;
                conn_t *c = NULL;
                for (int k = 0; k < HTTP_ENG_MAX_CONN; k++) if (C[k].sock < 0) { c = &C[k]; break; }
                if (!c) break;
                socklen_t alen = sizeof(c->addr);
                int s = accept(srv[i], (struct sockaddr *)&c->addr, &alen);
                if (s < 0) {
                    // Out of sockets: the connection stays pending, so back off.
                    ESP_LOGW(TAG, "accept on port %u failed: errno %d", (unsigned)ports[i], errno);
                    vTaskDelay(pdMS_TO_TICKS(200));
                    continue;
                }
                struct timeval st = { .tv_sec = HTTP_ENG_SEND_TIMEOUT_S, .tv_usec = 0 };
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &st, sizeof(st));
                c->sock = s;
                c->port = ports[i];
                c->t_open = c->t_last = now;
                c->len = c->head_len = c->body_need = 0;
                c->head_over = false;
                used++;
            }
            for (int i = 0; i < HTTP_ENG_MAX_CONN; i++) {
                conn_t *c = &C[i];
                if (c->sock < 0 || !FD_ISSET(c->sock, &rd)) continue;
                if (conn_read(c)) { handle(c); conn_close(c); }
            }
        }

        // Timeouts: handle what arrived, or drop a connection that sent nothing.
        for (int i = 0; i < HTTP_ENG_MAX_CONN; i++) {
            conn_t *c = &C[i];
            if (c->sock < 0) continue;
            if (now - c->t_last >= HTTP_RECV_TIMEOUT_S * 1000 || now - c->t_open >= HTTP_ENG_CONN_S * 1000) {
                if (c->len) handle(c);
                conn_close(c);
            }
        }
    }
}
