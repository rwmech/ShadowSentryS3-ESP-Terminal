// Pi-hole routes on the admin port. See api_pihole.h.

#include "api_pihole.h"
#include "pihole.h"
#include "json_esc.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SEND_TIMEOUT_S  10
#define OUT_MAX         (8 * 1024)      // status about 1.5 KB, one device at most about 4.6 KB

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

static void send_json(int sock, const char *status, const char *body, size_t len)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, (unsigned)len);
    if (n <= 0 || n >= (int)sizeof(hdr)) return;
    if (send_all(sock, hdr, (size_t)n)) send_all(sock, body, len);
}

static void send_lit(int sock, const char *status, const char *body)
{
    send_json(sock, status, body, strlen(body));
}

// ── Bounded writer ────────────────────────────────────────────────────────────

typedef struct { char *b; size_t cap, o; bool full; } jw_t;

static void jw(jw_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jw(jw_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(j->b + j->o, j->cap - j->o, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= j->cap - j->o) { j->full = true; return; }
    j->o += (size_t)w;
}

static void jw_kstr(jw_t *j, const char *key, const char *s, size_t max)
{
    jw(j, ",\"%s\":\"", key);
    if (j->full) return;
    size_t room = j->cap - j->o;
    size_t n = json_esc(s, max, j->b + j->o, room);
    if (n + 3 >= room) { j->full = true; return; }
    j->o += n;
    jw(j, "\"");
}

// ── Query parameters ──────────────────────────────────────────────────────────

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// The value of key in q (up to ' ', '#' or the end), percent-decoded, into out.
// False if absent, too long or badly encoded.
static bool param(const char *q, const char *key, char *out, size_t cap)
{
    size_t kl = strlen(key);
    for (const char *p = q; p && *p && *p != ' ';) {
        if (!strncmp(p, key, kl) && p[kl] == '=') {
            p += kl + 1;
            size_t o = 0;
            while (*p && *p != '&' && *p != ' ' && *p != '#' && *p != '\r') {
                char c = *p++;
                if (c == '%') {
                    int a = hexv(p[0]), b = a < 0 ? -1 : hexv(p[1]);
                    if (b < 0) return false;
                    c = (char)(a * 16 + b);
                    p += 2;
                }
                if (o + 1 >= cap) return false;
                out[o++] = c;
            }
            out[o] = '\0';
            return true;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return false;
}

static bool parse_ip(const char *s, uint32_t *out)
{
    unsigned a[4];
    char tail;
    if (strlen(s) > 15 || sscanf(s, "%3u.%3u.%3u.%3u%c", &a[0], &a[1], &a[2], &a[3], &tail) != 4) return false;
    if (a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255) return false;
    *out = (uint32_t)a[0] | (uint32_t)a[1] << 8 | (uint32_t)a[2] << 16 | (uint32_t)a[3] << 24;
    return *out != 0;
}

static bool parse_mac(const char *s, uint8_t mac[6])
{
    if (strlen(s) != 17) return false;
    for (int i = 0; i < 6; i++) {
        int a = hexv(s[3 * i]), b = hexv(s[3 * i + 1]);
        if (a < 0 || b < 0 || (i < 5 && s[3 * i + 2] != ':' && s[3 * i + 2] != '-')) return false;
        mac[i] = (uint8_t)(a * 16 + b);
    }
    return mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5];
}

// ── Routes ────────────────────────────────────────────────────────────────────

static void get_status(int sock, char *out)
{
    pihole_status_t *s = heap_caps_malloc(sizeof(*s), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s) { send_lit(sock, "503 Service Unavailable", "{\"error\":\"out of memory\"}"); return; }
    pihole_get_status(s);
    jw_t j = { .b = out, .cap = OUT_MAX };
    if (!s->enabled && !s->running) {
        jw(&j, "{\"enabled\":false}");
    } else {
        uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);
        jw(&j, "{\"enabled\":%s,\"running\":%s,\"session\":%s,\"syncing\":%s",
           s->enabled ? "true" : "false", s->running ? "true" : "false",
           s->session ? "true" : "false", s->syncing ? "true" : "false");
        jw_kstr(&j, "state", s->state, sizeof(s->state));
        jw_kstr(&j, "error", s->error, sizeof(s->error));
        jw_kstr(&j, "version", s->version, sizeof(s->version));
        jw_kstr(&j, "host", s->host, sizeof(s->host));
        jw_kstr(&j, "ip", s->ip, sizeof(s->ip));
        jw_kstr(&j, "tls_seen", s->tls_seen, sizeof(s->tls_seen));
        jw(&j, ",\"last_http\":%d,\"last_ok_ts\":%lu,\"last_ok_ago_s\":%ld,\"next_in_s\":%lu,\"backoff_s\":%lu,"
               "\"devices\":%lu,\"with_top\":%lu,\"syncs\":%lu,\"failures\":%lu,\"requests\":%lu,"
               "\"oversized\":%lu,\"stack_free\":%lu,\"sync_s\":%d,\"refresh_min_s\":%d",
           s->last_http, (unsigned long)s->last_ok_ts,
           s->last_ok_up ? (long)(up - s->last_ok_up) : -1L, (unsigned long)s->next_in_s,
           (unsigned long)s->backoff_s, (unsigned long)s->devices, (unsigned long)s->with_top,
           (unsigned long)s->syncs, (unsigned long)s->failures, (unsigned long)s->requests,
           (unsigned long)s->oversized, (unsigned long)s->stack_free, PIHOLE_SYNC_S, PIHOLE_REFRESH_MIN_S);
        jw(&j, ",\"test_req\":%lu,\"test_done\":%lu,\"test_ok\":%s,\"test_status\":%d",
           (unsigned long)s->test_req, (unsigned long)s->test_done, s->test_ok ? "true" : "false", s->test_status);
        jw_kstr(&j, "test_msg", s->test_msg, sizeof(s->test_msg));
        // The dnsmasq log: what the outbound matching rests on.
        jw(&j, ",\"dns_log\":{");
        jw_kstr(&j, "state", s->log_state, sizeof(s->log_state));
        jw_kstr(&j, "why", s->log_why, sizeof(s->log_why));
        uint32_t cover = s->log_since > s->map_evict_newest ? s->log_since : s->map_evict_newest;
        jw(&j, ",\"since\":%lu,\"cover_from\":%lu,\"query_logging\":%s,\"polls\":%lu,\"lines\":%lu,"
               "\"queries\":%lu,\"answers\":%lu,\"missed\":%lu,\"gaps\":%lu,\"addresses\":%lu,\"evicted\":%lu,"
               "\"geo_blocked_ts\":%lu,\"poll_s\":%d,\"cover_s\":%d,\"map_max\":%d}",
           (unsigned long)s->log_since, (unsigned long)(s->log_since ? cover : 0),
           s->query_logging < 0 ? "null" : s->query_logging ? "true" : "false",
           (unsigned long)s->log_polls, (unsigned long)s->log_lines, (unsigned long)s->log_queries,
           (unsigned long)s->log_answers, (unsigned long)s->log_missed, (unsigned long)s->log_gaps,
           (unsigned long)s->map_entries, (unsigned long)s->map_evicted, (unsigned long)s->geo_blocked_ts,
           PIHOLE_LOG_POLL_S, PIHOLE_LOG_COVER_S, PIHOLE_MAP_MAX);
        jw(&j, "}");
    }
    free(s);
    if (j.full) send_lit(sock, "500 Internal Server Error", "{\"error\":\"status too long\"}");
    else send_json(sock, "200 OK", out, j.o);
}

static void post_test(int sock, char *out)
{
    uint32_t n = pihole_request_test();
    if (!n) { send_lit(sock, "409 Conflict", "{\"error\":\"save a Pi-hole URL and app password first\"}"); return; }
    int len = snprintf(out, OUT_MAX, "{\"queued\":true,\"test\":%lu}", (unsigned long)n);
    send_json(sock, "200 OK", out, (size_t)len);
}

static void post_refresh(int sock, const char *query, char *out)
{
    char v[24];
    uint32_t ip = 0;
    if (param(query, "ip", v, sizeof(v)) && !parse_ip(v, &ip)) {
        send_lit(sock, "400 Bad Request", "{\"error\":\"ip must be a dotted quad\"}");
        return;
    }
    int r = pihole_request_refresh(ip);
    if (r < 0) { send_lit(sock, "409 Conflict", "{\"error\":\"Pi-hole is off\"}"); return; }
    if (r > 0) {
        int len = snprintf(out, OUT_MAX, "{\"error\":\"one refresh per %d s\",\"retry_after_s\":%d}",
                           PIHOLE_REFRESH_MIN_S, r);
        send_json(sock, "429 Too Many Requests", out, (size_t)len);
        return;
    }
    send_lit(sock, "202 Accepted", "{\"queued\":true}");
}

static void get_device(int sock, const char *query, char *out)
{
    char v[48];
    uint32_t ip = 0;
    uint8_t mac[6] = { 0 };
    bool has_mac = false;
    if (param(query, "ip", v, sizeof(v)) && v[0] && !parse_ip(v, &ip)) {
        send_lit(sock, "400 Bad Request", "{\"error\":\"ip must be a dotted quad\"}");
        return;
    }
    if (param(query, "mac", v, sizeof(v)) && v[0]) {
        if (!parse_mac(v, mac)) { send_lit(sock, "400 Bad Request", "{\"error\":\"mac must be aa:bb:cc:dd:ee:ff\"}"); return; }
        has_mac = true;
    }
    if (!ip && !has_mac) { send_lit(sock, "400 Bad Request", "{\"error\":\"give mac or ip\"}"); return; }
    pihole_status_t *s = heap_caps_malloc(sizeof(*s), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s) { send_lit(sock, "503 Service Unavailable", "{\"error\":\"out of memory\"}"); return; }
    pihole_get_status(s);
    bool on = s->enabled;
    free(s);
    if (!on) { send_lit(sock, "200 OK", "{\"enabled\":false}"); return; }
    static const char head[] = "{\"enabled\":true,\"found\":true";
    memcpy(out, head, sizeof(head) - 1);
    size_t o = sizeof(head) - 1;
    size_t n = pihole_device_json(ip, has_mac ? mac : NULL, out + o, OUT_MAX - o - 2, true, true);
    if (n == 0) { send_lit(sock, "200 OK", "{\"enabled\":true,\"found\":false}"); return; }
    if (n >= OUT_MAX - o - 2) { send_lit(sock, "500 Internal Server Error", "{\"error\":\"device too long\"}"); return; }
    o += n;
    out[o++] = '}';
    send_json(sock, "200 OK", out, o);
}

bool api_pihole_handle(int sock, const char *req, int req_len)
{
    (void)req_len;
    bool get = !strncmp(req, "GET ", 4), post = !strncmp(req, "POST ", 5);
    if (!get && !post) return false;
    const char *p = req + (get ? 4 : 5);
    static const char pfx[] = "/api/pihole/";
    if (strncmp(p, pfx, sizeof(pfx) - 1)) return false;
    p += sizeof(pfx) - 1;
    size_t n = strcspn(p, " ?");
    const char *query = p[n] == '?' ? p + n + 1 : "";
    enum { R_NONE, R_STATUS, R_TEST, R_REFRESH, R_DEVICE } r = R_NONE;
    if      (get  && n == 6 && !strncmp(p, "status", 6))  r = R_STATUS;
    else if (post && n == 4 && !strncmp(p, "test", 4))    r = R_TEST;
    else if (post && n == 7 && !strncmp(p, "refresh", 7)) r = R_REFRESH;
    else if (get  && n == 6 && !strncmp(p, "device", 6))  r = R_DEVICE;
    if (r == R_NONE) return false;

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char *out = heap_caps_malloc(OUT_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!out) { send_lit(sock, "503 Service Unavailable", "{\"error\":\"out of memory\"}"); return true; }
    switch (r) {
    case R_STATUS:  get_status(sock, out); break;
    case R_TEST:    post_test(sock, out); break;
    case R_REFRESH: post_refresh(sock, query, out); break;
    case R_DEVICE:  get_device(sock, query, out); break;
    default: break;
    }
    free(out);
    return true;
}
