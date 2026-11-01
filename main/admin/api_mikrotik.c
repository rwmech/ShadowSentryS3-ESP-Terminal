// Router and device-intelligence routes on the admin port. See api_mikrotik.h.
// Fork addition, Robert Mech.
//
// Runs on the admin task (one client at a time, 8 KB internal stack): the
// correlation result and the reply are PSRAM, allocated per request. Every
// string from the router or Pi-hole goes through json_esc().

#include "api_mikrotik.h"
#include "mikrotik.h"
#include "correlate.h"
#include "settings.h"
#include "describe.h"
#include "json_esc.h"
#include "wifi_manager.h"
#include "lwip/sockets.h"
#include "lwip/ip4_addr.h"
#include "esp_heap_caps.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEND_TIMEOUT_S  10
#define INTEL_JSON_MAX  (20 * 1024)     // 48 destinations at about 200 B, flags, identity
#define QUERY_MAX       160

// ── Reply helpers ─────────────────────────────────────────────────────────────

typedef struct { char *b; size_t n, cap; bool full; } jb_t;

static void jb_raw(jb_t *j, const char *s, size_t n)
{
    if (j->full || j->n + n >= j->cap) { j->full = true; return; }
    memcpy(j->b + j->n, s, n);
    j->n += n;
    j->b[j->n] = '\0';
}

static void jb_lit(jb_t *j, const char *s) { jb_raw(j, s, strlen(s)); }

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

// "key":"escaped value"
static void jb_kv(jb_t *j, const char *key, const char *val, size_t max)
{
    char esc[256];
    json_esc(val ? val : "", max, esc, sizeof(esc));
    jb_fmt(j, "\"%s\":\"%s\"", key, esc);
}

static void jb_ip(jb_t *j, const char *key, uint32_t ip)
{
    char b[16] = "";
    if (ip) { ip4_addr_t a = { .addr = ip }; ip4addr_ntoa_r(&a, b, sizeof(b)); }
    jb_fmt(j, "\"%s\":\"%s\"", key, b);
}

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

static void send_err(int sock, const char *status, const char *msg)
{
    char b[160];
    int n = snprintf(b, sizeof(b), "{\"error\":\"%s\"}", msg);     // msg: our own fixed text
    send_json(sock, status, b, (size_t)(n > 0 && n < (int)sizeof(b) ? n : 0));
}

// ── Query ─────────────────────────────────────────────────────────────────────

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// key=value from the query, percent-decoded, bounded. False if absent or too long.
static bool qparam(const char *q, const char *key, char *out, size_t cap)
{
    size_t kl = strlen(key);
    for (const char *p = q; p && *p; ) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > kl && p[kl] == '=' && !strncmp(p, key, kl)) {
            size_t o = 0;
            for (size_t i = kl + 1; i < seg; i++) {
                char c = p[i];
                if (c == '%' && i + 2 < seg && hexv(p[i + 1]) >= 0 && hexv(p[i + 2]) >= 0) {
                    c = (char)(hexv(p[i + 1]) << 4 | hexv(p[i + 2]));
                    i += 2;
                } else if (c == '+') {
                    c = ' ';
                }
                if (o + 1 >= cap) return false;
                out[o++] = c;
            }
            out[o] = '\0';
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

static bool parse_mac(const char *t, uint8_t mac[6])
{
    if (strlen(t) != 17) return false;
    for (int i = 0; i < 6; i++) {
        int h = hexv(t[i * 3]), l = hexv(t[i * 3 + 1]);
        if (h < 0 || l < 0) return false;
        if (i < 5 && t[i * 3 + 2] != ':' && t[i * 3 + 2] != '-') return false;
        mac[i] = (uint8_t)(h << 4 | l);
    }
    static const uint8_t zero[6] = { 0 };
    return memcmp(mac, zero, 6) != 0;
}

static bool parse_ipv4(const char *t, uint32_t *out)
{
    uint8_t b[4];
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

// ── GET /api/device/intel ─────────────────────────────────────────────────────

static const char *conn_state_key(uint8_t s)
{
    return s == MIKROTIK_CONN_OK ? "ok" : s == MIKROTIK_CONN_ERROR ? "error" : "none";
}

static void intel_json(jb_t *j, const correlate_t *c)
{
    char mac[WIFI_MAC_STR_LEN] = "";
    if (c->mac_known) wifi_manager_format_mac(c->mac, mac, sizeof(mac));
    jb_lit(j, "{");
    jb_ip(j, "ip", c->ip);
    jb_fmt(j, ",\"mac\":\"%s\",", mac);
    jb_kv(j, "vendor", c->mac_known ? wifi_manager_mac_vendor(c->mac) : "", 64);
    jb_lit(j, ",");
    jb_kv(j, "label", c->label, sizeof(c->label));
    jb_lit(j, ",");
    jb_kv(j, "summary", c->summary, sizeof(c->summary));

    // The honeypot's own events.
    jb_fmt(j, ",\"honeypot\":{\"events\":%lu,\"last\":%lu,\"codes\":[",
           (unsigned long)c->hp_events, (unsigned long)c->hp_last);
    for (int i = 0; i < c->hp_n; i++) {
        const char *name = describe_code_name(c->hp[i].code);
        jb_fmt(j, "%s{\"code\":\"%s\",\"count\":%u,", i ? "," : "", c->hp[i].code, (unsigned)c->hp[i].n);
        jb_kv(j, "name", name ? name : "", 48);
        jb_lit(j, "}");
    }
    jb_lit(j, "]}");

    // The router.
    jb_fmt(j, ",\"mikrotik\":{\"state\":\"%s\"", mikrotik_state_key(c->mt_state));
    if (c->host_found) {
        const mikrotik_host_t *h = &c->host;
        jb_fmt(j, ",\"as_of\":%lu,\"identity\":{", (unsigned long)c->host_as_of);
        jb_kv(j, "hostname", h->hostname, sizeof(h->hostname));     jb_lit(j, ",");
        jb_kv(j, "client_id", h->client_id, sizeof(h->client_id));  jb_lit(j, ",");
        jb_kv(j, "lease_status", h->lease_status, sizeof(h->lease_status)); jb_lit(j, ",");
        jb_kv(j, "last_seen", h->last_seen, sizeof(h->last_seen));  jb_lit(j, ",");
        jb_kv(j, "port", h->port, sizeof(h->port));                 jb_lit(j, ",");
        jb_kv(j, "bridge", h->bridge, sizeof(h->bridge));           jb_lit(j, ",");
        jb_kv(j, "arp_interface", h->arp_if, sizeof(h->arp_if));    jb_lit(j, ",");
        jb_kv(j, "ap", h->wifi_if, sizeof(h->wifi_if));             jb_lit(j, ",");
        jb_kv(j, "ssid", h->ssid, sizeof(h->ssid));
        jb_fmt(j, ",\"signal\":%d,\"wifi\":%s,\"lease\":%s,\"new_device\":%s,\"first_seen\":%lu}",
               (int)h->signal, (h->src & MIKROTIK_SRC_WIFI) ? "true" : "false",
               (h->src & MIKROTIK_SRC_LEASE) ? "true" : "false", h->new_device ? "true" : "false",
               (unsigned long)h->first_seen);
    } else {
        jb_lit(j, ",\"identity\":null");
    }
    const mikrotik_conn_t *k = &c->conn;
    jb_fmt(j, ",\"conn\":{\"state\":\"%s\",\"pending\":%s,\"as_of\":%lu,\"total\":%u,\"external\":%u,"
              "\"external_hosts\":%u,\"truncated\":%s,\"dst\":[",
           conn_state_key(k->state), k->pending ? "true" : "false", (unsigned long)k->as_of,
           (unsigned)k->total, (unsigned)k->external, (unsigned)k->ext_hosts, k->truncated ? "true" : "false");
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        const char *pr = d->proto == 6 ? "tcp" : d->proto == 17 ? "udp" : d->proto == 1 ? "icmp" : "";
        jb_lit(j, i ? ",{" : "{");
        jb_ip(j, "ip", d->ip);
        jb_fmt(j, ",\"port\":%u,\"proto\":\"%s\",\"proto_num\":%u,\"external\":%s,\"conns\":%u,"
                  "\"bytes_out\":%llu,\"bytes_in\":%llu,\"pkts_out\":%lu,\"pkts_in\":%lu,",
               (unsigned)d->port, pr, (unsigned)d->proto, d->external ? "true" : "false", (unsigned)d->conns,
               (unsigned long long)d->bytes_out, (unsigned long long)d->bytes_in,
               (unsigned long)d->pkts_out, (unsigned long)d->pkts_in);
        jb_kv(j, "tcp_state", d->tcp_state, sizeof(d->tcp_state));
        jb_lit(j, ",");
        jb_kv(j, "name", d->name, sizeof(d->name));
        jb_fmt(j, ",\"name_src\":\"%s\",\"first_seen\":%lu,\"last_seen\":%lu,",
               d->name_src == MIKROTIK_NAME_ROUTER_DNS ? "router_dns" : d->name_src == MIKROTIK_NAME_PIHOLE ? "pihole" : "",
               (unsigned long)d->first_seen, (unsigned long)d->last_seen);
        jb_kv(j, "cc", c->geo[i].cc, sizeof(c->geo[i].cc));
        jb_lit(j, ",");
        jb_kv(j, "asn", c->geo[i].asn, sizeof(c->geo[i].asn));
        jb_lit(j, ",");
        jb_kv(j, "org", c->geo[i].org, sizeof(c->geo[i].org));
        jb_lit(j, ",\"flags\":[");
        for (int b = 0, f = 0; b < 7; b++)
            if (c->dflags[i] & (1u << b)) jb_fmt(j, "%s\"%s\"", f++ ? "," : "", correlate_flag_key(b));
        jb_lit(j, "]");
        if (d->beacon_n) jb_fmt(j, ",\"beacon\":{\"every_s\":%lu,\"times\":%u}", (unsigned long)d->beacon_s, (unsigned)d->beacon_n);
        jb_lit(j, "}");
    }
    jb_lit(j, "]}}");

    // Pi-hole, when a client is built in and has data.
    if (c->dns_on) {
        jb_fmt(j, ",\"pihole\":{\"state\":\"ok\",\"as_of\":%lu,\"window_s\":%lu,\"total\":%u,\"blocked\":%u,",
               (unsigned long)c->dns.as_of, (unsigned long)c->dns.window_s, (unsigned)c->dns.total, (unsigned)c->dns.blocked);
        jb_ip(j, "server", c->dns.server_ip);
        jb_lit(j, ",\"queries\":[");
        for (int i = 0; i < c->dns.n && i < CORRELATE_DNS_MAX; i++) {
            jb_lit(j, i ? ",{" : "{");
            jb_kv(j, "domain", c->dns.q[i].domain, sizeof(c->dns.q[i].domain));
            jb_fmt(j, ",\"blocked\":%s,\"ts\":%lu}", c->dns.q[i].blocked ? "true" : "false", (unsigned long)c->dns.q[i].ts);
        }
        jb_lit(j, "]}");
    } else {
        jb_lit(j, ",\"pihole\":{\"state\":\"off\"}");
    }

    jb_lit(j, ",\"flags\":[");
    for (int i = 0; i < c->n_flags; i++) {
        jb_fmt(j, "%s{\"key\":\"%s\",", i ? "," : "", c->flags[i].key);
        jb_kv(j, "reason", c->flags[i].reason, sizeof(c->flags[i].reason));
        jb_lit(j, "}");
    }
    jb_lit(j, "]}");
}

static void get_intel(int sock, const char *query)
{
    char v[24];
    uint8_t mac[6];
    uint32_t ip = 0;
    bool have_mac = false;
    if (qparam(query, "mac", v, sizeof(v)) && v[0]) {
        if (!parse_mac(v, mac)) { send_err(sock, "400 Bad Request", "mac must be aa:bb:cc:dd:ee:ff"); return; }
        have_mac = true;
    }
    if (qparam(query, "ip", v, sizeof(v)) && v[0]) {
        if (!parse_ipv4(v, &ip) || !ip) { send_err(sock, "400 Bad Request", "ip must be a dotted quad"); return; }
    }
    if (!have_mac && !ip) { send_err(sock, "400 Bad Request", "give mac, ip or both"); return; }

    correlate_t *c = heap_caps_malloc(sizeof(*c), MALLOC_CAP_SPIRAM);
    char *buf = heap_caps_malloc(INTEL_JSON_MAX, MALLOC_CAP_SPIRAM);
    if (!c || !buf) { free(c); free(buf); send_err(sock, "503 Service Unavailable", "out of memory"); return; }
    correlate_build(ip, have_mac ? mac : NULL, true, true, c);   // conn.pending: a fetch is on its way
    jb_t j = { .b = buf, .n = 0, .cap = INTEL_JSON_MAX, .full = false };
    intel_json(&j, c);
    free(c);
    if (j.full) send_err(sock, "500 Internal Server Error", "response too large");
    else send_json(sock, "200 OK", buf, j.n);
    free(buf);
}

// ── Status, test, forget ──────────────────────────────────────────────────────

static void get_status(int sock)
{
    mikrotik_status_t *s = heap_caps_malloc(sizeof(*s), MALLOC_CAP_SPIRAM);
    char *buf = heap_caps_malloc(2048, MALLOC_CAP_SPIRAM);
    if (!s || !buf) { free(s); free(buf); send_err(sock, "503 Service Unavailable", "out of memory"); return; }
    mikrotik_get_status(s);
    jb_t j = { .b = buf, .n = 0, .cap = 2048, .full = false };
    jb_fmt(&j, "{\"enabled\":%s,\"running\":%s,\"state\":\"%s\",\"scheme\":\"%s\",\"last_status\":%d,"
               "\"last_ok\":%lu,\"last_try\":%lu,\"next_s\":%lu,\"backoff_s\":%lu,\"polls\":%lu,\"failures\":%lu,"
               "\"hosts\":%u,\"leases\":%u,\"arp\":%u,\"bridge\":%u,\"wifi\":%u,\"wifi_tables\":[",
               settings_mikrotik_enabled() ? "true" : "false", s->running ? "true" : "false",
               mikrotik_state_key(s->state), s->https ? "https" : "http", s->last_status,
               (unsigned long)s->last_ok, (unsigned long)s->last_try, (unsigned long)s->next_s,
               (unsigned long)s->backoff_s, (unsigned long)s->polls, (unsigned long)s->failures,
               (unsigned)s->hosts, (unsigned)s->leases, (unsigned)s->arp, (unsigned)s->bridge, (unsigned)s->wifi);
    static const char *const WT[3] = { "wifi", "wireless", "caps-man" };
    bool first = true;
    for (int i = 0; i < 3; i++) if (s->wifi_tables & (1u << i)) { jb_fmt(&j, "%s\"%s\"", first ? "" : ",", WT[i]); first = false; }
    jb_fmt(&j, "],\"known\":%u,\"learned\":%s,\"new_devices\":%lu,\"conn_fetches\":%lu,"
               "\"cert\":{\"pin_set\":%s,\"tofu\":\"%s\",\"seen\":\"%s\"},",
           (unsigned)s->known, s->learned ? "true" : "false", (unsigned long)s->new_devices,
           (unsigned long)s->conn_fetches, s->pin_set ? "true" : "false", s->tofu, s->seen);
    jb_kv(&j, "detail", s->detail, sizeof(s->detail));
    jb_fmt(&j, ",\"test_req\":%lu,\"test_done\":%lu,\"test_status\":%d,\"test_ok\":%s,",
           (unsigned long)s->test_req, (unsigned long)s->test_done, s->test_status, s->test_ok ? "true" : "false");
    jb_kv(&j, "test_text", s->test_text, sizeof(s->test_text));
    jb_lit(&j, "}");
    free(s);
    if (j.full) send_err(sock, "500 Internal Server Error", "response too large");
    else send_json(sock, "200 OK", buf, j.n);
    free(buf);
}

static void post_test(int sock)
{
    if (!settings_mikrotik_enabled()) { send_err(sock, "409 Conflict", "MikroTik URL, user or password not set, or switched off"); return; }
    mikrotik_start();                   // in case it was configured since boot
    uint32_t n = mikrotik_request_test();
    if (!n) { send_err(sock, "503 Service Unavailable", "MikroTik task not running"); return; }
    char b[64];
    int len = snprintf(b, sizeof(b), "{\"queued\":true,\"test\":%lu}", (unsigned long)n);
    send_json(sock, "200 OK", b, (size_t)len);
}

static void post_forget(int sock)
{
    mikrotik_cert_forget();
    static const char ok[] = "{\"ok\":true}";
    send_json(sock, "200 OK", ok, sizeof(ok) - 1);
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

bool api_mikrotik_handle(int sock, const char *req, int req_len)
{
    (void)req_len;
    bool get = !strncmp(req, "GET ", 4), post = !strncmp(req, "POST ", 5);
    if (!get && !post) return false;
    const char *t = req + (get ? 4 : 5), *e = t;
    while (*e && *e != ' ' && *e != '\r' && *e != '\n') e++;
    const char *q = memchr(t, '?', (size_t)(e - t));
    size_t plen = (size_t)((q ? q : e) - t);
    char path[40], query[QUERY_MAX + 1] = "";
    if (plen >= sizeof(path)) return false;
    memcpy(path, t, plen);
    path[plen] = '\0';
    bool ours = !strcmp(path, "/api/device/intel") || !strncmp(path, "/api/mikrotik/", 14);
    if (!ours) return false;
    if (q) {
        size_t ql = (size_t)(e - q - 1);
        if (ql > QUERY_MAX) { send_err(sock, "414 URI Too Long", "query too long"); return true; }
        memcpy(query, q + 1, ql);
        query[ql] = '\0';
    }

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (get && !strcmp(path, "/api/device/intel"))            get_intel(sock, query);
    else if (get && !strcmp(path, "/api/mikrotik/status"))    get_status(sock);
    else if (post && !strcmp(path, "/api/mikrotik/test"))     post_test(sock);
    else if (post && !strcmp(path, "/api/mikrotik/cert/forget")) post_forget(sock);
    else send_err(sock, "404 Not Found", "no such route");
    return true;
}
