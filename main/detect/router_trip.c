// Router tripwires: syslog from the MikroTik router, copied off the Wi-Fi
// input, parsed into 55-2x events; the address-list check. See router_trip.h.
// Fork addition, Robert Mech.
//
// Everything in a syslog line is hostile text: a failed login carries the
// user name the attacker typed, a DHCP line the host name a client sent. Every
// read below is bounded by the copied length, and only printable ASCII leaves
// this file.

#include "router_trip.h"
#include "router_flow.h"
#include "mikrotik.h"
#include "mikrotik_watch.h"
#include "settings.h"
#include "sd_log.h"
#include "json_esc.h"
#include "wifi_manager.h"
#include "log_store.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/ip4_addr.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "RTRTRIP";

#define LIVE_S          900         // syslog counts as live this long after a line
#define HOLD_S          300         // one event per code and source
#define HOLD_DNS_S      3600        // DNS bypass: smart TVs do it all day
#define HOLD_N          48
#define FAIL_N          8           // admin addresses with failures being counted
#define FAIL_BURST      3
#define FAIL_WINDOW_S   300
#define RECENT_N        32          // tripwire sources raised by syslog, for the list check
#define RECENT_S        86400
#define SD_PER_MIN      30
#define RT_LINE_MAX        (ROUTER_SYSLOG_SLOT + 1)
#define LIST_MAX        64
#define LIST_EVENTS     4
#define LIST_BYTES      (64 * 1024)

static inline uint16_t rd16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }
static int64_t up_s(void) { return esp_timer_get_time() / 1000000LL; }

// ── Ring (Wi-Fi RX task to router task) ───────────────────────────────────────

typedef struct {
    uint16_t len;
    uint8_t  cut;
    uint8_t  _pad;
    char     data[ROUTER_SYSLOG_SLOT];
} sl_slot_t;

static sl_slot_t        *s_ring;            // PSRAM, ROUTER_SYSLOG_SLOTS
static uint32_t          s_head, s_tail;    // one producer, one consumer
static TaskHandle_t      s_task;
static volatile uint32_t s_rip;             // router IPv4, network order
static portMUX_TYPE      s_gw_mux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t           s_gw_mac[6];
static bool              s_gw_ok;
static volatile uint32_t s_st_received, s_st_foreign, s_st_dropped, s_st_cut;
static volatile int64_t  s_last_line_s;     // uptime s of the last line, 0 never

static bool gw_match(const uint8_t *mac)
{
    portENTER_CRITICAL(&s_gw_mux);
    bool ok = s_gw_ok && !memcmp(mac, s_gw_mac, 6);
    portEXIT_CRITICAL(&s_gw_mux);
    return ok;
}

bool router_frame_tap(const uint8_t *f, size_t len, uint32_t our_ip)
{
    sl_slot_t *ring = __atomic_load_n(&s_ring, __ATOMIC_ACQUIRE);
    if (!f || !our_ip || len < 14 + 20 + 8 || !s_rip) return false;
    if (f[12] != 0x08 || f[13] != 0x00) return false;               // IPv4
    const uint8_t *ip = f + 14;
    unsigned hl = (ip[0] & 0x0fu) * 4u;
    if ((ip[0] >> 4) != 4 || hl < 20 || 14 + hl + 8 > len || ip[9] != 17) return false;
    uint32_t dst, src;
    memcpy(&dst, ip + 16, 4);
    if (dst != our_ip) return false;
    const uint8_t *udp = ip + hl;
    uint16_t dport = rd16(udp + 2);
    bool flow = ROUTER_IPFIX_ENABLE && dport == ROUTER_IPFIX_PORT;
    if (dport != ROUTER_SYSLOG_PORT && !flow) return false;
    if (rd16(ip + 6) & 0x3fff) return false;                        // a fragment: lwIP's
    memcpy(&src, ip + 12, 4);
    uint32_t rip = s_rip;
    if (!rip || src != rip || !gw_match(f + 6)) { s_st_foreign++; return false; }
    size_t tot = rd16(ip + 2), ulen = rd16(udp + 4);
    if (tot < hl + 8 || 14 + tot > len || ulen < 8 || ulen > tot - hl) return false;
    if (flow) {                                     // a no-op while the collector is off
        router_flow_push(udp + 8, ulen - 8);
        TaskHandle_t tk = s_task;
        if (tk) xTaskNotifyGive(tk);
        return true;
    }
    if (!ring) return false;
    s_st_received++;
    uint32_t h = s_head, t = __atomic_load_n(&s_tail, __ATOMIC_ACQUIRE);
    if (h - t >= ROUTER_SYSLOG_SLOTS) { s_st_dropped++; return true; }    // the router's: consumed anyway
    sl_slot_t *d = &ring[h % ROUTER_SYSLOG_SLOTS];
    size_t n = ulen - 8;
    d->cut = n > ROUTER_SYSLOG_SLOT;
    if (d->cut) { n = ROUTER_SYSLOG_SLOT; s_st_cut++; }
    d->len = (uint16_t)n;
    memcpy(d->data, udp + 8, n);
    __atomic_store_n(&s_head, h + 1, __ATOMIC_RELEASE);
    TaskHandle_t tk = s_task;
    if (tk) xTaskNotifyGive(tk);
    return true;
}

// ── State (router task; the recent table also the mikrotik task) ──────────────

typedef struct { uint8_t code; uint16_t held; uint32_t src, aux; int64_t t; } hold_t;
typedef struct { uint32_t ip; int64_t first; uint16_t n; bool raised; } fail_t;

typedef struct {
    char         line[RT_LINE_MAX];
    hold_t       hold[HOLD_N];
    fail_t       fail[FAIL_N];
    attack_log_t ev;
    mikrotik_host_t host;           // src_mac()'s copy, off the task stack
    uint32_t     admin[ROUTER_ADMIN_MAX];
    int          n_admin;
    int64_t      sd_min;            // uptime minute of the SD budget
    int          sd_used;
    struct { uint32_t ip; uint32_t t; } recent[RECENT_N];   // under s_rec_mux (the list check reads it)
} rt_t;

static rt_t        *R;
static portMUX_TYPE s_rec_mux = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE s_st_mux = portMUX_INITIALIZER_UNLOCKED;
static router_trip_status_t s_st;                              // counters under s_st_mux

#define ST_INC(f) do { portENTER_CRITICAL(&s_st_mux); s_st.f++; portEXIT_CRITICAL(&s_st_mux); } while (0)

enum { K_FAIL, K_LOGIN, K_CHANGE, K_PSD, K_MGMT, K_DNS, K_LIST, K_DNS_RED };
static const char *const CODE[] = { "55-21", "55-22", "55-23", "55-24", "55-25", "55-26", "55-27", "55-28" };

// Uptime seconds + 1, so 0 stays "never".
static void recent_note(uint32_t ip)
{
    rt_t *r = __atomic_load_n(&R, __ATOMIC_ACQUIRE);
    if (!r || !ip) return;
    uint32_t now = (uint32_t)up_s() + 1;
    portENTER_CRITICAL(&s_rec_mux);
    int k = 0;
    for (int i = 0; i < RECENT_N; i++) {
        if (r->recent[i].ip == ip) { k = i; break; }
        if (r->recent[i].t < r->recent[k].t) k = i;
    }
    r->recent[k].ip = ip;
    r->recent[k].t = now;
    portEXIT_CRITICAL(&s_rec_mux);
}

static bool recent_has(uint32_t ip)
{
    rt_t *r = __atomic_load_n(&R, __ATOMIC_ACQUIRE);
    if (!r) return false;
    uint32_t now = (uint32_t)up_s() + 1;
    bool hit = false;
    portENTER_CRITICAL(&s_rec_mux);
    for (int i = 0; i < RECENT_N && !hit; i++)
        hit = r->recent[i].ip == ip && r->recent[i].t && now - r->recent[i].t < RECENT_S;
    portEXIT_CRITICAL(&s_rec_mux);
    return hit;
}

// ── Small helpers ─────────────────────────────────────────────────────────────

// Printable ASCII only; '"', '\\' and '`' become '\''. At most n bytes of s.
static void txt(char *out, size_t cap, const char *s, size_t n)
{
    size_t o = 0;
    if (!cap) return;
    for (size_t i = 0; i < n && s[i] && o + 1 < cap; i++) {
        char c = s[i];
        if (c < 0x20 || c > 0x7e) c = '?';
        if (c == '"' || c == '\\' || c == '`') c = '\'';
        out[o++] = c;
    }
    out[o] = '\0';
}

static void ip_s(uint32_t ip, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

// Exactly n characters of s as a dotted quad.
static bool ip4_n(const char *s, size_t n, uint32_t *out)
{
    uint8_t b[4];
    size_t i = 0;
    for (int k = 0; k < 4; k++) {
        unsigned v = 0, d = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + (unsigned)(s[i++] - '0');
            if (++d > 3 || v > 255) return false;
        }
        if (!d) return false;
        b[k] = (uint8_t)v;
        if (k < 3) { if (i >= n || s[i] != '.') return false; i++; }
    }
    if (i != n) return false;
    memcpy(out, b, 4);
    return true;
}

int router_trip_parse_ips(const char *s, uint32_t *out, int max)
{
    int n = 0;
    while (s && *s && n < max) {
        while (*s == ',' || *s == ' ' || *s == ';') s++;
        size_t k = 0;
        while (s[k] && s[k] != ',' && s[k] != ' ' && s[k] != ';') k++;
        uint32_t ip;
        if (k && ip4_n(s, k, &ip) && ip) out[n++] = ip;
        s += k;
    }
    return n;
}

// Length of the token at s: up to a space, a comma or the end, at most max.
static size_t tok(const char *s, size_t max)
{
    size_t n = 0;
    while (s[n] && s[n] != ' ' && s[n] != ',' && n < max) n++;
    return n;
}

bool router_trip_is_admin(uint32_t ip)
{
    if (!ip) return false;
    if (R) for (int i = 0; i < R->n_admin; i++) if (R->admin[i] == ip) return true;
    const settings_t *st = settings_get();
    int n = st->admin_allow_n;
    if (n < 0 || n > SETTINGS_ADMIN_ALLOW_MAX) n = 0;
    for (int i = 0; i < n; i++) if (st->admin_allow[i] == ip) return true;
    return false;
}

static uint32_t our_ip(void)
{
    char b[16];
    uint32_t ip = 0;
    if (wifi_manager_get_ip_str(b, sizeof(b)) && ip4_n(b, strlen(b), &ip)) return ip;
    return 0;
}

// ── Events ────────────────────────────────────────────────────────────────────

// The source's MAC for an event: this board's ARP table first, else the
// MikroTik client's host cache (its ARP, leases and bridge hosts from the
// last poll; a linear scan under its lock), so the vendor resolves for
// devices this board never talked to. h is the caller's scratch copy.
static void src_mac(uint32_t ip, uint8_t mac[6], mikrotik_host_t *h)
{
    static const uint8_t zero[6] = { 0 };
    if (!ip || wifi_manager_lookup_mac(ip, mac)) return;
    if (mikrotik_host(NULL, ip, h, NULL) && memcmp(h->mac, zero, 6)) memcpy(mac, h->mac, 6);
}

// One event per code, source and aux per hold time; repeats are counted into
// the next. True when the event should go out now (*held = repeats before it).
static bool hold_pass(int code, uint32_t src, uint32_t aux, int hold_s, uint16_t *held)
{
    int64_t now = up_s();
    hold_t *h = NULL, *old = &R->hold[0];
    for (int i = 0; i < HOLD_N; i++) {
        hold_t *x = &R->hold[i];
        if (x->t && x->code == code && x->src == src && x->aux == aux) { h = x; break; }
        if (x->t < old->t) old = x;
    }
    if (h && now - h->t < hold_s) {
        if (h->held < 65535) h->held++;
        ST_INC(held);
        return false;
    }
    *held = h ? h->held : 0;
    if (!h) h = old;
    h->code = (uint8_t)code;
    h->src = src;
    h->aux = aux;
    h->t = now;
    h->held = 0;
    return true;
}

static void trip_event(int code, uint32_t src, uint16_t held, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void trip_event(int code, uint32_t src, uint16_t held, const char *fmt, ...)
{
    attack_log_t *e = &R->ev;
    memset(e, 0, sizeof(*e));
    e->timestamp = (uint32_t)time(NULL);
    e->type = ATTACK_ROUTER;
    e->src_ip = src ? src : s_rip;
    src_mac(e->src_ip, e->src_mac, &R->host);
    char tail[20] = "";
    if (held) snprintf(tail, sizeof(tail), " (+%u held)", (unsigned)held);
    size_t room = sizeof(e->payload) - strlen(tail);
    int n = snprintf(e->payload, room, "[%s] ", CODE[code]);
    va_list ap;
    va_start(ap, fmt);
    if (n > 0 && (size_t)n < room) vsnprintf(e->payload + n, room - (size_t)n, fmt, ap);
    va_end(ap);
    strlcat(e->payload, tail, sizeof(e->payload));
    ESP_LOGW(TAG, "%s", e->payload);
    if (code == K_PSD || code == K_MGMT || code == K_DNS || code == K_DNS_RED) recent_note(src);
    if (mikrotik_watch_post(e)) ST_INC(events);
    else ESP_LOGW(TAG, "event dropped (queue full)");
}

// {"kind":"router_log",...}: what the router said, for the Logs page and the
// device page. At most SD_PER_MIN lines a minute.
static void sd_line(const char *what, const char *code, uint32_t src, const char *user, const char *via,
                    const char *msg)
{
    int64_t m = up_s() / 60;
    if (m != R->sd_min) { R->sd_min = m; R->sd_used = 0; }
    if (R->sd_used >= SD_PER_MIN) { ST_INC(sd_dropped); return; }
    R->sd_used++;
    char *l = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
    if (!l) return;
    char ip[16] = "", mac[WIFI_MAC_STR_LEN] = "", u[72], v[40], mj[520];
    uint8_t mb[6] = { 0 };
    if (src) {
        ip_s(src, ip, sizeof(ip));
        if (wifi_manager_lookup_mac(src, mb)) wifi_manager_format_mac(mb, mac, sizeof(mac));
    }
    json_esc(user ? user : "", 32, u, sizeof(u));
    json_esc(via ? via : "", 16, v, sizeof(v));
    json_esc(msg ? msg : "", 256, mj, sizeof(mj));
    int n = snprintf(l, 1024, "{\"kind\":\"router_log\",\"ts\":%lu,\"what\":\"%s\",\"code\":\"%s\",\"ip\":\"%s\","
                     "\"mac\":\"%s\",\"user\":\"%s\",\"via\":\"%s\",\"msg\":\"%s\"}\n",
                     (unsigned long)time(NULL), what, code ? code : "", ip, mac, u, v, mj);
    if (n <= 0 || n >= 1024) { free(l); return; }
    if (sd_log_line(l, (size_t)n)) ST_INC(sd_lines);
}

// ── Line parsers ──────────────────────────────────────────────────────────────

// Strip what RouterOS puts before the message: an RFC 3164 "<PRI>", the time
// ("Oct  2 17:36:35 " or an ISO 8601 token) and the identity, then the topics
// ("system,error,critical") if add-topics-string or the default format put
// them there. *topics points at them ("" none).
static char *split(char *s, char **topics, size_t *tlen)
{
    *topics = "";
    *tlen = 0;
    bool syslog = false;
    if (s[0] == '<') {
        int i = 1;
        while (i < 5 && s[i] >= '0' && s[i] <= '9') i++;
        if (i > 1 && s[i] == '>') { s += i + 1; syslog = true; }
    }
    if (syslog) {
        static const char *const MON[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                                           "Oct", "Nov", "Dec" };
        bool bsd = false;
        for (int m = 0; m < 12 && !bsd; m++) bsd = !strncmp(s, MON[m], 3);
        if (bsd && strlen(s) >= 16 && s[3] == ' ' && s[9] == ':' && s[12] == ':' && s[15] == ' ') s += 16;
        else if (isdigit((unsigned char)s[0]) && strlen(s) > 5 && s[4] == '-') s += tok(s, 40) + (s[tok(s, 40)] == ' ');
        size_t h = tok(s, 64);                          // the identity
        if (s[h] == ' ') s += h + 1;
    }
    // Topics: lowercase words, digits, '-' and '!' joined by commas, ending in a space.
    size_t n = 0;
    bool comma = false;
    while (s[n] && n < 80 && (islower((unsigned char)s[n]) || isdigit((unsigned char)s[n]) || s[n] == '-' ||
                              s[n] == '!' || s[n] == ',')) {
        if (s[n] == ',') comma = true;
        n++;
    }
    static const char *const ONE[] = { "system", "firewall", "dhcp", "account", "critical", "info", "error",
                                       "warning", "script" };
    bool one = false;
    for (size_t i = 0; i < sizeof(ONE) / sizeof(ONE[0]) && !one; i++) one = strlen(ONE[i]) == n && !strncmp(s, ONE[i], n);
    if (n && s[n] == ' ' && (comma || one)) {
        *topics = s;
        *tlen = n;
        s += n + 1;
    }
    while (*s == ' ') s++;
    return s;
}

// The source of a login line. The user name before it is attacker text and
// may itself hold " from 1.2.3.4 via ssh", so the last " from <IPv4> via
// <svc>" wins; and when RouterOS appends its extra fields ("app=ssh
// duser=<user> outcome=failure src=<IPv4>", which repeat the user name after
// the message), the last " src=<IPv4>" wins over both. *end: where the user
// name stops (the chosen " from ", or the end).
static void from_via(const char *p, uint32_t *addr, char *via, size_t vcap, const char **end)
{
    *addr = 0;
    via[0] = '\0';
    *end = NULL;
    for (const char *f = strstr(p, " from "); f; f = strstr(f + 1, " from ")) {
        const char *a = f + 6;
        size_t n = tok(a, 15);
        uint32_t ip;
        if (!ip4_n(a, n, &ip) || strncmp(a + n, " via ", 5)) continue;
        *addr = ip;
        *end = f;
        txt(via, vcap, a + n + 5, tok(a + n + 5, 15));
    }
    const char *src = NULL;
    for (const char *f = strstr(p, " src="); f; f = strstr(f + 1, " src=")) src = f + 5;
    uint32_t ip;
    if (src && ip4_n(src, tok(src, 15), &ip)) *addr = ip;
}

static void on_login_fail(const char *m)
{
    ST_INC(c_login_fail);
    const char *u = m + strlen("login failure for user ");
    const char *f;
    char user[24], via[16];
    uint32_t a;
    from_via(u - 1, &a, via, sizeof(via), &f);
    txt(user, sizeof(user), u, f ? (size_t)(f - u) : tok(u, 23));
    sd_line("login_fail", CODE[K_FAIL], a, user, via, m);
    if (a && a == our_ip()) return;                     // our own read-only login
    uint16_t held = 0;
    if (!a || !router_trip_is_admin(a)) {
        if (hold_pass(K_FAIL, a, 0, HOLD_S, &held))
            trip_event(K_FAIL, a, held, "as %s via %s", user, via[0] ? via : "?");   // the source is the headline's
        return;
    }
    // An admin address: a burst only.
    int64_t now = up_s();
    fail_t *x = NULL, *old = &R->fail[0];
    for (int i = 0; i < FAIL_N; i++) {
        if (R->fail[i].ip == a) { x = &R->fail[i]; break; }
        if (R->fail[i].first < old->first) old = &R->fail[i];
    }
    if (!x || now - x->first > FAIL_WINDOW_S) {
        x = x ? x : old;
        x->ip = a; x->first = now; x->n = 0; x->raised = false;
    }
    x->n++;
    if (x->n >= FAIL_BURST && !x->raised) {
        x->raised = true;
        trip_event(K_FAIL, a, 0, "%u in %lu s from an admin, as %s via %s", (unsigned)x->n,
              (unsigned long)(now - x->first), user, via[0] ? via : "?");
    }
}

static void on_login(const char *m)
{
    ST_INC(c_login);
    const char *u = m + 5;                              // "user "
    const char *f = strstr(u, " logged in");
    char user[24], via[16];
    txt(user, sizeof(user), u, f ? (size_t)(f - u) : tok(u, 23));
    uint32_t a;
    const char *end;
    from_via(f ? f : u - 1, &a, via, sizeof(via), &end);
    if (a && a == our_ip()) return;                     // our own REST login: every request logs one
    sd_line("login", "", a, user, via, m);
    if (!a || router_trip_is_admin(a)) return;
    uint16_t held = 0;
    if (hold_pass(K_LOGIN, a, 0, HOLD_S, &held))
        trip_event(K_LOGIN, a, held, "as %s via %s, not an admin", user, via[0] ? via : "?");
}

// "<item> changed by <actor>[ (<command>)]". actor: "admin",
// "scheduler:<name>", "script:<name>" or "<client>/<service>:<user>@<addr>".
static void on_change(const char *m, const char *by)
{
    ST_INC(c_change);
    const char *verb_end = strstr(by, " by ");
    if (!verb_end) return;
    const char *act = verb_end + 4;
    size_t an = 0;
    while (act[an] && act[an] != ' ' && an < 96) an++;
    char what[48], actor[48];
    txt(what, sizeof(what), m, (size_t)(verb_end - m));
    txt(actor, sizeof(actor), act, an);
    uint32_t a = 0;
    const char *at = memchr(act, '@', an);
    if (at) {
        size_t k = (size_t)(act + an - (at + 1));
        if (!ip4_n(at + 1, k, &a)) a = 0;
    }
    bool automated = !strncmp(act, "scheduler:", 10) || !strncmp(act, "script:", 7);
    bool alert = automated || (a && !router_trip_is_admin(a));
    sd_line("change", alert ? CODE[K_CHANGE] : "", a, actor, "", m);
    if (!alert) return;
    uint16_t held = 0;
    if (hold_pass(K_CHANGE, a, 0, 60, &held))
        trip_event(K_CHANGE, a, held, "%s by %s%s", what, actor, automated ? " (a scheduler or script)" : ", not an admin");
}

// "SS-TRIP-<KIND> <chain>: in:.. out:.., ..., proto TCP (SYN), a:p->b:q, len N"
static void on_firewall(const char *m)
{
    int code;
    const char *k = m + 8;
    if (!strncmp(k, "PSD", 3))       { code = K_PSD;  ST_INC(c_psd); }
    else if (!strncmp(k, "MGMT", 4)) { code = K_MGMT; ST_INC(c_mgmt); }
    else if (!strncmp(k, "DNS", 3))  { code = K_DNS;  ST_INC(c_dns); }
    else { ST_INC(c_other); return; }
    char proto[8] = "";
    const char *p = strstr(m, "proto ");
    if (p) txt(proto, sizeof(proto), p + 6, tok(p + 6, 7));
    uint32_t src = 0, dst = 0;
    unsigned dport = 0;
    const char *ar = strstr(m, "->");
    if (ar && ar > m) {
        const char *b = ar;
        while (b > m && b[-1] != ' ' && ar - b < 22) b--;
        const char *c = memchr(b, ':', (size_t)(ar - b));
        if (!ip4_n(b, (size_t)((c ? c : ar) - b), &src)) src = 0;
        const char *d = ar + 2;
        size_t dn = tok(d, 22);
        const char *dc = memchr(d, ':', dn);
        if (!ip4_n(d, (size_t)((dc ? dc : d + dn) - d), &dst)) dst = 0;
        if (dc) dport = (unsigned)strtoul(dc + 1, NULL, 10);
    }
    // The router NATs every LAN device's port 53 to the Pi-hole, after this
    // rule saw it: a lookup on 53 was handled, so 55-28 (info). DoT (853)
    // and the rest cannot be redirected and stay 55-26.
    if (code == K_DNS && dport == 53 && (!strcmp(proto, "UDP") || !strcmp(proto, "TCP")) &&
        settings_get()->router_dns_redirect)
        code = K_DNS_RED;
    sd_line(code == K_PSD ? "psd" : code == K_MGMT ? "mgmt" : "dns", CODE[code], src, "", "", m);
    if (!src || router_trip_is_admin(src)) return;
    char ds[16] = "?";
    if (dst) ip_s(dst, ds, sizeof(ds));
    uint16_t held = 0;
    // Kept short: the headline ("Code CC-NN <name> | <source>: " plus this,
    // DESCRIBE_MAX 96) ends at 95 characters, and the code name already says
    // what the rule is. Worst case (15-character addresses, 5-digit port) is
    // 90 characters (55-28; a 7-character proto makes 55-25 80), so the
    // address and port are never cut; a " (+N held)" tail may be, at a word,
    // with "..." (describe.c).
    if (code == K_PSD) {
        if (hold_pass(code, src, 0, HOLD_S, &held))
            trip_event(code, src, held, "%s, first to %s", proto[0] ? proto : "?", ds);
    } else if (code == K_MGMT) {
        if (hold_pass(code, src, dport, HOLD_S, &held))
            trip_event(code, src, held, "%s to %s:%u", proto[0] ? proto : "?", ds, dport);
    } else if (code == K_DNS_RED) {
        if (hold_pass(code, src, dst, HOLD_DNS_S, &held))
            trip_event(code, src, held, "%s 53 to %s, redirected", proto, ds);
    } else {
        // TCP 853 is DNS over TLS: named, since that is what bypasses the Pi-hole.
        if (hold_pass(code, src, dst, HOLD_DNS_S, &held))
            trip_event(code, src, held, "%s %u to %s", dport == 853 && !strcmp(proto, "TCP") ? "DoT" : proto[0] ? proto : "?",
                       dport, ds);
    }
}

// "<server> assigned <ip> for <MAC> <host>" (RouterOS 7; "to" before 7).
static void on_dhcp(const char *m, const char *as)
{
    ST_INC(c_dhcp);
    const char *i = as + 10;                            // " assigned "
    size_t in = tok(i, 15);
    uint32_t ip;
    if (!ip4_n(i, in, &ip)) return;
    const char *f = i + in;
    if (!strncmp(f, " for ", 5)) f += 5;
    else if (!strncmp(f, " to ", 4)) f += 4;
    else return;
    uint8_t mac[6];
    for (int b = 0; b < 6; b++) {
        if (!isxdigit((unsigned char)f[0]) || !isxdigit((unsigned char)f[1])) return;
        char hx[3] = { f[0], f[1], 0 };
        mac[b] = (uint8_t)strtoul(hx, NULL, 16);
        f += 2;
        if (b < 5) { if (*f != ':') return; f++; }
    }
    char host[32] = "";
    if (*f == ' ') txt(host, sizeof(host), f + 1, tok(f + 1, 31));
    sd_line("dhcp", "", ip, host, "", m);
    mikrotik_note_lease(mac, ip, host);                 // 60-02 once per MAC, shared with the lease poll
}

static bool topic(const char *t, size_t n, const char *w)
{
    size_t wl = strlen(w);
    for (size_t i = 0; i + wl <= n; ) {
        size_t k = i;
        while (k < n && t[k] != ',') k++;
        if (k - i == wl && !strncmp(t + i, w, wl)) return true;
        i = k + 1;
    }
    return false;
}

// The earliest " changed by " / " added by " / " removed by " / " moved by "
// in the first 64 characters: the item names before it are the router's, the
// command after it may quote anything (a comment).
static const char *change_verb(const char *m)
{
    static const char *const V[] = { " changed by ", " added by ", " removed by ", " moved by " };
    const char *best = NULL;
    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        const char *p = strstr(m, V[i]);
        if (p && p - m < 64 && (!best || p < best)) best = p;
    }
    return best;
}

// "<server> assigned ": the first word, then " assigned ".
static const char *dhcp_assigned(const char *m)
{
    size_t n = tok(m, 32);
    return (n && !strncmp(m + n, " assigned ", 10)) ? m + n : NULL;
}

// Classify by the topics when they are there (tripwires.rsc sets
// add-topics-string=yes); by the message's start otherwise. Every pattern is
// anchored at the start of the message or within its first words, which are
// the router's, so text a client chose (a DHCP host name, a user name) cannot
// pass for another kind of line.
static void parse_line(char *s)
{
    char *t;
    size_t tn;
    char *m = split(s, &t, &tn);
    bool has = tn > 0;
    const char *p;
    if (!strncmp(m, "login failure for user ", 23) && (!has || (topic(t, tn, "system") && topic(t, tn, "error"))))
        on_login_fail(m);
    else if (!strncmp(m, "user ", 5) && strstr(m, " logged in") && (!has || topic(t, tn, "account")))
        on_login(m);
    else if (!strncmp(m, "SS-TRIP-", 8) && (!has || topic(t, tn, "firewall")))
        on_firewall(m);
    else if ((p = dhcp_assigned(m)) && (!has || topic(t, tn, "dhcp")))
        on_dhcp(m, p);
    else if ((p = change_verb(m)) && (!has || (topic(t, tn, "system") && !topic(t, tn, "account") &&
                                               !topic(t, tn, "dhcp") && !topic(t, tn, "firewall"))))
        on_change(m, p);
    else ST_INC(c_other);
}

static void drain(void)
{
    for (int k = 0; k < ROUTER_SYSLOG_SLOTS; k++) {
        uint32_t t = s_tail, h = __atomic_load_n(&s_head, __ATOMIC_ACQUIRE);
        if (t == h) return;
        const sl_slot_t *d = &s_ring[t % ROUTER_SYSLOG_SLOTS];
        size_t n = d->len < ROUTER_SYSLOG_SLOT ? d->len : ROUTER_SYSLOG_SLOT;
        for (size_t i = 0; i < n; i++) {
            char c = d->data[i];
            R->line[i] = (c == '\n' || c == '\r' || c == '\t' || c == 0) ? ' ' : c;
        }
        R->line[n] = '\0';
        __atomic_store_n(&s_tail, t + 1, __ATOMIC_RELEASE);
        while (n && R->line[n - 1] == ' ') R->line[--n] = '\0';
        s_last_line_s = up_s();
        ST_INC(parsed);
        parse_line(R->line);
    }
}

// ── Router address and gateway MAC ────────────────────────────────────────────

static void refresh_router(void)
{
    uint32_t ip = 0;
    if (!ip4_n(ROUTER_SYSLOG_SRC, strlen(ROUTER_SYSLOG_SRC), &ip)) ip = mikrotik_watch_router_ip();
    if (ip != s_rip) {
        char b[16] = "none";
        if (ip) ip_s(ip, b, sizeof(b));
        ESP_LOGI(TAG, "Router address for syslog: %s%s", b, ROUTER_SYSLOG_SRC[0] ? " (ROUTER_SYSLOG_SRC)" : "");
    }
    s_rip = ip;
}

static void refresh_gateway(void)
{
    uint32_t gw;
    uint8_t m[6];
    if (!wifi_manager_get_gateway(&gw) || !wifi_manager_lookup_mac(gw, m)) return;
    portENTER_CRITICAL(&s_gw_mux);
    bool changed = !s_gw_ok || memcmp(m, s_gw_mac, 6);
    memcpy(s_gw_mac, m, 6);
    s_gw_ok = true;
    portEXIT_CRITICAL(&s_gw_mux);
    if (changed) {
        char ms[WIFI_MAC_STR_LEN];
        wifi_manager_format_mac(m, ms, sizeof(ms));
        ESP_LOGI(TAG, "Gateway MAC for the router feeds: %s", ms);
    }
}

uint32_t router_trip_router_ip(void) { return s_rip; }

bool router_trip_gateway_mac(uint8_t mac[6])
{
    portENTER_CRITICAL(&s_gw_mux);
    bool ok = s_gw_ok;
    if (ok) memcpy(mac, s_gw_mac, 6);
    portEXIT_CRITICAL(&s_gw_mux);
    return ok;
}

bool router_trip_syslog_live(void)
{
    int64_t t = s_last_line_s;
    return t && up_s() - t < LIVE_S;
}

// ── Task ──────────────────────────────────────────────────────────────────────

void router_trip_task(void *arg)
{
    (void)arg;
    rt_t *r = heap_caps_calloc(1, sizeof(*r), MALLOC_CAP_SPIRAM);
    sl_slot_t *ring = heap_caps_calloc(ROUTER_SYSLOG_SLOTS, sizeof(sl_slot_t), MALLOC_CAP_SPIRAM);
    if (!r || !ring) {
        ESP_LOGE(TAG, "Not started: out of memory");
        free(r); free(ring);
        for (;;) vTaskDelay(portMAX_DELAY);             // a PSRAM-stack task: parked, not deleted
    }
    r->n_admin = router_trip_parse_ips(ROUTER_ADMIN_IPS, r->admin, ROUTER_ADMIN_MAX);
    __atomic_store_n(&R, r, __ATOMIC_RELEASE);
    s_task = xTaskGetCurrentTaskHandle();
    wifi_manager_wait_for_ip();
    refresh_router();
    refresh_gateway();
#if ROUTER_SYSLOG_ENABLE
    __atomic_store_n(&s_ring, ring, __ATOMIC_RELEASE);  // the tap starts copying now
#endif
    router_flow_init();                                 // IPFIX: its ring starts taking datagrams now
    ESP_LOGI(TAG, "Syslog on UDP %d %s: %u B ring and %u B state in PSRAM, no socket, %d admin address%s from ROUTER_ADMIN_IPS",
             ROUTER_SYSLOG_PORT, ROUTER_SYSLOG_ENABLE ? "on" : "off",
             (unsigned)(ROUTER_SYSLOG_SLOTS * sizeof(sl_slot_t)), (unsigned)sizeof(*R), R->n_admin,
             R->n_admin == 1 ? "" : "es");
    int64_t next_rtr = 0, next_gw = 0;
    bool hw = false;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(250));
        int64_t now = up_s();
        if (now >= next_rtr) { next_rtr = now + 10; refresh_router(); }
        if (now >= next_gw) {
            refresh_gateway();
            bool ok;
            portENTER_CRITICAL(&s_gw_mux);
            ok = s_gw_ok;
            portEXIT_CRITICAL(&s_gw_mux);
            next_gw = now + (ok ? 60 : 5);
        }
        if (s_ring) drain();
        router_flow_service();
        if (!hw && s_st_received) {
            hw = true;
            ESP_LOGI(TAG, "First line from the router, stack high-water %u B of %d",
                     (unsigned)uxTaskGetStackHighWaterMark(NULL), ROUTER_TASK_STACK);
        }
    }
}

// ── List check (mikrotik task) ────────────────────────────────────────────────

typedef struct { uint32_t id; uint32_t ip; } le_t;
typedef struct {
    le_t     prev[LIST_MAX], cur[LIST_MAX];
    uint16_t n_prev, n_cur;
    bool     learned;
    int64_t  due;
    attack_log_t ev;
    mikrotik_host_t host;
} list_t;
static list_t *L;

static bool list_cb(void *ctx, const mikrotik_row_t *r)
{
    (void)ctx;
    if (L->n_cur >= LIST_MAX) return false;
    const char *id = mikrotik_row_get(r, ".id");
    const char *a = mikrotik_row_get(r, "address");
    size_t an = strcspn(a, "/");
    uint32_t ip;
    if (!ip4_n(a, an, &ip)) return true;
    uint32_t h = 2166136261u;
    for (const char *s = id; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
    L->cur[L->n_cur].id = h;
    L->cur[L->n_cur].ip = ip;
    L->n_cur++;
    return true;
}

bool router_trip_list_tick(void)
{
#if !ROUTER_SYSLOG_ENABLE
    return false;
#else
    int64_t now = up_s();
    if (!L) {
        L = heap_caps_calloc(1, sizeof(*L), MALLOC_CAP_SPIRAM);
        if (!L) return false;
        L->due = now + 30;
    }
    if (now < L->due) return false;
    L->due = now + ROUTER_LIST_CHECK_S;
    L->n_cur = 0;
    uint32_t rows = 0;
    int st = mikrotik_rest_get("/ip/firewall/address-list?list=" ROUTER_TRIP_LIST
                               "&.proplist=.id,address,creation-time,timeout,dynamic,disabled",
                               list_cb, NULL, LIST_BYTES, &rows);
    // time() takes a newlib lock: calling it inside the critical section aborted
    // the board on 2026-11-04 (lock_acquire_generic, ISR-style take failed), so
    // read the clock before entering it.
    uint32_t now_wall = (uint32_t)time(NULL);
    portENTER_CRITICAL(&s_st_mux);
    s_st.list_checks++;
    s_st.list_status = st;
    s_st.list_last = now_wall;
    if (st != 200 && st != -4) s_st.list_errors++;
    else s_st.list_entries = L->n_cur;
    portEXIT_CRITICAL(&s_st_mux);
    if (st != 200 && st != -4) return true;
    int raised = 0, more = 0;
    uint32_t more_ip = 0;
    for (int i = 0; i < L->n_cur && L->learned; i++) {
        bool old = false;
        for (int k = 0; k < L->n_prev && !old; k++) old = L->prev[k].id == L->cur[i].id;
        if (old || recent_has(L->cur[i].ip)) continue;
        if (raised >= LIST_EVENTS) { more++; more_ip = L->cur[i].ip; continue; }
        raised++;
        attack_log_t *e = &L->ev;
        memset(e, 0, sizeof(*e));
        e->timestamp = (uint32_t)time(NULL);
        e->type = ATTACK_ROUTER;
        e->src_ip = L->cur[i].ip;
        src_mac(e->src_ip, e->src_mac, &L->host);
        char ip[16];
        ip_s(e->src_ip, ip, sizeof(ip));
        // Short for the headline, which names the source already.
        snprintf(e->payload, sizeof(e->payload), "[%s] on the %s list, not in syslog", CODE[K_LIST], ROUTER_TRIP_LIST);
        ESP_LOGW(TAG, "%s: %s", ip, e->payload);
        recent_note(e->src_ip);
        if (mikrotik_watch_post(e)) ST_INC(list_events);
    }
    if (more) {
        attack_log_t *e = &L->ev;
        memset(e, 0, sizeof(*e));
        e->timestamp = (uint32_t)time(NULL);
        e->type = ATTACK_ROUTER;
        e->src_ip = more_ip;
        snprintf(e->payload, sizeof(e->payload), "[%s] %d more new on the %s list",
                 CODE[K_LIST], more, ROUTER_TRIP_LIST);
        if (mikrotik_watch_post(e)) ST_INC(list_events);
    }
    if (!L->learned) ESP_LOGI(TAG, "Tripwire list: %u entries learned", (unsigned)L->n_cur);
    memcpy(L->prev, L->cur, sizeof(L->prev[0]) * L->n_cur);
    L->n_prev = L->n_cur;
    L->learned = true;
    portENTER_CRITICAL(&s_st_mux);
    s_st.list_learned = true;
    portEXIT_CRITICAL(&s_st_mux);
    return true;
#endif
}

// ── Status ────────────────────────────────────────────────────────────────────

void router_trip_get_status(router_trip_status_t *out)
{
    portENTER_CRITICAL(&s_st_mux);
    *out = s_st;
    portEXIT_CRITICAL(&s_st_mux);
    out->enabled = ROUTER_SYSLOG_ENABLE && s_ring;
    out->live = router_trip_syslog_live();
    out->router_ip = s_rip;
    portENTER_CRITICAL(&s_gw_mux);
    out->gw_known = s_gw_ok;
    portEXIT_CRITICAL(&s_gw_mux);
    out->received = s_st_received;
    out->foreign = s_st_foreign;
    out->dropped = s_st_dropped;
    out->cut = s_st_cut;
    int64_t t = s_last_line_s;
    out->last_ts = t ? (uint32_t)(time(NULL) - (up_s() - t)) : 0;
}

size_t router_trip_status_json(char *buf, size_t cap)
{
    router_trip_status_t s;
    router_trip_get_status(&s);
    char rip[16] = "";
    if (s.router_ip) ip_s(s.router_ip, rip, sizeof(rip));
    int n = snprintf(buf, cap,
        "{\"enabled\":%s,\"port\":%d,\"router\":\"%s\",\"gateway_mac_known\":%s,\"live\":%s,\"last\":%lu,"
        "\"received\":%lu,\"foreign\":%lu,\"dropped\":%lu,\"cut\":%lu,\"parsed\":%lu,\"events\":%lu,\"held\":%lu,"
        "\"sd_lines\":%lu,\"sd_dropped\":%lu,\"lines\":{\"login_fail\":%lu,\"login\":%lu,\"change\":%lu,"
        "\"psd\":%lu,\"mgmt\":%lu,\"dns\":%lu,\"dhcp\":%lu,\"other\":%lu},"
        "\"list\":{\"name\":\"%s\",\"learned\":%s,\"checks\":%lu,\"errors\":%lu,\"status\":%d,\"entries\":%lu,"
        "\"events\":%lu,\"last\":%lu}}",
        s.enabled ? "true" : "false", ROUTER_SYSLOG_PORT, rip, s.gw_known ? "true" : "false",
        s.live ? "true" : "false", (unsigned long)s.last_ts, (unsigned long)s.received,
        (unsigned long)s.foreign, (unsigned long)s.dropped, (unsigned long)s.cut, (unsigned long)s.parsed,
        (unsigned long)s.events, (unsigned long)s.held, (unsigned long)s.sd_lines, (unsigned long)s.sd_dropped,
        (unsigned long)s.c_login_fail, (unsigned long)s.c_login, (unsigned long)s.c_change, (unsigned long)s.c_psd,
        (unsigned long)s.c_mgmt, (unsigned long)s.c_dns, (unsigned long)s.c_dhcp, (unsigned long)s.c_other,
        ROUTER_TRIP_LIST, s.list_learned ? "true" : "false", (unsigned long)s.list_checks,
        (unsigned long)s.list_errors, s.list_status, (unsigned long)s.list_entries, (unsigned long)s.list_events,
        (unsigned long)s.list_last);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}
