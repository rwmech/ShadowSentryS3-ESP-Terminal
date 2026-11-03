// Device intelligence: the honeypot's events, the router's view and Pi-hole's
// view of one device, merged, with flags. See correlate.h. Fork addition,
// Robert Mech.
//
// Copies only: the router cache and Pi-hole are read through their getters,
// the flash ring through log_store_get_recent(). Every string that came from
// the router or Pi-hole is cut to printable ASCII before it goes into a
// reason or the summary; the JSON and Discord layers escape again.

#include "correlate.h"
#include "mikrotik.h"
#include "log_store.h"
#include "describe.h"
#include "alarm.h"
#include "discovery.h"
#include "wifi_manager.h"
#include "geoip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "lwip/ip4_addr.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Optional: defined by the Pi-hole client when it is built in, else NULL.
#pragma weak correlate_pihole_device
#pragma weak correlate_pihole_dnslog
#pragma weak correlate_pihole_answers

#define RING_MAX 200        // the flash ring's size (log_store.c)

// External ports that are rarely legitimate from a home device.
static const struct { uint16_t port; const char *what; } ODD_PORTS[] = {
    { 23,    "Telnet" },          { 2323,  "Telnet" },        { 6667, "IRC" },
    { 6697,  "IRC over TLS" },    { 4444,  "Metasploit's default" },
    { 5555,  "ADB" },             { 445,   "SMB" },           { 135,  "MS RPC" },
    { 139,   "NetBIOS" },         { 31337, "Back Orifice" },  { 9001, "Tor relay" },
};

// Public resolvers that answer DNS over HTTPS (443) and TLS (853): a
// connection to one on those ports is a lookup Pi-hole never sees.
static const struct { uint8_t a, b, c, d, bits; const char *who; } RESOLVERS[] = {
    { 8, 8, 8, 8, 32, "Google" },        { 8, 8, 4, 4, 32, "Google" },
    { 1, 1, 1, 1, 32, "Cloudflare" },    { 1, 0, 0, 1, 32, "Cloudflare" },
    { 1, 1, 1, 2, 32, "Cloudflare" },    { 1, 0, 0, 2, 32, "Cloudflare" },
    { 1, 1, 1, 3, 32, "Cloudflare" },    { 1, 0, 0, 3, 32, "Cloudflare" },
    { 9, 9, 9, 9, 32, "Quad9" },         { 149, 112, 112, 112, 32, "Quad9" },
    { 9, 9, 9, 11, 32, "Quad9" },        { 208, 67, 222, 222, 32, "OpenDNS" },
    { 208, 67, 220, 220, 32, "OpenDNS" },{ 94, 140, 14, 14, 32, "AdGuard" },
    { 94, 140, 15, 15, 32, "AdGuard" },  { 185, 228, 168, 9, 32, "CleanBrowsing" },
    { 185, 228, 169, 9, 32, "CleanBrowsing" }, { 76, 76, 2, 0, 24, "Control D" },
    { 76, 76, 10, 0, 24, "Control D" },  { 194, 242, 2, 2, 32, "Mullvad" },
    { 45, 90, 28, 0, 24, "NextDNS" },    { 45, 90, 30, 0, 24, "NextDNS" },
};

static const char *resolver(uint32_t ip)
{
    const uint8_t *q = (const uint8_t *)&ip;
    for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
        const uint8_t r[4] = { RESOLVERS[i].a, RESOLVERS[i].b, RESOLVERS[i].c, RESOLVERS[i].d };
        int whole = RESOLVERS[i].bits / 8;
        if (!memcmp(q, r, (size_t)whole)) return RESOLVERS[i].who;
    }
    return NULL;
}

const char *correlate_flag_key(int bit)
{
    static const char *const K[] = { "dns_bypass", "doh", "unusual_port", "beaconing", "upload", "direct_ip",
                                     "blocked_contact", "no_lookup" };
    _Static_assert(sizeof(K) / sizeof(K[0]) == CORRELATE_F_BITS, "a key per flag bit");
    return bit >= 0 && bit < CORRELATE_F_BITS ? K[bit] : "";
}

const char *correlate_lookup_key(uint8_t lk)
{
    static const char *const K[] = { "", "self", "other", "unseen", "before", "wait" };
    return lk < sizeof(K) / sizeof(K[0]) ? K[lk] : "";
}

static void mb(uint64_t n, char *b, size_t len)
{
    if (n >= 1048576ull) snprintf(b, len, "%.1f MB", (double)n / 1048576.0);
    else snprintf(b, len, "%lu KB", (unsigned long)((n + 1023) / 1024));
}

static void ip_s(uint32_t ip, char *b, size_t n)
{
    ip4_addr_t a = { .addr = ip };
    ip4addr_ntoa_r(&a, b, (int)n);
}

static void txt(char *dst, size_t cap, const char *src)
{
    size_t o = 0;
    for (; src && *src && o + 1 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c >= 0x20 && c <= 0x7e && c != '"' && c != '`') dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

static void flag(correlate_t *c, const char *key, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void flag(correlate_t *c, const char *key, const char *fmt, ...)
{
    if (c->n_flags >= CORRELATE_FLAGS_MAX) return;
    correlate_flag_t *f = &c->flags[c->n_flags++];
    strlcpy(f->key, key, sizeof(f->key));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->reason, sizeof(f->reason), fmt, ap);
    va_end(ap);
}

static const char *proto_s(uint8_t p) { return p == 6 ? "tcp" : p == 17 ? "udp" : p == 1 ? "icmp" : "ip"; }

// ── Honeypot events ───────────────────────────────────────────────────────────

static void hp_count(correlate_t *c, const char *code)
{
    for (int i = 0; i < c->hp_n; i++)
        if (!strcmp(c->hp[i].code, code)) { if (c->hp[i].n < 65535) c->hp[i].n++; return; }
    if (c->hp_n >= CORRELATE_CODES_MAX) return;
    strlcpy(c->hp[c->hp_n].code, code, sizeof(c->hp[0].code));
    c->hp[c->hp_n++].n = 1;
}

static void events(correlate_t *c)
{
    attack_log_t *ring = heap_caps_malloc(RING_MAX * sizeof(*ring), MALLOC_CAP_SPIRAM);
    if (ring) {
        int n = log_store_get_recent(ring, RING_MAX);
        for (int i = 0; i < n; i++) {
            const attack_log_t *e = &ring[i];
            bool hit = (c->ip && e->src_ip == c->ip) || (c->mac_known && !memcmp(e->src_mac, c->mac, 6));
            if (!hit) continue;
            c->hp_events++;
            if (e->timestamp > c->hp_last) c->hp_last = e->timestamp;
            hp_count(c, describe_code(e));
        }
        free(ring);
    }
    // The open incident's codes (discovery and new-device events are not in the ring).
    alarm_info_t a;
    alarm_get(&a);
    bool same = a.state != ALARM_IDLE && ((c->ip && a.src_ip == c->ip) || (c->mac_known && !memcmp(a.src_mac, c->mac, 6)));
    int n_codes = describe_code_count();
    for (int i = 0; same && i < n_codes && i < DESCRIBE_CODE_BITS; i++) {
        if (!(a.codes & (1ull << i))) continue;
        const char *code = describe_code_at(i, NULL, NULL);
        bool have = false;
        for (int k = 0; code && k < c->hp_n && !have; k++) have = !strcmp(c->hp[k].code, code);
        if (code && !have) hp_count(c, code);
    }
}

// ── Flags ─────────────────────────────────────────────────────────────────────

static bool dns_has_ip(const correlate_dns_t *d, uint32_t ip, bool blocked, const char **domain)
{
    for (int i = 0; i < d->n; i++) {
        if (d->q[i].blocked != blocked) continue;
        for (int k = 0; k < 2; k++)
            if (d->q[i].ip[k] && d->q[i].ip[k] == ip) { if (domain) *domain = d->q[i].domain; return true; }
    }
    return false;
}

static bool dns_any_ips(const correlate_dns_t *d)
{
    for (int i = 0; i < d->n; i++) if (d->q[i].ip[0]) return true;
    return false;
}

static void flags(correlate_t *c)
{
    const mikrotik_conn_t *k = &c->conn;
    char ip[16], dom[48];
    bool bypass = false;

    // DNS straight to a server that is not the Pi-hole (an outside one when
    // there is no Pi-hole data). Known public resolvers are the doh flag.
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        if (!(d->port == 53 || (d->port == 853 && d->proto == 6))) continue;
        if (c->dns_on ? (d->ip == c->dns.server_ip || (!d->external && !c->dns.server_ip)) : !d->external) continue;
        if (d->port == 853 && resolver(d->ip)) continue;
        c->dflags[i] |= CORRELATE_F_DNS;
        if (bypass) continue;
        ip_s(d->ip, ip, sizeof(ip));
        flag(c, "dns_bypass", "sends DNS%s straight to %s:%u, %s", d->port == 853 ? " over TLS" : "", ip,
             (unsigned)d->port, c->dns_on ? "not through Pi-hole" : "an outside server");
        bypass = true;
    }
    // DNS over HTTPS or TLS to a known resolver.
    bool doh = false;
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        const char *who = (d->port == 443 || d->port == 853) ? resolver(d->ip) : NULL;
        if (!who) continue;
        c->dflags[i] |= CORRELATE_F_DOH;
        bypass = true;
        if (doh) continue;
        ip_s(d->ip, ip, sizeof(ip));
        flag(c, "doh", "DNS over %s to %s (%s:%u): lookups Pi-hole never sees", d->port == 853 ? "TLS" : "HTTPS",
             who, ip, (unsigned)d->port);
        doh = true;
    }
    if (c->dns_on) {
        if (!bypass && k->external >= 3 && c->dns.total == 0 && c->dns.window_s) {
            flag(c, "dns_bypass", "%u external connections but no lookups through Pi-hole in the last %lu min",
                 (unsigned)k->external, (unsigned long)(c->dns.window_s / 60));
            bypass = true;
        }
        // Blocked names.
        bool hit = false;
        for (int i = 0; i < k->n_dst && !hit; i++) {
            const char *d = NULL;
            if (!k->dst[i].external || !dns_has_ip(&c->dns, k->dst[i].ip, true, &d)) continue;
            c->dflags[i] |= CORRELATE_F_BLOCKED;
            ip_s(k->dst[i].ip, ip, sizeof(ip));
            txt(dom, sizeof(dom), d);
            flag(c, "blocked_contact", "connected to %s, an address of %s, which Pi-hole blocks", ip, dom);
            hit = true;
        }
        if (!hit && bypass && c->dns.blocked) {
            const char *d = "";
            for (int i = 0; i < c->dns.n && !d[0]; i++) if (c->dns.q[i].blocked) d = c->dns.q[i].domain;
            txt(dom, sizeof(dom), d);
            flag(c, "blocked_contact", "Pi-hole blocked %u lookups%s%s%s, and it uses other DNS, so it may reach them anyway",
                 (unsigned)c->dns.blocked, dom[0] ? " (" : "", dom, dom[0] ? ")" : "");
        }
    }

    // Beacons (worked out in mikrotik.c from repeated fetches).
    int nb = 0;
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        if (!d->beacon_n || !d->external) continue;
        c->dflags[i] |= CORRELATE_F_BEACON;
        if (nb >= 2) continue;
        ip_s(d->ip, ip, sizeof(ip));
        flag(c, "beaconing", "new %s connections to %s:%u about every %lu s (%u times), little data each: a check-in or beacon",
             proto_s(d->proto), ip, (unsigned)d->port, (unsigned long)d->beacon_s, (unsigned)d->beacon_n);
        nb++;
    }

    // Unusual ports out.
    char list[80] = "";
    int nu = 0;
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        if (!d->external) continue;
        for (size_t p = 0; p < sizeof(ODD_PORTS) / sizeof(ODD_PORTS[0]); p++) {
            if (ODD_PORTS[p].port != d->port) continue;
            c->dflags[i] |= CORRELATE_F_PORT;
            if (nu < 3) {
                char one[64];
                ip_s(d->ip, ip, sizeof(ip));
                snprintf(one, sizeof(one), "%s%s:%u (%s)", nu ? ", " : "", ip, (unsigned)d->port, ODD_PORTS[p].what);
                strlcat(list, one, sizeof(list));
            }
            nu++;
        }
    }
    if (nu) flag(c, "unusual_port", "outbound to %s%s", list, nu > 3 ? " and more" : "");

    // Upload-heavy.
    bool up = false;
    for (int i = 0; i < k->n_dst; i++) {
        const mikrotik_dst_t *d = &k->dst[i];
        if (!d->external || d->bytes_out < CORRELATE_UPLOAD_MIN || d->bytes_out < 4 * d->bytes_in) continue;
        c->dflags[i] |= CORRELATE_F_UPLOAD;
        if (up) continue;
        char sent[16];
        mb(d->bytes_out, sent, sizeof(sent));
        ip_s(d->ip, ip, sizeof(ip));
        unsigned long x = d->bytes_in ? (unsigned long)(d->bytes_out / d->bytes_in) : 0;
        if (x) flag(c, "upload", "sent %s to %s:%u, %lux what came back", sent, ip, (unsigned)d->port, x);
        else   flag(c, "upload", "sent %s to %s:%u, nothing came back", sent, ip, (unsigned)d->port);
        up = true;
    }

    // Direct-IP: only when a name source covers this device.
    bool covered = c->dns_on && dns_any_ips(&c->dns);
    for (int i = 0; i < k->n_dst && !covered; i++) covered = k->dst[i].name_src == MIKROTIK_NAME_ROUTER_DNS;
    if (covered && !c->dnslog.readable) {
        char dl[72] = "";
        int nd = 0;
        for (int i = 0; i < k->n_dst; i++) {
            const mikrotik_dst_t *d = &k->dst[i];
            if (!d->external || d->name[0] || d->port == 53 || d->port == 853 || (c->dflags[i] & CORRELATE_F_DOH)) continue;
            if (d->bytes_out + d->bytes_in < 4096 || (d->proto != 6 && d->proto != 17)) continue;
            c->dflags[i] |= CORRELATE_F_DIRECT;
            if (nd < 3) {
                char one[28];
                ip_s(d->ip, ip, sizeof(ip));
                snprintf(one, sizeof(one), "%s%s:%u", nd ? ", " : "", ip, (unsigned)d->port);
                strlcat(dl, one, sizeof(dl));
            }
            nd++;
        }
        if (nd) flag(c, "direct_ip", "%d external host%s with no DNS lookup behind %s: %s%s", nd, nd == 1 ? "" : "s",
                     nd == 1 ? "it" : "them", dl, nd > 3 ? " and more" : "");
    }

    // No lookup seen: Pi-hole's log covered the time, and nobody looked the
    // address up through it (the verdicts are set in lookups()).
    if (c->dnslog.usable) {
        char dl[72] = "";
        int nn = 0;
        for (int i = 0; i < k->n_dst; i++) {
            if (c->lk[i].lk != CORRELATE_LK_UNSEEN) continue;
            c->dflags[i] |= CORRELATE_F_NOLOOKUP;
            if (nn < 3) {
                char one[28];
                ip_s(k->dst[i].ip, ip, sizeof(ip));
                snprintf(one, sizeof(one), "%s%s:%u", nn ? ", " : "", ip, (unsigned)k->dst[i].port);
                strlcat(dl, one, sizeof(dl));
            }
            nn++;
        }
        uint32_t now = (uint32_t)time(NULL), min = c->dnslog.cover_from && now > c->dnslog.cover_from
                       ? (now - c->dnslog.cover_from) / 60 : 0;
        if (nn) flag(c, "no_lookup", "%d internet host%s nobody looked up through Pi-hole in its log's last %lu min: %s%s",
                     nn, nn == 1 ? "" : "s", (unsigned long)min, dl, nn > 3 ? " and more" : "");
    }

    // Fan-out.
    if (k->ext_hosts >= CORRELATE_FANOUT)
        flag(c, "fanout", "talking to %u distinct external hosts at once%s", (unsigned)k->ext_hosts,
             k->truncated ? " (more not read)" : "");
}

const char *correlate_src_key(uint8_t src)
{
    return src == CORRELATE_SRC_BOTH ? "both" : src == CORRELATE_SRC_IPFIX ? "ipfix" : "conntrack";
}

// The IPFIX destinations into conn.dst[]: a row conntrack has too is marked
// both; the rest are appended, busiest first, while there is room. Names
// from the router's DNS cache for the new rows.
static void merge_flows(correlate_t *c)
{
    mikrotik_conn_t *k = &c->conn;
    for (int i = 0; i < MIKROTIK_DST_MAX; i++) { c->fidx[i] = -1; c->dsrc[i] = CORRELATE_SRC_CONNTRACK; }
    if (!c->ip) return;
    c->flow_found = router_flow_device(c->ip, &c->flow);
    if (!c->flow_found) return;
    for (int f = 0; f < c->flow.n; f++) {
        const router_flow_dst_t *x = &c->flow.d[f];
        int i;
        for (i = 0; i < k->n_dst; i++)
            if (k->dst[i].ip == x->ip && k->dst[i].port == x->port && k->dst[i].proto == x->proto) break;
        if (i < k->n_dst) {
            if (c->fidx[i] < 0) { c->fidx[i] = (int8_t)f; c->dsrc[i] = CORRELATE_SRC_BOTH; }
            continue;
        }
        if (k->n_dst >= MIKROTIK_DST_MAX) { c->flow_cut = true; continue; }
        mikrotik_dst_t *d = &k->dst[k->n_dst];
        memset(d, 0, sizeof(*d));
        d->ip = x->ip;
        d->port = x->port;
        d->proto = x->proto;
        d->external = x->external;
        d->bytes_out = x->bytes_out;
        d->bytes_in = x->bytes_in;
        d->pkts_out = x->pkts_out;
        d->pkts_in = x->pkts_in;
        d->first_seen = x->first;
        d->last_seen = x->last;
        if (d->external && mikrotik_dns_name(d->ip, d->name, sizeof(d->name))) d->name_src = MIKROTIK_NAME_ROUTER_DNS;
        c->fidx[k->n_dst] = (int8_t)f;
        c->dsrc[k->n_dst] = CORRELATE_SRC_IPFIX;
        k->n_dst++;
    }
}

static void summarise(correlate_t *c)
{
    char s[CORRELATE_SUMMARY_LEN] = "", host[24];
    const mikrotik_host_t *h = &c->host;
    if (c->host_found) {
        txt(host, sizeof(host), h->hostname);
        const char *where = h->port[0] ? h->port : h->wifi_if[0] ? h->wifi_if : h->arp_if;
        char w[32];
        txt(w, sizeof(w), where);
        if (host[0] && w[0]) snprintf(s, sizeof(s), "%s on %s", host, w);
        else if (w[0])      snprintf(s, sizeof(s), "on %s", w);
        else if (host[0])   snprintf(s, sizeof(s), "%s", host);
        if (h->signal && (h->src & MIKROTIK_SRC_WIFI)) {
            char sig[16];
            snprintf(sig, sizeof(sig), " %d dBm", (int)h->signal);
            strlcat(s, sig, sizeof(s));
        }
    }
    if (c->conn_found && c->conn.state == MIKROTIK_CONN_OK) {
        char t[48];
        snprintf(t, sizeof(t), "%s%u external connection%s", s[0] ? ", " : "", (unsigned)c->conn.external,
                 c->conn.external == 1 ? "" : "s");
        strlcat(s, t, sizeof(s));
    } else if (c->flow_found) {
        unsigned ext = 0;
        for (int i = 0; i < c->flow.n; i++) ext += c->flow.d[i].external;
        char t[48];
        snprintf(t, sizeof(t), "%s%u external destination%s (IPFIX)", s[0] ? ", " : "", ext, ext == 1 ? "" : "s");
        strlcat(s, t, sizeof(s));
    }
    if (c->n_flags && s[0]) {
        char t[24];
        snprintf(t, sizeof(t), ", %u flagged", (unsigned)c->n_flags);
        strlcat(s, t, sizeof(s));
    }
    strlcpy(c->summary, s, sizeof(c->summary));
}

// ── Pi-hole's DNS log: who looked each destination up ─────────────────────────

// A destination a lookup should stand behind: internet, TCP or UDP, not DNS
// itself and not a known public resolver on 443 or 853 (the doh flag).
static bool wants_lookup(const correlate_t *c, const mikrotik_dst_t *d)
{
    if (!d->external || (d->proto != 6 && d->proto != 17)) return false;
    if (d->port == 53 || d->port == 853) return false;
    if (d->port == 443 && resolver(d->ip)) return false;
    return !(c->dns_on && c->dns.server_ip && d->ip == c->dns.server_ip);
}

static void lookups(correlate_t *c)
{
    if (!c->dnslog.readable || !correlate_pihole_answers || !c->ip) return;
    mikrotik_conn_t *k = &c->conn;
    uint32_t ips[MIKROTIK_DST_MAX];
    int8_t at[MIKROTIK_DST_MAX];
    int n = 0;
    for (int i = 0; i < k->n_dst; i++) if (wants_lookup(c, &k->dst[i])) { at[n] = (int8_t)i; ips[n++] = k->dst[i].ip; }
    if (!n) return;
    correlate_answer_t *a = heap_caps_calloc((size_t)n, sizeof(*a), MALLOC_CAP_SPIRAM);
    if (!a) return;
    correlate_pihole_answers(c->ip, c->dns_on ? &c->dns : NULL, ips, n, a);
    for (int j = 0; j < n; j++) {
        int i = at[j];
        mikrotik_dst_t *d = &k->dst[i];
        if (a[j].found) {
            c->lk[i].lk = a[j].self ? CORRELATE_LK_SELF : CORRELATE_LK_OTHER;
            c->lk[i].when = a[j].last;
            c->lk[i].by = a[j].self ? 0 : a[j].by;
            txt(c->lk[i].name, sizeof(c->lk[i].name), a[j].name);
            if (c->lk[i].name[0]) {
                strlcpy(d->name, c->lk[i].name, sizeof(d->name));
                d->name_src = MIKROTIK_NAME_PIHOLE;
            }
            if (c->lk[i].by) discovery_label_for(c->lk[i].by, NULL, c->lk[i].by_label, sizeof(c->lk[i].by_label));
        } else if (!c->dnslog.usable) {
            c->lk[i].lk = CORRELATE_LK_WAIT;
        } else if (d->first_seen && c->dnslog.cover_from && d->first_seen < c->dnslog.cover_from) {
            c->lk[i].lk = CORRELATE_LK_BEFORE;
        } else {
            c->lk[i].lk = CORRELATE_LK_UNSEEN;
        }
    }
    free(a);
}

// ── Build ─────────────────────────────────────────────────────────────────────

void correlate_build(uint32_t ip, const uint8_t *mac, bool fetch, bool with_events, correlate_t *c)
{
    static const uint8_t zero[6] = { 0 };
    memset(c, 0, sizeof(*c));
    c->ip = ip;
    if (mac && memcmp(mac, zero, 6)) { memcpy(c->mac, mac, 6); c->mac_known = true; }

    mikrotik_status_t st;
    mikrotik_get_status(&st);
    c->mt_state = st.state;
    if (c->mt_state != MIKROTIK_ST_OFF) {
        c->host_found = mikrotik_host(c->mac_known ? c->mac : NULL, ip, &c->host, &c->host_as_of);
        if (!c->host_found && c->mac_known && ip) c->host_found = mikrotik_host(NULL, ip, &c->host, &c->host_as_of);
        if (c->host_found) {
            if (!c->ip) c->ip = c->host.ip;
            if (!c->mac_known) { memcpy(c->mac, c->host.mac, 6); c->mac_known = true; }
        }
        if (fetch && c->ip) mikrotik_conn_request(c->ip, c->mac_known ? c->mac : NULL);
        if (c->ip) c->conn_found = mikrotik_conn_get(c->ip, &c->conn);
    }
    if (!c->mac_known && c->ip && wifi_manager_lookup_mac(c->ip, c->mac) && memcmp(c->mac, zero, 6)) c->mac_known = true;

    // IPFIX: destinations the conntrack snapshot missed (short flows).
    merge_flows(c);
    if (c->flow_found && c->conn.n_dst) {
        c->conn_found = true;           // names, GeoIP and flags below cover the IPFIX rows too
        if (!c->conn.ip) c->conn.ip = c->ip;
    }

    if (correlate_pihole_device && c->ip)
        c->dns_on = correlate_pihole_device(c->ip, c->mac_known ? c->mac : NULL, &c->dns);

    if (correlate_pihole_dnslog) correlate_pihole_dnslog(&c->dnslog);
    if (c->conn_found) lookups(c);
    if (c->conn_found) {
        int asked = 0;
        for (int i = 0; i < c->conn.n_dst; i++) {
            mikrotik_dst_t *d = &c->conn.dst[i];
            const char *dom = NULL;
            if (c->dns_on && dns_has_ip(&c->dns, d->ip, false, &dom) && dom) {
                txt(d->name, sizeof(d->name), dom);
                d->name_src = MIKROTIK_NAME_PIHOLE;
            }
            if (!d->external) continue;
            geoip_info_t g;
            if (geoip_lookup(d->ip, &g)) {
                txt(c->geo[i].cc, sizeof(c->geo[i].cc), g.cc);
                txt(c->geo[i].asn, sizeof(c->geo[i].asn), g.asn);
                txt(c->geo[i].org, sizeof(c->geo[i].org), g.org);
            } else if (fetch && asked < CORRELATE_GEO_LOOKUPS) {
                geoip_enqueue(d->ip);       // answered on a later call
                asked++;
            }
        }
    }
    if (with_events) {
        events(c);
        discovery_label_for(c->ip, c->mac_known ? c->mac : NULL, c->label, sizeof(c->label));
    }
    if (c->conn_found) flags(c);
    summarise(c);
}

size_t correlate_summary(uint32_t ip, const uint8_t *mac, char *buf, size_t len)
{
    if (!len) return 0;
    buf[0] = '\0';
    if (!ip && !mac) return 0;
    if (!mikrotik_running() && !correlate_pihole_device) return 0;
    correlate_t *c = heap_caps_malloc(sizeof(*c), MALLOC_CAP_SPIRAM);
    if (!c) return 0;
    correlate_build(ip, mac, false, false, c);
    size_t n = strlcpy(buf, c->summary, len);
    free(c);
    return n < len ? n : len - 1;
}

size_t correlate_incident_summary(uint32_t ip, const uint8_t *mac, char *buf, size_t len, int wait_ms)
{
    if (mikrotik_running() && ip) {
        uint32_t t0 = (uint32_t)time(NULL);
        bool asked = mikrotik_conn_request(ip, mac);
        mikrotik_conn_t *k = heap_caps_malloc(sizeof(*k), MALLOC_CAP_SPIRAM);
        for (int w = 0; k && w < wait_ms; w += 250) {
            bool have = mikrotik_conn_get(ip, k);
            if (!k->pending && (!asked || (have && k->as_of >= t0))) break;
            vTaskDelay(pdMS_TO_TICKS(250));
        }
        free(k);
    }
    return correlate_summary(ip, mac, buf, len);
}
