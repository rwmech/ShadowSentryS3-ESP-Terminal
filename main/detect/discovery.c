// LAN discovery listeners and the seen-devices table. See discovery.h.
//
// Every datagram is hostile: every length and offset is checked against the
// received size before it is read, every string is cut to printable ASCII on
// the way in and JSON-escaped on the way out. Nothing is ever sent on these
// sockets.

#include "discovery.h"
#include "log_store.h"
#include "sd_log.h"
#include "telegram.h"
#include "discord.h"
#include "alarm.h"
#include "oui.h"
#include "wifi_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static const char *TAG = "DISCO";

#define MACQ_DEPTH      32
#define MACMAP_N        32
#define KV_MAX          6
#define KV_VAL          96
#define RETRY_S         60          // a listener that failed to open is tried again
#define PER_SOCK_READS  8           // datagrams per socket per select() round
#define SD_LINE_MAX     1024
#define CLOCK_VALID     1700000000u

// ── Protocols and listeners ───────────────────────────────────────────────────

enum { DP_SSDP_SEARCH, DP_SSDP_NOTIFY, DP_WSD, DP_LLMNR, DP_NBNS, DP_KASA, DP_LIFX, DP_PS, DP_DHCP, DP_MDNS, DP_COUNT };
static const char *const DP_KEY[DP_COUNT] = {
    "ssdp-search", "ssdp-notify", "wsd", "llmnr", "nbns", "kasa", "lifx", "playstation", "dhcp", "mdns",
};
_Static_assert(DP_COUNT <= 16, "protos is a uint16_t bitmap");

enum { L_SSDP, L_WSD, L_LLMNR, L_NBNS, L_KASA, L_KASA2, L_LIFX, L_PS, L_PS2, L_DHCP, L_N };
typedef struct { uint16_t port; uint8_t group[4]; const char *name; } lsn_t;
static const lsn_t LSN[L_N] = {
    [L_SSDP]  = { 1900,  { 239, 255, 255, 250 }, "SSDP" },
    [L_WSD]   = { 3702,  { 239, 255, 255, 250 }, "WS-Discovery" },
    [L_LLMNR] = { 5355,  { 224, 0, 0, 252 },     "LLMNR" },
    [L_NBNS]  = { 137,   { 0 },                  "NBNS" },
    [L_KASA]  = { 9999,  { 0 },                  "Kasa" },
    [L_KASA2] = { 20002, { 0 },                  "Kasa" },
    [L_LIFX]  = { 56700, { 0 },                  "LIFX" },
    [L_PS]    = { 987,   { 0 },                  "PlayStation" },
    [L_PS2]   = { 9302,  { 0 },                  "PlayStation" },
    [L_DHCP]  = { 67,    { 0 },                  "DHCP" },
};

static inline bool disc_port(uint16_t p)
{
    switch (p) {
    case 1900: case 3702: case 5355: case 137: case 9999: case 20002:
    case 56700: case 987: case 9302:
        return true;
    case 67:
        return DISCOVERY_DHCP;
    default:
        return false;
    }
}

// ── State (PSRAM, the task's; dev[] shared with the JSON route under s_mux) ───

typedef struct {
    bool     used, mac_known;
    uint8_t  mac[6];
    uint32_t ip;                        // network order, 0 = unknown
    uint32_t first_ts, last_ts;         // epoch, 0 before SNTP
    uint32_t first_up, last_up;         // uptime, s
    uint16_t protos;                    // bit per DP_*
    uint8_t  label_score;
    uint8_t  q_head, q_n;
    uint32_t count[DP_COUNT];
    uint32_t total;
    char     label[DISCOVERY_LABEL_LEN];
    char     label_src[12];
    char     host[DISCOVERY_HOST_LEN];
    char     q[DISCOVERY_QUERY_KEEP][DISCOVERY_QUERY_LEN];
    char     vendor[OUI_NAME_MAX];      // database or compact table, "" unknown
    // Since the last digest: anything new (device, protocol, label, query),
    // whether the device itself is new, and what it did in plain words.
    bool     dirty, fresh;
    uint8_t  act_n, act_more;
    char     act[DISCOVERY_ACT_KEEP][DISCOVERY_ACT_LEN];
} disc_dev_t;

typedef struct { uint32_t ip; uint8_t mac[6]; uint8_t _pad[2]; } mac_msg_t;
typedef struct { uint32_t ip; uint8_t mac[6]; uint32_t up; } mac_ent_t;

// One parsed datagram.
typedef struct {
    uint8_t  proto;
    uint32_t ip;
    uint8_t  mac[6];
    bool     mac_known;
    char     query[DISCOVERY_QUERY_LEN];
    char     ua[96];                    // SSDP USER-AGENT or SERVER: a label source
    char     host[DISCOVERY_HOST_LEN];  // DHCP option 12 or a NetBIOS registration
    const char *host_src;
    char     vclass[48];                // DHCP option 60
    char     vendor[OUI_NAME_MAX];      // of mac, looked up before the table lock
    char     phrase[DISCOVERY_ACT_LEN]; // what it did, in plain words
    uint8_t  nkv;
    const char *k[KV_MAX];
    char     v[KV_MAX][KV_VAL];
} obs_t;

typedef struct {
    disc_dev_t   dev[DISCOVERY_DEV_MAX];
    disc_dev_t   snap;                  // observe()'s copy, logged outside the lock
    char         dline[256];            // digest(), one line before it is shortened
    mac_ent_t    macmap[MACMAP_N];
    obs_t        obs;
    attack_log_t ev;
    uint8_t      rx[DISCOVERY_RX_MAX + 1];
} state_t;

static state_t          *S;
static QueueHandle_t     s_macq;
static SemaphoreHandle_t s_mux;
static uint8_t           s_my_mac[6];

static int      s_sock[L_N];
static int      s_err[L_N];             // errno of the last failure, 0 = open
static char     s_stage[L_N];           // 'b' bind, 'j' join, 's' socket
static uint32_t s_pkts[L_N];
static volatile uint32_t s_macq_drop;

// mDNS query ring: single producer (the frame tap, Wi-Fi RX task), single
// consumer (the discovery task). The producer fills slot head % N and then
// publishes head; the consumer copies slot tail % N out and then publishes
// tail. Full: the query is dropped and counted.
typedef struct {
    uint32_t ip;                        // source, network order
    uint8_t  mac[6];
    uint8_t  mcast;                     // sent to 224.0.0.251 (else unicast to us)
    uint8_t  _pad;
    uint16_t len;                       // bytes of UDP payload kept
    uint8_t  data[DISCOVERY_MDNS_COPY];
} mdns_slot_t;
static mdns_slot_t      *s_mring;       // DISCOVERY_MDNS_SLOTS, PSRAM
static uint32_t          s_mhead, s_mtail;
static volatile uint32_t s_mdns_q, s_mdns_drop;
static uint32_t s_ev_held, s_sd_drop, s_stack_low = UINT32_MAX;

typedef struct { int32_t tokens; int64_t last_ms; } bucket_t;
static bucket_t s_ev_bucket, s_sd_bucket;

static inline uint16_t rd16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }
static inline uint32_t up_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000LL); }
static inline int64_t  now_ms(void) { return esp_timer_get_time() / 1000LL; }
static inline char     pr(uint8_t c) { return (c >= 0x20 && c < 0x7f) ? (char)c : '.'; }

static bool take(bucket_t *b, int32_t burst, int64_t refill_ms)
{
    int64_t now = now_ms();
    if (!b->last_ms) { b->tokens = burst; b->last_ms = now; }
    int64_t add = (now - b->last_ms) / refill_ms;
    if (add > 0) {
        b->tokens = (int32_t)((b->tokens + add > burst) ? burst : b->tokens + add);
        b->last_ms = b->tokens >= burst ? now : b->last_ms + add * refill_ms;
    }
    if (b->tokens > 0) { b->tokens--; return true; }
    return false;
}

// ── Frame tap (Wi-Fi RX task) ─────────────────────────────────────────────────

// mDNS: a query (QR=0, standard opcode) to 224.0.0.251:5353 or to us. Bounded
// copy of the UDP payload into the ring, no allocation; full ring = dropped.
static void mdns_copy(const uint8_t *f, size_t len, const uint8_t *ip, unsigned hl, uint32_t our_ip)
{
    static const uint8_t GROUP[4] = { 224, 0, 0, 251 };
    bool mcast = !memcmp(ip + 16, GROUP, 4);
    if (!mcast && (!our_ip || memcmp(ip + 16, &our_ip, 4))) return;
    size_t tot = rd16(ip + 2), ulen = rd16(ip + hl + 4);
    if (tot < hl + 8 || 14 + tot > len || ulen < 8 + 12 || ulen > tot - hl) return;
    const uint8_t *dns = ip + hl + 8;
    if ((dns[2] & 0x80) || (dns[2] & 0x78)) return;                 // responses, other opcodes
    uint32_t h = s_mhead, t = __atomic_load_n(&s_mtail, __ATOMIC_ACQUIRE);
    if (h - t >= DISCOVERY_MDNS_SLOTS) { s_mdns_drop++; return; }
    mdns_slot_t *sl = &s_mring[h % DISCOVERY_MDNS_SLOTS];
    size_t n = ulen - 8;
    if (n > DISCOVERY_MDNS_COPY) n = DISCOVERY_MDNS_COPY;
    memcpy(&sl->ip, ip + 12, 4);
    memcpy(sl->mac, f + 6, 6);
    sl->mcast = mcast;
    sl->len = (uint16_t)n;
    memcpy(sl->data, dns, n);
    __atomic_store_n(&s_mhead, h + 1, __ATOMIC_RELEASE);
    s_mdns_q++;
}

void discovery_frame_tap(const uint8_t *f, size_t len, uint32_t our_ip)
{
    if (!s_macq || !f || len < 14 + 20 + 8) return;
    if (f[12] != 0x08 || f[13] != 0x00 || (f[6] & 0x01)) return;   // IPv4, unicast source MAC
    const uint8_t *ip = f + 14;
    unsigned hl = (ip[0] & 0x0fu) * 4u;
    if ((ip[0] >> 4) != 4 || hl < 20 || 14 + hl + 8 > len || ip[9] != 17) return;
    if (rd16(ip + 6) & 0x1fff) return;                              // later fragment
    uint16_t dport = rd16(ip + hl + 2);
    if (dport == 5353) { if (s_mring) mdns_copy(f, len, ip, hl, our_ip); return; }
    if (!disc_port(dport)) return;
    mac_msg_t m;
    memcpy(&m.ip, ip + 12, 4);
    if (!m.ip) return;                                              // DHCP: chaddr instead
    memcpy(m.mac, f + 6, 6);
    if (xQueueSend(s_macq, &m, 0) != pdTRUE) s_macq_drop++;
}

static void macmap_drain(void)
{
    mac_msg_t m;
    uint32_t now = up_s();
    while (xQueueReceive(s_macq, &m, 0) == pdTRUE) {
        mac_ent_t *hit = NULL, *old = &S->macmap[0];
        for (int i = 0; i < MACMAP_N; i++) {
            mac_ent_t *e = &S->macmap[i];
            if (e->ip == m.ip) { hit = e; break; }
            if (e->up < old->up) old = e;
        }
        if (!hit) hit = old;
        hit->ip = m.ip;
        memcpy(hit->mac, m.mac, 6);
        hit->up = now ? now : 1;
    }
}

static bool mac_for(uint32_t ip, uint8_t mac[6])
{
    for (int i = 0; i < MACMAP_N; i++)
        if (S->macmap[i].up && S->macmap[i].ip == ip) { memcpy(mac, S->macmap[i].mac, 6); return true; }
    uint8_t b0 = (uint8_t)(ip & 0xff);
    if (!ip || ip == 0xFFFFFFFFu || b0 == 127 || b0 >= 224) return false;
    return wifi_manager_lookup_mac(ip, mac);    // ARP cache, on the tcpip task
}

// ── Bounded helpers ───────────────────────────────────────────────────────────

// Copy n bytes as printable ASCII, leading and trailing blanks dropped.
static void clean(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    size_t o = 0, i = 0;
    if (!cap) return;
    while (i < n && (src[i] == ' ' || src[i] == '\t')) i++;
    for (; i < n && o + 1 < cap; i++) dst[o++] = pr(src[i]);
    while (o && dst[o - 1] == ' ') o--;
    dst[o] = '\0';
}

static void kv(obs_t *o, const char *key, const uint8_t *val, size_t n)
{
    if (o->nkv >= KV_MAX) return;
    o->k[o->nkv] = key;
    clean(o->v[o->nkv], KV_VAL, val, n);
    o->nkv++;
}

static void kv_str(obs_t *o, const char *key, const char *val)
{
    kv(o, key, (const uint8_t *)val, strlen(val));
}

static void hex(char *dst, size_t cap, const uint8_t *b, size_t n)
{
    static const char H[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < cap; i++) { dst[o++] = H[b[i] >> 4]; dst[o++] = H[b[i] & 15]; }
    if (cap) dst[o] = '\0';
}

// Case-insensitive substring search (both NUL-terminated, already bounded).
static bool has(const char *hay, const char *needle)
{
    size_t n = strlen(needle), h = strlen(hay);
    for (size_t i = 0; n && i + n <= h; i++)
        if (!strncasecmp(hay + i, needle, n)) return true;
    return false;
}

static void q_set(obs_t *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void q_set(obs_t *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(o->query, sizeof(o->query), fmt, ap);
    va_end(ap);
}

// ── SSDP (text, HTTP-like headers) ────────────────────────────────────────────

static bool hdr_is(const uint8_t *b, size_t n, const char *name)
{
    return strlen(name) == n && !strncasecmp((const char *)b, name, n);
}

static bool parse_ssdp(const uint8_t *b, size_t n, obs_t *o)
{
    bool search;
    if (n >= 9 && !strncasecmp((const char *)b, "M-SEARCH ", 9))    search = true;
    else if (n >= 7 && !strncasecmp((const char *)b, "NOTIFY ", 7)) search = false;
    else return false;                      // responses go to the searcher, not here
    o->proto = search ? DP_SSDP_SEARCH : DP_SSDP_NOTIFY;

    char st[64] = "", nts[24] = "";
    size_t i = 0;
    while (i < n && b[i] != '\n') i++;      // request line
    i++;
    while (i < n) {
        size_t ls = i;
        while (i < n && b[i] != '\n') i++;
        size_t le = i++;
        if (le > ls && b[le - 1] == '\r') le--;
        if (le == ls) break;                // blank line: end of headers
        size_t c = ls;
        while (c < le && b[c] != ':') c++;
        if (c >= le) continue;
        size_t nl = c - ls, vs = c + 1, vl = le - vs;
        const uint8_t *nm = b + ls, *v = b + vs;
        if (search) {
            if (hdr_is(nm, nl, "ST"))              { kv(o, "st", v, vl); clean(st, sizeof(st), v, vl); }
            else if (hdr_is(nm, nl, "MAN"))        kv(o, "man", v, vl);
            else if (hdr_is(nm, nl, "MX"))         kv(o, "mx", v, vl);
            else if (hdr_is(nm, nl, "USER-AGENT")) { kv(o, "ua", v, vl); clean(o->ua, sizeof(o->ua), v, vl); }
        } else {
            if (hdr_is(nm, nl, "NT"))              { kv(o, "nt", v, vl); clean(st, sizeof(st), v, vl); }
            else if (hdr_is(nm, nl, "NTS"))        { kv(o, "nts", v, vl); clean(nts, sizeof(nts), v, vl); }
            else if (hdr_is(nm, nl, "SERVER"))     { kv(o, "server", v, vl); clean(o->ua, sizeof(o->ua), v, vl); }
            else if (hdr_is(nm, nl, "LOCATION"))   kv(o, "location", v, vl);
        }
    }
    if (search) q_set(o, "M-SEARCH %s", st[0] ? st : "(no ST)");
    else        q_set(o, "NOTIFY %s %s", nts[0] ? nts : "?", st[0] ? st : "(no NT)");
    return true;
}

// ── WS-Discovery (SOAP; bounded scans, no XML parser) ─────────────────────────

// Text of the first element whose local name is name (any namespace prefix):
// up to the next '<', at most cap - 1 bytes. False if there is none.
static bool xml_text(const uint8_t *b, size_t n, const char *name, char *out, size_t cap)
{
    size_t nl = strlen(name);
    out[0] = '\0';
    for (size_t i = 0; i + 1 + nl < n; i++) {
        if (b[i] != '<' || b[i + 1] == '/' || b[i + 1] == '?' || b[i + 1] == '!') continue;
        size_t j = i + 1, k = j;
        while (k < n && k - j < 32 && b[k] != ':' && b[k] != '>' && b[k] != ' ' && b[k] != '/') k++;
        size_t ls = (k < n && b[k] == ':') ? k + 1 : j;
        if (ls + nl >= n || memcmp(b + ls, name, nl)) continue;
        size_t e = ls + nl;
        if (b[e] != '>' && b[e] != ' ' && b[e] != '\t' && b[e] != '\r' && b[e] != '\n' && b[e] != '/') continue;
        while (e < n && b[e] != '>') e++;
        if (e >= n || b[e - 1] == '/') return true;     // <x/>: present, empty
        size_t s = ++e;
        while (e < n && b[e] != '<') e++;
        clean(out, cap, b + s, e - s);
        return true;
    }
    return false;
}

static bool parse_wsd(const uint8_t *b, size_t n, obs_t *o)
{
    char act[96], types[KV_VAL], scopes[KV_VAL];
    if (!xml_text(b, n, "Action", act, sizeof(act)) || !act[0]) return false;
    const char *a = strrchr(act, '/');
    a = a ? a + 1 : act;
    o->proto = DP_WSD;
    kv_str(o, "action", a);
    bool t = xml_text(b, n, "Types", types, sizeof(types));
    bool s = xml_text(b, n, "Scopes", scopes, sizeof(scopes));
    if (t) kv_str(o, "types", types);
    if (s) kv_str(o, "scopes", scopes);
    char x[KV_VAL];
    if (xml_text(b, n, "XAddrs", x, sizeof(x))) kv_str(o, "xaddrs", x);
    q_set(o, "%s %s%s%s", a, t && types[0] ? types : "(any type)", s && scopes[0] ? " " : "",
          s ? scopes : "");
    return true;
}

// ── DNS names (LLMNR) and NetBIOS names ───────────────────────────────────────

// The name at *off in b[0..n): at most 8 compression pointers, each to an
// earlier offset than itself (so no loops), at most 255 bytes of labels.
// Writes it dotted and printable; moves *off past it in the packet.
static bool dns_name(const uint8_t *b, size_t n, size_t *off, char *out, size_t cap)
{
    size_t p = *off, o = 0, total = 0, end = 0;
    int jumps = 0;
    out[0] = '\0';
    for (int guard = 0; guard < 160; guard++) {
        if (p >= n) return false;
        uint8_t l = b[p];
        if (l == 0) { *off = jumps ? end : p + 1; out[o] = '\0'; return true; }
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= n) return false;
            size_t t = ((size_t)(l & 0x3F) << 8) | b[p + 1];
            if (!jumps) end = p + 2;
            if (t >= p || ++jumps > 8) return false;
            p = t;
            continue;
        }
        if (l & 0xC0) return false;                     // reserved label types
        if (p + 1 + l > n) return false;
        total += l + 1u;
        if (total > 255) return false;
        if (o && o + 1 < cap) out[o++] = '.';
        for (size_t i = 0; i < l; i++) if (o + 1 < cap) out[o++] = pr(b[p + 1 + i]);
        out[o] = '\0';
        p += 1u + l;
    }
    return false;
}

static const char *qtype_name(uint16_t t, char *tmp, size_t cap)
{
    switch (t) {
    case 1: return "A";    case 5: return "CNAME"; case 12: return "PTR"; case 16: return "TXT";
    case 28: return "AAAA"; case 33: return "SRV";  case 255: return "ANY";
    default: snprintf(tmp, cap, "type%u", (unsigned)t); return tmp;
    }
}

// The question section of a DNS-format query: "TYPE name, ..." into names
// (cap bytes), at most max questions. Returns how many were read.
static unsigned dns_questions(const uint8_t *b, size_t n, unsigned qd, unsigned max,
                              char *names, size_t cap)
{
    size_t off = 12, nn = 0;
    unsigned got = 0;
    names[0] = '\0';
    for (unsigned q = 0; q < qd && q < max; q++) {
        char name[80], tb[12];
        if (!dns_name(b, n, &off, name, sizeof(name)) || off + 4 > n) break;
        const char *tn = qtype_name(rd16(b + off), tb, sizeof(tb));
        off += 4;
        got++;
        int w = snprintf(names + nn, cap - nn, "%s%s %s", nn ? ", " : "", tn, name);
        if (w < 0 || (size_t)w >= cap - nn) break;
        nn += (size_t)w;
    }
    return got;
}

static bool parse_llmnr(const uint8_t *b, size_t n, obs_t *o)
{
    if (n < 12) return false;
    uint16_t fl = rd16(b + 2), qd = rd16(b + 4);
    if ((fl & 0x8000) || ((fl >> 11) & 0x0f) || !qd) return false;     // queries only
    o->proto = DP_LLMNR;
    char names[KV_VAL];
    if (!dns_questions(b, n, qd, 4, names, sizeof(names)) || !names[0]) return false;
    kv_str(o, "names", names);
    q_set(o, "%s", names);
    return true;
}

// mDNS query from the ring (the tap already checked QR=0 and the opcode).
// Known answers and the rest are not read.
static bool parse_mdns(const uint8_t *b, size_t n, bool mcast, obs_t *o)
{
    if (n < 12) return false;
    uint16_t fl = rd16(b + 2), qd = rd16(b + 4);
    if ((fl & 0x8000) || ((fl >> 11) & 0x0f) || !qd) return false;
    o->proto = DP_MDNS;
    char names[KV_VAL], cnt[8];
    unsigned got = dns_questions(b, n, qd, 8, names, sizeof(names));
    if (!got || !names[0]) return false;
    snprintf(cnt, sizeof(cnt), "%u", (unsigned)qd);
    kv_str(o, "names", names);
    kv_str(o, "questions", cnt);
    kv_str(o, "dst", mcast ? "multicast" : "unicast");
    q_set(o, "%s", names);
    return true;
}

// NetBIOS first-level encoding: 32 bytes 'A'..'P', two per name byte.
static bool nb_decode(const uint8_t *e, char *out, size_t cap, uint8_t *suffix)
{
    char raw[16];
    for (int i = 0; i < 16; i++) {
        uint8_t h = e[2 * i], l = e[2 * i + 1];
        if (h < 'A' || h > 'P' || l < 'A' || l > 'P') return false;
        raw[i] = (char)(((h - 'A') << 4) | (l - 'A'));
    }
    *suffix = (uint8_t)raw[15];
    clean(out, cap, (const uint8_t *)raw, 15);
    return true;
}

static bool parse_nbns(const uint8_t *b, size_t n, obs_t *o)
{
    if (n < 12 + 34 + 4) return false;
    uint16_t fl = rd16(b + 2);
    unsigned op = (fl >> 11) & 0x0f;
    if ((fl & 0x8000) || !rd16(b + 4) || b[12] != 0x20) return false;  // requests with a name
    char name[20];
    uint8_t sfx;
    if (!nb_decode(b + 13, name, sizeof(name), &sfx) || !name[0]) return false;
    o->proto = DP_NBNS;
    const char *what = op == 0 ? "query" : op == 5 ? "register" : op == 6 ? "release" :
                       op == 8 || op == 9 ? "refresh" : "other";
    char nm[32];
    snprintf(nm, sizeof(nm), "%s<%02x>", name, sfx);
    kv_str(o, "op", what);
    kv_str(o, "name", nm);
    if (op == 5 || op == 8 || op == 9) {                // the sender's own name
        strlcpy(o->host, name, sizeof(o->host));
        o->host_src = "netbios";
    }
    q_set(o, "%s %s", what, nm);
    return true;
}

// ── Vendor broadcasts ─────────────────────────────────────────────────────────

static void vendor_hex(obs_t *o, const uint8_t *b, size_t n)
{
    char h[40], sz[12];
    hex(h, sizeof(h), b, n < 16 ? n : 16);
    snprintf(sz, sizeof(sz), "%u", (unsigned)n);
    kv_str(o, "size", sz);
    kv_str(o, "hex", h);
}

static bool parse_kasa(const uint8_t *b, size_t n, uint16_t port, obs_t *o)
{
    if (!n) return false;
    o->proto = DP_KASA;
    vendor_hex(o, b, n);
    if (port == 9999) {                     // XOR autokey, key 171 (python-kasa)
        uint8_t plain[64];
        size_t m = n < sizeof(plain) ? n : sizeof(plain);
        uint8_t key = 171;
        for (size_t i = 0; i < m; i++) { plain[i] = b[i] ^ key; key = b[i]; }
        if (plain[0] == '{') {
            char j[KV_VAL];
            clean(j, sizeof(j), plain, m);
            kv_str(o, "json", j);
            q_set(o, "%u: %.48s", (unsigned)port, j);
            return true;
        }
    }
    q_set(o, "%u: %u B %s", (unsigned)port, (unsigned)n, o->v[1]);
    return true;
}

static bool parse_lifx(const uint8_t *b, size_t n, obs_t *o)
{
    if (!n) return false;
    o->proto = DP_LIFX;
    vendor_hex(o, b, n);
    if (n >= 36) {
        unsigned t = (unsigned)(b[32] | (b[33] << 8));       // little-endian message type
        char ts[8];
        snprintf(ts, sizeof(ts), "%u", t);
        kv_str(o, "type", ts);
        q_set(o, "type %u%s", t, t == 2 ? " (GetService)" : "");
    } else {
        q_set(o, "%u B", (unsigned)n);
    }
    return true;
}

static bool parse_ps(const uint8_t *b, size_t n, uint16_t port, obs_t *o)
{
    if (!n) return false;
    o->proto = DP_PS;
    vendor_hex(o, b, n);
    size_t e = 0;
    while (e < n && e < 64 && b[e] >= 0x20 && b[e] < 0x7f) e++;
    if (e >= 4) {
        char l[68];
        clean(l, sizeof(l), b, e);
        kv_str(o, "line", l);
        q_set(o, "%u: %s", (unsigned)port, l);
    } else {
        q_set(o, "%u: %u B", (unsigned)port, (unsigned)n);
    }
    return true;
}

// ── DHCP client broadcasts (BOOTP request, options after the magic cookie) ─────

static bool parse_dhcp(const uint8_t *b, size_t n, obs_t *o)
{
    static const uint8_t COOKIE[4] = { 0x63, 0x82, 0x53, 0x63 };
    if (n < 240 || b[0] != 1 || memcmp(b + 236, COOKIE, 4)) return false;   // BOOTREQUEST
    if (b[1] == 1 && b[2] == 6) {                       // Ethernet chaddr
        if (!memcmp(b + 28, s_my_mac, 6)) return false; // our own client
        static const uint8_t zero[6] = { 0 };
        if (memcmp(b + 28, zero, 6) && !(b[28] & 0x01)) { memcpy(o->mac, b + 28, 6); o->mac_known = true; }
    }
    uint32_t ciaddr, req = 0;
    memcpy(&ciaddr, b + 12, 4);
    unsigned type = 0;
    char prl[KV_VAL] = "";
    size_t pl = 0;
    size_t i = 240;
    for (int guard = 0; guard < 128 && i < n; guard++) {
        uint8_t c = b[i];
        if (c == 0) { i++; continue; }
        if (c == 255 || i + 1 >= n) break;
        size_t l = b[i + 1];
        if (i + 2 + l > n) break;
        const uint8_t *v = b + i + 2;
        switch (c) {
        case 53: if (l >= 1) type = v[0]; break;
        case 12: clean(o->host, sizeof(o->host), v, l); o->host_src = "dhcp"; break;
        case 60: clean(o->vclass, sizeof(o->vclass), v, l); break;
        case 50: if (l == 4) memcpy(&req, v, 4); break;
        case 55:
            for (size_t k = 0; k < l; k++) {
                int w = snprintf(prl + pl, sizeof(prl) - pl, "%s%u", pl ? "," : "", (unsigned)v[k]);
                if (w < 0 || (size_t)w >= sizeof(prl) - pl) break;
                pl += (size_t)w;
            }
            break;
        default: break;
        }
        i += 2 + l;
    }
    static const char *const T[] = { "?", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK",
                                     "RELEASE", "INFORM" };
    const char *tn = type < sizeof(T) / sizeof(T[0]) ? T[type] : "?";
    o->proto = DP_DHCP;
    o->ip = ciaddr ? ciaddr : req ? req : o->ip;
    kv_str(o, "msg", tn);
    if (o->host[0])   kv_str(o, "hostname", o->host);
    if (o->vclass[0]) kv_str(o, "vendor_class", o->vclass);
    if (prl[0])       kv_str(o, "prl", prl);
    q_set(o, "%s%s%s%s%s", tn, o->host[0] ? " host=" : "", o->host,
          o->vclass[0] ? " class=" : "", o->vclass);
    return true;
}

// ── Labels ────────────────────────────────────────────────────────────────────

enum { W_UA = 1, W_HOST = 2, W_VC = 4 };
typedef struct { const char *needle; uint8_t where; const char *label; } lab_t;
static const lab_t LABELS[] = {         // specific first; lan-discovery-scans.md
    { "LGE WebOS TV",      W_UA,          "LG TV (webOS)" },
    { "LG-webOS",          W_UA,          "LG TV (webOS)" },
    { "LGwebOSTV",         W_HOST,        "LG TV (webOS)" },
    { "webOS",             W_UA | W_HOST, "LG TV (webOS)" },
    { "SEC_HHP_",          W_UA,          "Samsung (SEC_HHP)" },
    { "Tizen",             W_UA,          "Samsung TV (Tizen)" },
    { "Samsung",           W_UA,          "Samsung" },
    { "Roku",              W_UA | W_HOST, "Roku" },
    { "Sonos",             W_UA | W_HOST, "Sonos" },
    { "IpBridge",          W_UA,          "Philips Hue bridge" },
    { "Cling",             W_UA,          "Fire TV or Android (Cling)" },
    { "Xbox",              W_UA | W_HOST, "Xbox" },
    { "PlayStation",       W_UA | W_HOST, "PlayStation" },
    { "CrKey",             W_UA,          "Chromecast" },
    { "Chromecast",        W_UA | W_HOST, "Chromecast" },
    { "Microsoft-Windows", W_UA,          "Windows PC" },
    { "MSFT 5.0",          W_VC,          "Windows PC" },
    { "android-dhcp",      W_VC,          "Android device" },
    { "dhcpcd",            W_VC,          "Linux or Android (dhcpcd)" },
    { "udhcp",             W_VC,          "Embedded Linux (udhcp)" },
};

static const char *label_match(const char *s, uint8_t where)
{
    for (size_t i = 0; i < sizeof(LABELS) / sizeof(LABELS[0]); i++)
        if ((LABELS[i].where & where) && has(s, LABELS[i].needle)) return LABELS[i].label;
    return NULL;
}

// The best label this datagram offers. Scores: 5 a known string in a
// USER-AGENT, SERVER or hostname; 4 a raw hostname; 3 a known vendor class;
// 2 a raw SERVER / USER-AGENT or vendor class; (1 is the MAC vendor).
static uint8_t label_of(const obs_t *o, char *out, size_t cap, const char **src)
{
    uint8_t best = 0;
    const char *m;
#define OFFER(score, text, from) do { if ((score) > best) { best = (score); strlcpy(out, (text), cap); *src = (from); } } while (0)
    const char *ua_src = o->proto == DP_SSDP_NOTIFY ? "server" : "user-agent";
    if (o->ua[0])     { m = label_match(o->ua, W_UA);       if (m) OFFER(5, m, ua_src); else OFFER(2, o->ua, ua_src); }
    if (o->host[0])   { m = label_match(o->host, W_HOST);   OFFER(m ? 5 : 4, m ? m : o->host, o->host_src ? o->host_src : "host"); }
    if (o->vclass[0]) { m = label_match(o->vclass, W_VC);   OFFER(m ? 3 : 2, m ? m : o->vclass, "dhcp-class"); }
#undef OFFER
    return best;
}

// ── Seen devices ──────────────────────────────────────────────────────────────

static void shorten(char *s, size_t max);

// The vendor, and "<vendor> device" as the label while nothing better is known.
static void vendor_label(disc_dev_t *d, const char *v)
{
    if (!v[0] || !strcmp(d->vendor, v)) return;
    strlcpy(d->vendor, v, sizeof(d->vendor));
    if (d->label_score <= 1 && d->mac_known && !(d->mac[0] & 0x02)) {
        char vs[OUI_NAME_MAX];
        strlcpy(vs, v, sizeof(vs));
        shorten(vs, 30);
        snprintf(d->label, sizeof(d->label), "%.30s device", vs);
        strlcpy(d->label_src, "mac-vendor", sizeof(d->label_src));
        d->label_score = 1;
    }
}

static disc_dev_t *find_dev(const obs_t *o, bool *is_new)
{
    disc_dev_t *hit = NULL, *free_d = NULL, *old = NULL;
    *is_new = false;
    for (int i = 0; i < DISCOVERY_DEV_MAX; i++) {
        disc_dev_t *d = &S->dev[i];
        if (!d->used) { if (!free_d) free_d = d; continue; }
        if (!old || d->last_up < old->last_up) old = d;
        if (o->mac_known && d->mac_known && !memcmp(d->mac, o->mac, 6)) return d;
    }
    for (int i = 0; o->ip && i < DISCOVERY_DEV_MAX; i++) {
        disc_dev_t *d = &S->dev[i];
        if (d->used && d->ip == o->ip && (!o->mac_known || !d->mac_known) &&
            (!hit || d->last_up > hit->last_up)) hit = d;
    }
    if (hit) {
        if (o->mac_known && !hit->mac_known) { memcpy(hit->mac, o->mac, 6); hit->mac_known = true; }
        return hit;
    }
    if (!o->mac_known && !o->ip) return NULL;
    disc_dev_t *d = free_d ? free_d : old;
    memset(d, 0, sizeof(*d));
    d->used = true;
    d->mac_known = o->mac_known;
    if (o->mac_known) memcpy(d->mac, o->mac, 6);
    d->first_up = up_s();
    uint32_t t = (uint32_t)time(NULL);
    d->first_ts = t >= CLOCK_VALID ? t : 0;
    vendor_label(d, o->vendor);
    *is_new = true;
    return d;
}

static void fmt_ip(uint32_t ip, char *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

// Append "key":"value" (escaped, value already printable) at *o.
static void jstr(char *buf, size_t cap, size_t *o, const char *key, const char *val)
{
    if (*o >= cap) return;
    int w = key ? snprintf(buf + *o, cap - *o, "\"%s\":\"", key) : snprintf(buf + *o, cap - *o, "\"");
    if (w < 0 || (size_t)w >= cap - *o) { *o = cap; return; }
    *o += (size_t)w;
    const char *p = val;
    for (; *p && *o + 2 < cap; p++) {
        char c = *p;
        if (c == '"' || c == '\\') { buf[(*o)++] = '\\'; buf[(*o)++] = c; }
        else if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7f) buf[(*o)++] = '.';
        else buf[(*o)++] = c;
    }
    if (*p || *o + 1 >= cap) { *o = cap; return; }     // did not fit: flag it
    buf[(*o)++] = '"';
}

static void jraw(char *buf, size_t cap, size_t *o, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void jraw(char *buf, size_t cap, size_t *o, const char *fmt, ...)
{
    if (*o >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(buf + *o, cap - *o, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= cap - *o) { *o = cap; return; }
    *o += (size_t)w;
}

// The SD line and the console line, under one rate limit.
static void sd_line(const disc_dev_t *d, const obs_t *o, const char *what)
{
    if (!take(&s_sd_bucket, DISCOVERY_SD_BURST, DISCOVERY_SD_REFILL_MS)) { s_sd_drop++; return; }
    char ip[16], mac[WIFI_MAC_STR_LEN];
    fmt_ip(d->ip, ip, sizeof(ip));
    wifi_manager_format_mac(d->mac_known ? d->mac : (const uint8_t[6]){ 0 }, mac, sizeof(mac));
    ESP_LOGI(TAG, "%s %s [%s] %s, %s: %s", what, ip, mac, d->label[0] ? d->label : "?",
             DP_KEY[o->proto], o->query);
    char *line = heap_caps_malloc(SD_LINE_MAX, MALLOC_CAP_SPIRAM);
    if (!line) { s_sd_drop++; return; }
    size_t n = 0, cap = SD_LINE_MAX - 2;        // room for "}\n"
    jraw(line, cap, &n, "{\"kind\":\"discovery\",\"ts\":%lu,", (unsigned long)time(NULL));
    jstr(line, cap, &n, "ip", ip);
    jraw(line, cap, &n, ",");
    jstr(line, cap, &n, "mac", mac);
    jraw(line, cap, &n, ",");
    jstr(line, cap, &n, "vendor", d->vendor);
    jraw(line, cap, &n, ",\"random_mac\":%s,\"proto\":\"%s\",\"what\":\"%s\",",
         d->mac_known && (d->mac[0] & 0x02) ? "true" : "false", DP_KEY[o->proto], what);
    jstr(line, cap, &n, "label", d->label);
    jraw(line, cap, &n, ",");
    jstr(line, cap, &n, "host", d->host);
    jraw(line, cap, &n, ",");
    jstr(line, cap, &n, "query", o->query);
    for (int i = 0; i < o->nkv; i++) {
        jraw(line, cap, &n, ",");
        jstr(line, cap, &n, o->k[i], o->v[i]);
    }
    if (n >= cap) {                             // cut: close it as a valid object anyway
        n = 0;
        jraw(line, cap, &n, "{\"kind\":\"discovery\",\"ts\":%lu,\"proto\":\"%s\",\"what\":\"%s\",\"cut\":true",
             (unsigned long)time(NULL), DP_KEY[o->proto], what);
    }
    line[n++] = '}';
    line[n++] = '\n';
    if (!sd_log_line(line, n)) s_sd_drop++;     // freed by sd_log either way
}

static void event(const disc_dev_t *d, const obs_t *o, int what, const char *old_label)
{
    if (!take(&s_ev_bucket, DISCOVERY_EV_BURST, (int64_t)DISCOVERY_EV_REFILL_S * 1000)) {
        s_ev_held++;
        return;
    }
    attack_log_t *e = &S->ev;
    memset(e, 0, sizeof(*e));
    uint32_t t = (uint32_t)time(NULL);
    e->timestamp = t;
    e->src_ip = d->ip;
    if (d->mac_known) memcpy(e->src_mac, d->mac, 6);
    e->type = ATTACK_DISCOVERY;
    const char *lab = d->label[0] ? d->label : "unknown device";
    char held[20] = "";
    if (s_ev_held) snprintf(held, sizeof(held), " (+%lu held)", (unsigned long)s_ev_held);
    s_ev_held = 0;
    size_t room = sizeof(e->payload) - strlen(held);    // the held count always fits
    int w;
    if (what == 0)
        w = snprintf(e->payload, room, "New device %s, %s: %s", lab, DP_KEY[o->proto], o->query);
    else if (what == 1)
        w = snprintf(e->payload, room, "%s now %s: %s", lab, DP_KEY[o->proto], o->query);
    else
        w = snprintf(e->payload, room, "Label %s (from %s, was %s), %s", lab, d->label_src,
                     old_label[0] ? old_label : "none", DP_KEY[o->proto]);
    if (w < 0) e->payload[0] = '\0';
    strlcat(e->payload, held, sizeof(e->payload));
    // Not log_store_append(): discovery stays out of the flash ring, the
    // dashboard's attack list, the panel and stats.bin. Discord's event log
    // and the incident logic get the event directly; the alarm and Telegram
    // apply the alert mask (discovery off by default) and the ignore list.
    discord_log_event(e);
    alarm_note_event(e);
    telegram_notify(e);

    uint32_t hw = (uint32_t)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    if (hw < s_stack_low) {
        s_stack_low = hw;
        ESP_LOGI(TAG, "stack high-water %lu B free of %d", (unsigned long)hw, DISCOVERY_TASK_STACK);
    }
}

static void observe(obs_t *o)
{
    xSemaphoreTake(s_mux, portMAX_DELAY);
    bool is_new;
    disc_dev_t *d = find_dev(o, &is_new);
    if (!d) { xSemaphoreGive(s_mux); return; }
    uint32_t t = (uint32_t)time(NULL);
    d->last_up = up_s();
    d->last_ts = t >= CLOCK_VALID ? t : 0;
    if (o->ip) d->ip = o->ip;
    d->count[o->proto]++;
    d->total++;
    bool new_proto = !is_new && !(d->protos & (1u << o->proto));
    d->protos |= (uint16_t)(1u << o->proto);

    char lab[DISCOVERY_LABEL_LEN] = "", old[DISCOVERY_LABEL_LEN];
    const char *src = "";
    uint8_t sc = label_of(o, lab, sizeof(lab), &src);
    bool new_label = false;
    strlcpy(old, d->label, sizeof(old));
    if (sc > d->label_score) {
        new_label = !is_new && strcmp(lab, d->label);
        strlcpy(d->label, lab, sizeof(d->label));
        strlcpy(d->label_src, src, sizeof(d->label_src));
        d->label_score = sc;
    }
    if (o->host[0]) strlcpy(d->host, o->host, sizeof(d->host));
    if (!is_new) vendor_label(d, o->vendor);

    bool new_query = false;
    if (o->query[0]) {
        new_query = true;
        for (int i = 0; i < d->q_n; i++) if (!strcmp(d->q[i], o->query)) { new_query = false; break; }
        if (new_query) {
            strlcpy(d->q[d->q_head], o->query, DISCOVERY_QUERY_LEN);
            d->q_head = (uint8_t)((d->q_head + 1) % DISCOVERY_QUERY_KEEP);
            if (d->q_n < DISCOVERY_QUERY_KEEP) d->q_n++;
        }
    }
    if (is_new || new_proto || new_label || new_query) {
        d->dirty = true;
        if (is_new) d->fresh = true;
        if (o->phrase[0]) {
            bool seen = false;
            for (int i = 0; i < d->act_n; i++) if (!strcmp(d->act[i], o->phrase)) { seen = true; break; }
            if (!seen && d->act_n < DISCOVERY_ACT_KEEP) strlcpy(d->act[d->act_n++], o->phrase, DISCOVERY_ACT_LEN);
            else if (!seen && d->act_more < 255) d->act_more++;
        }
    }
    S->snap = *d;                               // logged outside the lock
    xSemaphoreGive(s_mux);

    if (!(is_new || new_proto || new_label || new_query)) return;
    const char *what = is_new ? "device" : new_proto ? "protocol" : new_label ? "label" : "query";
    sd_line(&S->snap, o, what);
    if (is_new || new_proto || new_label) event(&S->snap, o, is_new ? 0 : new_proto ? 1 : 2, old);
}

// ── Plain words ───────────────────────────────────────────────────────────────

// Shorten s in place to at most max characters, at a word boundary when there
// is one in the second half, ending in "..." when anything was cut.
static void shorten(char *s, size_t max)
{
    size_t n = strlen(s);
    if (n <= max || max < 8) { if (n > max) s[max] = '\0'; return; }
    size_t cut = max - 3, b = cut;
    while (b > max / 2 && s[b] != ' ' && s[b] != ',' && s[b] != ';' && s[b] != '/' && s[b] != ':' &&
           s[b] != '.') b--;
    if (b > max / 2) cut = b;
    while (cut && strchr(" ,;:.", s[cut - 1])) cut--;
    memcpy(s + cut, "...", 4);
}

static const char *kv_get(const obs_t *o, const char *key)
{
    for (int i = 0; i < o->nkv; i++) if (!strcmp(o->k[i], key)) return o->v[i];
    return "";
}

typedef struct { const char *needle; const char *words; } words_t;

static const words_t SSDP_WORDS[] = {   // ST / NT, substring, first match
    { "urn:Belkin:",                         "searching for Belkin WeMo plugs" },
    { "dial-multiscreen-org:service:dial",   "looking for cast targets (DIAL)" },
    { "MediaServer:",                        "looking for media servers (DLNA)" },
    { "MediaRenderer:",                      "looking for media players" },
    { "roku:ecp",                            "looking for Roku devices" },
    { "InternetGatewayDevice",               "looking for the router (UPnP IGD)" },
    { "WANIPConnection",                     "looking for the router (UPnP IGD)" },
    { "WANCommonInterfaceConfig",            "looking for the router (UPnP IGD)" },
    { "ssdp:all",                            "searching for all UPnP devices" },
    { "upnp:rootdevice",                     "searching for all UPnP devices" },
    { "ZonePlayer",                          "looking for Sonos speakers" },
    { "webos-second-screen",                 "looking for LG TVs" },
    { "samsung.com",                         "looking for Samsung TVs" },
    { "hue-bridge",                          "looking for Hue bridges" },
};

static const words_t MDNS_WORDS[] = {   // service in the question name, first match
    { "_googlecast.",       "looking for Chromecasts" },
    { "_airplay.",          "looking for AirPlay" },
    { "_raop.",             "looking for AirPlay speakers" },
    { "_spotify-connect.",  "looking for Spotify Connect speakers" },
    { "_hap.",              "looking for HomeKit" },
    { "_homekit.",          "looking for HomeKit" },
    { "_ipp",               "looking for printers" },
    { "_printer.",          "looking for printers" },
    { "_pdl-datastream.",   "looking for printers" },
    { "_scanner.",          "looking for scanners" },
    { "_uscan",             "looking for scanners" },
    { "_companion-link.",   "looking for Apple devices" },
    { "_rdlink.",           "looking for Apple devices" },
    { "_sleep-proxy.",      "looking for a sleep proxy" },
    { "_hue.",              "looking for Hue bridges" },
    { "_sonos.",            "looking for Sonos speakers" },
    { "_androidtvremote",   "looking for Android TVs" },
    { "_amzn-wplay.",       "looking for Fire TVs" },
    { "_matter",            "looking for Matter devices" },
    { "_meshcop.",          "looking for Thread border routers" },
    { "_home-assistant.",   "looking for Home Assistant" },
    { "_services._dns-sd.", "listing every mDNS service" },
    { "_smb.",              "looking for file shares" },
    { "_afpovertcp.",       "looking for file shares" },
    { "_ssh.",              "looking for SSH servers" },
    { "_http.",             "looking for web servers" },
    { "_device-info.",      "asking for device details" },
};

static const words_t WSD_WORDS[] = {    // Probe Types, substring
    { "PrintDevice",             "printers" },
    { "wprt:",                   "printers" },
    { "ScanDevice",              "scanners" },
    { "wscn:",                   "scanners" },
    { "NetworkVideoTransmitter", "ONVIF cameras" },
    { "Computer",                "computers" },
    { "Device",                  "network devices (WSD)" },
};

static const char *words_for(const words_t *t, size_t n, const char *s)
{
    for (size_t i = 0; i < n; i++) if (has(s, t[i].needle)) return t[i].words;
    return NULL;
}

// The interesting tail of an unknown URN ("...:device:ZonePlayer:1" -> "ZonePlayer:1").
static void urn_tail(const char *s, char *out, size_t cap)
{
    const char *p = strstr(s, ":device:");
    if (!p) p = strstr(s, ":service:");
    if (p) p = strchr(p + 1, ':') + 1;
    strlcpy(out, p ? p : s, cap);
    shorten(out, 28);
}

static bool is_wpad(const char *name)
{
    return !strncasecmp(name, "wpad", 4) && (name[4] == '\0' || name[4] == '.' || name[4] == '<');
}

static void asked_for(const char *name, char *out, size_t cap)
{
    char n[40];
    strlcpy(n, name, sizeof(n));
    char *lt = strchr(n, '<');              // NetBIOS suffix
    if (lt) *lt = '\0';
    if (is_wpad(n)) strlcpy(out, "asked for WPAD (proxy auto-discovery)", cap);
    else { shorten(n, 32); snprintf(out, cap, "asked for %s", n); }
}

// mDNS and LLMNR questions ("PTR _googlecast._tcp.local, A host.local"): up
// to two distinct phrases, joined.
static void dns_words(const char *names, char *out, size_t cap)
{
    const char *got[2] = { NULL, NULL };
    char tmp[2][DISCOVERY_ACT_LEN];
    int n = 0;
    bool more = false;
    const char *p = names;
    while (*p) {
        const char *sp = strchr(p, ' ');
        if (!sp) break;
        const char *name = sp + 1, *end = strstr(name, ", ");
        char nm[80];
        size_t l = end ? (size_t)(end - name) : strlen(name);
        if (l >= sizeof(nm)) l = sizeof(nm) - 1;
        memcpy(nm, name, l);
        nm[l] = '\0';
        const char *w = words_for(MDNS_WORDS, sizeof(MDNS_WORDS) / sizeof(MDNS_WORDS[0]), nm);
        char buf[DISCOVERY_ACT_LEN];
        if (w) strlcpy(buf, w, sizeof(buf));
        else if (nm[0] == '_') { char s[40]; strlcpy(s, nm, sizeof(s)); shorten(s, 30); snprintf(buf, sizeof(buf), "looking for %s", s); }
        else if (has(nm, ".in-addr.arpa") || has(nm, ".ip6.arpa")) strlcpy(buf, "looking up an address", sizeof(buf));
        else asked_for(nm, buf, sizeof(buf));
        bool dup = false;
        for (int i = 0; i < n; i++) if (!strcmp(got[i], buf)) dup = true;
        if (!dup) {
            if (n < 2) { strlcpy(tmp[n], buf, sizeof(tmp[n])); got[n] = tmp[n]; n++; }
            else more = true;
        }
        if (!end) break;
        p = end + 2;
    }
    if (!n) { out[0] = '\0'; return; }
    snprintf(out, cap, "%s%s%s%s", got[0], n > 1 ? ", " : "", n > 1 ? got[1] : "", more ? " and more" : "");
}

static void lower(char *s) { for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s = (char)(*s - 'A' + 'a'); }

// What this datagram means, in plain words, at most cap - 1 characters.
static void plain(const obs_t *o, char *out, size_t cap)
{
    char a[DISCOVERY_ACT_LEN];
    const char *w;
    out[0] = '\0';
    switch (o->proto) {
    case DP_SSDP_SEARCH: {
        const char *st = kv_get(o, "st");
        w = words_for(SSDP_WORDS, sizeof(SSDP_WORDS) / sizeof(SSDP_WORDS[0]), st);
        if (w) strlcpy(out, w, cap);
        else { urn_tail(st[0] ? st : "?", a, sizeof(a)); snprintf(out, cap, "searching for %s", a); }
        break;
    }
    case DP_SSDP_NOTIFY: {
        const char *nts = kv_get(o, "nts");
        if (has(nts, "byebye"))      strlcpy(out, "signing off (UPnP)", cap);
        else if (has(nts, "update")) strlcpy(out, "announcing an update (UPnP)", cap);
        else                         strlcpy(out, "announcing itself", cap);
        break;
    }
    case DP_WSD: {
        const char *act = kv_get(o, "action"), *types = kv_get(o, "types");
        if (!strcmp(act, "Probe")) {
            w = words_for(WSD_WORDS, sizeof(WSD_WORDS) / sizeof(WSD_WORDS[0]), types);
            if (w) snprintf(out, cap, "looking for %s", w);
            else if (types[0]) { strlcpy(a, types, sizeof(a)); shorten(a, 30); snprintf(out, cap, "looking for %s (WSD)", a); }
            else strlcpy(out, "looking for any WSD device", cap);
        } else if (!strcmp(act, "Hello"))   strlcpy(out, "announcing itself (WSD)", cap);
        else if (!strcmp(act, "Bye"))       strlcpy(out, "signing off (WSD)", cap);
        else if (!strcmp(act, "Resolve"))   strlcpy(out, "resolving a WSD device", cap);
        else { strlcpy(a, act, sizeof(a)); shorten(a, 24); snprintf(out, cap, "WS-Discovery %s", a); }
        break;
    }
    case DP_LLMNR:
    case DP_MDNS:
        dns_words(kv_get(o, "names"), out, cap);
        break;
    case DP_NBNS: {
        const char *op = kv_get(o, "op"), *name = kv_get(o, "name");
        if (!strcmp(op, "query")) asked_for(name, out, cap);
        else {
            strlcpy(a, name, sizeof(a));
            char *lt = strchr(a, '<');
            if (lt) *lt = '\0';
            snprintf(out, cap, "%s its NetBIOS name %s", !strcmp(op, "register") ? "registered" :
                     !strcmp(op, "release") ? "released" : "refreshed", a);
        }
        break;
    }
    case DP_KASA: strlcpy(out, "probing for TP-Link Kasa plugs", cap); break;
    case DP_LIFX: strlcpy(out, "probing for LIFX bulbs", cap); break;
    case DP_PS:   strlcpy(out, "PlayStation discovery", cap); break;
    case DP_DHCP: {
        char t[16], vc[28];
        strlcpy(t, kv_get(o, "msg"), sizeof(t));
        lower(t);
        strlcpy(vc, o->vclass, sizeof(vc));
        shorten(vc, 24);
        snprintf(out, cap, "DHCP %s%s%s%s%s", t, o->host[0] ? ", hostname " : "", o->host,
                 vc[0] ? ", " : "", vc);
        break;
    }
    default: break;
    }
    shorten(out, cap - 1);
}

// ── Digest (Discord, every DISCOVERY_DIGEST_S) ────────────────────────────────

// One message, only when something was new: a line per device with news,
// newest first, label then address then what it did. Then every device's
// window starts over.
static void digest(void)
{
    char *buf = heap_caps_malloc(DISCOVERY_DIGEST_MAX + 1, MALLOC_CAP_SPIRAM);
    if (!buf) return;
    size_t o = 0, budget = DISCOVERY_DIGEST_MAX - 48;   // room for the "+N more" line
    int lines = 0, more = 0;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    uint8_t idx[DISCOVERY_DEV_MAX];
    int n = 0;
    for (int i = 0; i < DISCOVERY_DEV_MAX; i++) {
        if (!S->dev[i].used || !S->dev[i].dirty) continue;
        int j = n++;
        while (j > 0 && S->dev[idx[j - 1]].last_up < S->dev[i].last_up) { idx[j] = idx[j - 1]; j--; }
        idx[j] = (uint8_t)i;
    }
    for (int k = 0; k < n; k++) {
        const disc_dev_t *d = &S->dev[idx[k]];
        char *line = S->dline, addr[WIFI_MAC_STR_LEN], acts[160] = "";
        if (d->ip) fmt_ip(d->ip, addr, sizeof(addr));
        else if (d->mac_known) wifi_manager_format_mac(d->mac, addr, sizeof(addr));
        else strlcpy(addr, "?", sizeof(addr));
        size_t al = 0;
        for (int i = 0; i < d->act_n; i++) {
            int w = snprintf(acts + al, sizeof(acts) - al, "%s%s", i ? "; " : "", d->act[i]);
            if (w < 0 || (size_t)w >= sizeof(acts) - al) break;
            al += (size_t)w;
        }
        if (d->act_more && al + 12 < sizeof(acts)) snprintf(acts + al, sizeof(acts) - al, "; and more");
        const char *lab = d->label[0] ? d->label : (d->mac_known && (d->mac[0] & 0x02)) ?
                          "private-MAC device" : "unknown device";
        snprintf(line, sizeof(S->dline), "%s%s %s: %s", lab, d->fresh ? " (new)" : "", addr,
                 acts[0] ? acts : "seen");
        shorten(line, DISCOVERY_DIGEST_LINE);
        size_t len = strlen(line), cost = len + 1;
        for (size_t i = 0; i < len; i++) if (line[i] == '@') cost++;     // Discord breaks each '@'
        if (lines >= DISCOVERY_DIGEST_LINES || o + cost > budget) { more++; continue; }
        memcpy(buf + o, line, len);
        o += len;
        buf[o++] = '\n';
        lines++;
    }
    for (int i = 0; i < DISCOVERY_DEV_MAX; i++) {
        disc_dev_t *d = &S->dev[i];
        d->dirty = d->fresh = false;
        d->act_n = d->act_more = 0;
    }
    xSemaphoreGive(s_mux);
    if (!lines) { free(buf); return; }
    if (more) o += (size_t)snprintf(buf + o, DISCOVERY_DIGEST_MAX + 1 - o, "+%d more on the Devices tab\n", more);
    buf[o] = '\0';
    ESP_LOGI(TAG, "Digest: %d devices%s", lines + more, more ? " (some only on the Devices tab)" : "");
    discord_post_digest(buf);                   // owns buf from here
}

// ── Sockets and task ──────────────────────────────────────────────────────────

static void open_listener(int i)
{
    const lsn_t *l = &LSN[i];
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) { s_err[i] = errno; s_stage[i] = 's'; return; }
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(l->port),
                             .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        s_err[i] = errno; s_stage[i] = 'b';
        close(s);
        return;
    }
    if (l->group[0]) {
        struct ip_mreq mr;
        memcpy(&mr.imr_multiaddr.s_addr, l->group, 4);
        mr.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
            s_err[i] = errno; s_stage[i] = 'j';
            close(s);
            return;
        }
    }
    s_sock[i] = s;
    s_err[i] = 0;
}

static uint32_t my_ip(void)
{
    esp_netif_t *n = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    return (n && esp_netif_get_ip_info(n, &info) == ESP_OK) ? info.ip.addr : 0;
}

static void finish(obs_t *o);

static void handle(int li, size_t n, uint32_t src)
{
    const uint8_t *b = S->rx;
    obs_t *o = &S->obs;
    memset(o, 0, sizeof(*o));
    o->ip = src;
    bool ok = false;
    switch (li) {
    case L_SSDP:  ok = parse_ssdp(b, n, o); break;
    case L_WSD:   ok = parse_wsd(b, n, o); break;
    case L_LLMNR: ok = parse_llmnr(b, n, o); break;
    case L_NBNS:  ok = parse_nbns(b, n, o); break;
    case L_KASA: case L_KASA2: ok = parse_kasa(b, n, LSN[li].port, o); break;
    case L_LIFX:  ok = parse_lifx(b, n, o); break;
    case L_PS: case L_PS2: ok = parse_ps(b, n, LSN[li].port, o); break;
    case L_DHCP:  ok = parse_dhcp(b, n, o); break;
    default: break;
    }
    if (!ok) return;
    finish(o);
}

static void finish(obs_t *o)
{
    if (!o->mac_known && o->ip && mac_for(o->ip, o->mac)) o->mac_known = true;
    if (o->mac_known) oui_lookup(o->mac, o->vendor, sizeof(o->vendor));   // cached after the first
    plain(o, o->phrase, sizeof(o->phrase));
    if (o->mac_known && !memcmp(o->mac, s_my_mac, 6)) return;
    observe(o);
}

// Queued mDNS queries, oldest first. The slot is copied out before it is freed.
static void mdns_drain(uint32_t me)
{
    uint32_t t = s_mtail, h = __atomic_load_n(&s_mhead, __ATOMIC_ACQUIRE);
    for (; t != h; t++) {
        const mdns_slot_t *sl = &s_mring[t % DISCOVERY_MDNS_SLOTS];
        uint32_t ip = sl->ip;
        uint8_t mac[6];
        memcpy(mac, sl->mac, 6);
        bool mcast = sl->mcast;
        size_t n = sl->len <= DISCOVERY_MDNS_COPY ? sl->len : DISCOVERY_MDNS_COPY;
        memcpy(S->rx, sl->data, n);
        __atomic_store_n(&s_mtail, t + 1, __ATOMIC_RELEASE);
        S->rx[n] = 0;
        if (!ip || ip == me) continue;
        obs_t *o = &S->obs;
        memset(o, 0, sizeof(*o));
        o->ip = ip;
        memcpy(o->mac, mac, 6);
        o->mac_known = true;
        if (parse_mdns(S->rx, n, mcast, o)) finish(o);
    }
}

void discovery_init(void)
{
    for (int i = 0; i < L_N; i++) s_sock[i] = -1;
    S = heap_caps_calloc(1, sizeof(state_t), MALLOC_CAP_SPIRAM);
    s_mux = xSemaphoreCreateMutex();
    QueueHandle_t q = xQueueCreateWithCaps(MACQ_DEPTH, sizeof(mac_msg_t), MALLOC_CAP_SPIRAM);
    mdns_slot_t *ring = heap_caps_calloc(DISCOVERY_MDNS_SLOTS, sizeof(mdns_slot_t), MALLOC_CAP_SPIRAM);
    if (!S || !s_mux || !q || !ring) {
        ESP_LOGE(TAG, "No memory for the discovery state, listeners off");
        return;
    }
    s_mring = ring;
    s_macq = q;                                 // last: the frame tap starts now
    ESP_LOGI(TAG, "Discovery: %u B state + %u B MAC queue + %u B mDNS ring in PSRAM",
             (unsigned)sizeof(state_t), (unsigned)(MACQ_DEPTH * sizeof(mac_msg_t)),
             (unsigned)(DISCOVERY_MDNS_SLOTS * sizeof(mdns_slot_t)));
}

void discovery_task(void *arg)
{
    (void)arg;
    if (!s_macq) { vTaskDelete(NULL); return; }
    esp_wifi_get_mac(WIFI_IF_STA, s_my_mac);
    wifi_manager_wait_for_ip();

    int n_open = 0;
    for (int i = 0; i < L_N; i++) {
        if (i == L_DHCP && !DISCOVERY_DHCP) continue;
        open_listener(i);
        if (s_sock[i] >= 0) n_open++;
        else ESP_LOGW(TAG, "%s UDP %u not open: %s errno %d", LSN[i].name, (unsigned)LSN[i].port,
                      s_stage[i] == 'j' ? "join" : s_stage[i] == 'b' ? "bind" : "socket", s_err[i]);
    }
    ESP_LOGI(TAG, "Listening (log only, never answers) on %d of %d UDP ports: SSDP 1900, WSD 3702, "
             "LLMNR 5355, NBNS 137, Kasa 9999 20002, LIFX 56700, PlayStation 987 9302%s; mDNS 5353 queries "
             "copied from the Wi-Fi input (no socket)", n_open, L_N - (DISCOVERY_DHCP ? 0 : 1),
             DISCOVERY_DHCP ? ", DHCP 67" : "");

    uint32_t last_retry = up_s(), me = my_ip(), last_me = up_s(), last_digest = up_s();
    for (;;) {
        fd_set rd;
        FD_ZERO(&rd);
        int maxfd = -1;
        for (int i = 0; i < L_N; i++)
            if (s_sock[i] >= 0) { FD_SET(s_sock[i], &rd); if (s_sock[i] > maxfd) maxfd = s_sock[i]; }
        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };   // also the mDNS ring's latency
        int r = 0;
        if (maxfd >= 0) r = select(maxfd + 1, &rd, NULL, NULL, &tv);
        else vTaskDelay(pdMS_TO_TICKS(500));
        macmap_drain();
        uint32_t now = up_s();
        if (now - last_me >= 5) { me = my_ip(); last_me = now; }
        mdns_drain(me);
        oui_service(4);                         // vendor misses from other tasks
        if (now - last_digest >= DISCOVERY_DIGEST_S) { last_digest = now; digest(); }
        if (now - last_retry >= RETRY_S) {
            last_retry = now;
            for (int i = 0; i < L_N; i++)
                if (s_sock[i] < 0 && (i != L_DHCP || DISCOVERY_DHCP)) {
                    open_listener(i);
                    if (s_sock[i] >= 0) ESP_LOGI(TAG, "%s UDP %u open", LSN[i].name, (unsigned)LSN[i].port);
                }
        }
        if (r <= 0) continue;
        for (int i = 0; i < L_N; i++) {
            if (s_sock[i] < 0 || !FD_ISSET(s_sock[i], &rd)) continue;
            for (int k = 0; k < PER_SOCK_READS; k++) {
                struct sockaddr_in from;
                socklen_t fl = sizeof(from);
                int n = recvfrom(s_sock[i], S->rx, DISCOVERY_RX_MAX, MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &fl);
                if (n < 0) break;
                if (fl < sizeof(from) || from.sin_family != AF_INET) continue;
                S->rx[n] = 0;
                s_pkts[i]++;
                uint32_t src = from.sin_addr.s_addr;
                if (src && src == me) continue;
                macmap_drain();
                handle(i, (size_t)n, src);
            }
        }
    }
}

// ── GET /api/devices ──────────────────────────────────────────────────────────

size_t discovery_devices_json(char *buf, size_t cap)
{
    if (!buf || cap < 128) return 0;
    size_t o = 0, lim = cap - 48;               // room to close the object
    uint32_t pk = 0;
    for (int i = 0; i < L_N; i++) pk += s_pkts[i];
    jraw(buf, lim, &o, "{\"enabled\":%s,\"packets\":%lu,\"mac_queue_dropped\":%lu,\"sd_dropped\":%lu,"
         "\"events_held\":%lu,\"max\":%d,\"mdns\":\"copied from the Wi-Fi input, no socket: %lu queries, %lu dropped\","
         "\"mdns_queries\":%lu,\"mdns_dropped\":%lu,\"listeners\":[",
         S ? "true" : "false", (unsigned long)pk, (unsigned long)s_macq_drop, (unsigned long)s_sd_drop,
         (unsigned long)s_ev_held, DISCOVERY_DEV_MAX, (unsigned long)s_mdns_q, (unsigned long)s_mdns_drop,
         (unsigned long)s_mdns_q, (unsigned long)s_mdns_drop);
    for (int i = 0; i < L_N; i++) {
        char err[40] = "";
        if (i == L_DHCP && !DISCOVERY_DHCP) strlcpy(err, "disabled", sizeof(err));
        else if (s_sock[i] < 0 && s_err[i])
            snprintf(err, sizeof(err), "%s failed, errno %d",
                     s_stage[i] == 'j' ? "join" : s_stage[i] == 'b' ? "bind" : "socket", s_err[i]);
        jraw(buf, lim, &o, "%s{\"name\":\"%s\",\"port\":%u,\"open\":%s,\"packets\":%lu,\"error\":\"%s\"}",
             i ? "," : "", LSN[i].name, (unsigned)LSN[i].port, s_sock[i] >= 0 ? "true" : "false",
             (unsigned long)s_pkts[i], err);
    }
    jraw(buf, lim, &o, "],\"devices\":[");
    int count = 0;
    bool cut = false;
    if (S) {
        xSemaphoreTake(s_mux, portMAX_DELAY);
        uint8_t idx[DISCOVERY_DEV_MAX];
        int n = 0;
        for (int i = 0; i < DISCOVERY_DEV_MAX; i++) {
            if (!S->dev[i].used) continue;
            int j = n++;
            while (j > 0 && S->dev[idx[j - 1]].last_up < S->dev[i].last_up) { idx[j] = idx[j - 1]; j--; }
            idx[j] = (uint8_t)i;
        }
        uint32_t now = up_s();
        for (int k = 0; k < n && !cut; k++) {
            const disc_dev_t *d = &S->dev[idx[k]];
            size_t mark = o;
            char ip[16], mac[WIFI_MAC_STR_LEN];
            fmt_ip(d->ip, ip, sizeof(ip));
            wifi_manager_format_mac(d->mac_known ? d->mac : (const uint8_t[6]){ 0 }, mac, sizeof(mac));
            jraw(buf, lim, &o, "%s{", count ? "," : "");
            jstr(buf, lim, &o, "mac", mac);
            jraw(buf, lim, &o, ",\"random_mac\":%s,", d->mac_known && (d->mac[0] & 0x02) ? "true" : "false");
            jstr(buf, lim, &o, "vendor", d->vendor);
            jraw(buf, lim, &o, ",");
            jstr(buf, lim, &o, "ip", d->ip ? ip : "");
            jraw(buf, lim, &o, ",");
            jstr(buf, lim, &o, "label", d->label);
            jraw(buf, lim, &o, ",");
            jstr(buf, lim, &o, "label_src", d->label_src);
            jraw(buf, lim, &o, ",");
            jstr(buf, lim, &o, "host", d->host);
            jraw(buf, lim, &o, ",\"protos\":{");
            bool first = true;
            for (int p = 0; p < DP_COUNT; p++) {
                if (!(d->protos & (1u << p))) continue;
                jraw(buf, lim, &o, "%s\"%s\":%lu", first ? "" : ",", DP_KEY[p], (unsigned long)d->count[p]);
                first = false;
            }
            jraw(buf, lim, &o, "},\"total\":%lu,\"first_ts\":%lu,\"last_ts\":%lu,\"first_ago_s\":%lu,"
                 "\"last_ago_s\":%lu,\"queries\":[",
                 (unsigned long)d->total, (unsigned long)d->first_ts, (unsigned long)d->last_ts,
                 (unsigned long)(now - d->first_up), (unsigned long)(now - d->last_up));
            for (int q = 0; q < d->q_n; q++) {          // newest first
                int qi = (d->q_head + DISCOVERY_QUERY_KEEP - 1 - q) % DISCOVERY_QUERY_KEEP;
                if (q) jraw(buf, lim, &o, ",");
                jstr(buf, lim, &o, NULL, d->q[qi]);
            }
            jraw(buf, lim, &o, "]}");
            if (o >= lim) { o = mark; cut = true; break; }
            count++;
        }
        xSemaphoreGive(s_mux);
    }
    if (o > lim) o = lim;
    o += (size_t)snprintf(buf + o, cap - o, "],\"count\":%d,\"truncated\":%s}", count, cut ? "true" : "false");
    return o < cap ? o : cap - 1;
}
