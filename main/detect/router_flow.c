// Router flows: IPFIX / NetFlow v9 collector off the Wi-Fi input. See
// router_flow.h. Fork addition, Robert Mech.
//
// The router is trusted to send these, but the bytes still come off the
// network: every length and offset is checked against what is left of the
// datagram before it is read, and every loop is bounded by it.

#include "router_flow.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "RTRFLOW";

static inline uint16_t rd16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }
static inline uint32_t rd32(const uint8_t *b) { return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }
static int64_t up_s(void) { return esp_timer_get_time() / 1000000LL; }

// An unsigned field of 1 to 8 bytes (reduced-size encoding, RFC 7011 6.2).
static uint64_t rdn(const uint8_t *b, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n && i < 8; i++) v = v << 8 | b[i];
    return v;
}

// ── Ring (Wi-Fi RX task to router task) ───────────────────────────────────────

typedef struct {
    uint16_t len;
    uint8_t  data[ROUTER_FLOW_SLOT];
} fl_slot_t;

static fl_slot_t        *s_ring;
static uint32_t          s_head, s_tail;
static volatile uint32_t s_rx, s_rx_drop, s_rx_cut;

void router_flow_push(const uint8_t *data, size_t len)
{
    fl_slot_t *ring = __atomic_load_n(&s_ring, __ATOMIC_ACQUIRE);
    if (!ring) return;
    s_rx++;
    if (len > ROUTER_FLOW_SLOT) { s_rx_cut++; return; }     // not a whole datagram: useless
    uint32_t h = s_head, t = __atomic_load_n(&s_tail, __ATOMIC_ACQUIRE);
    if (h - t >= ROUTER_FLOW_SLOTS) { s_rx_drop++; return; }
    fl_slot_t *d = &ring[h % ROUTER_FLOW_SLOTS];
    d->len = (uint16_t)len;
    memcpy(d->data, data, len);
    __atomic_store_n(&s_head, h + 1, __ATOMIC_RELEASE);
}

// ── Templates (router task only) ──────────────────────────────────────────────

enum { F_BYTES, F_PKTS, F_PROTO, F_SPORT, F_DPORT, F_SRC, F_DST, F_NSRC, F_NDST, F_N };

typedef struct {
    bool     used, usable, varlen;
    uint8_t  ver;
    uint16_t id, n;
    uint32_t domain;            // IPFIX observation domain, v9 source id
    int64_t  seen;
    uint16_t fixed_len;         // record length when no field is variable
    struct { uint16_t ie, len; } f[ROUTER_FLOW_FIELDS];
    int16_t  off[F_N];          // byte offset of each wanted field (fixed layout), -1 none
    uint8_t  len[F_N];
} tmpl_t;

// ── Table (router task writes, any task reads under s_lock) ───────────────────

typedef struct {
    uint32_t ip;
    uint32_t first, last;
    uint16_t n;
    bool     truncated;
    router_flow_dst_t d[ROUTER_FLOW_DST];
} fdev_t;

typedef struct {
    tmpl_t   t[ROUTER_FLOW_TEMPLATES];
    fdev_t    dev[ROUTER_FLOW_DEVICES];
} fl_t;

static fl_t             *F;
static SemaphoreHandle_t s_lock;
static struct {
    uint32_t datagrams, records, kept, lan, dropped, no_template, templates, bad, unusable, v9, v10;
    uint32_t last;              // unix time of the last datagram
    int64_t  sec;               // the rate budget's second
    uint32_t used;              // records in it
} s_st;                         // router task writes; the status reads the words as they are

static bool private_ip(uint32_t ip)
{
    const uint8_t *b = (const uint8_t *)&ip;      // network order
    return b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168);
}

static bool public_ip(uint32_t ip)
{
    const uint8_t *b = (const uint8_t *)&ip;
    if (!ip || private_ip(ip)) return false;
    if (b[0] == 0 || b[0] == 127 || b[0] >= 224) return false;     // this net, loopback, multicast and up
    if (b[0] == 169 && b[1] == 254) return false;                  // link-local
    if (b[0] == 100 && (b[1] & 0xc0) == 64) return false;          // CGNAT
    return true;
}

static int want_of(uint16_t ie)
{
    switch (ie) {
    case 1: case 85:  return F_BYTES;
    case 2: case 86:  return F_PKTS;
    case 4:   return F_PROTO;
    case 7:   return F_SPORT;
    case 11:  return F_DPORT;
    case 8:   return F_SRC;
    case 12:  return F_DST;
    case 225: return F_NSRC;
    case 226: return F_NDST;
    default:  return -1;
    }
}

static tmpl_t *tmpl_find(uint8_t ver, uint32_t domain, uint16_t id)
{
    for (int i = 0; i < ROUTER_FLOW_TEMPLATES; i++) {
        tmpl_t *t = &F->t[i];
        if (t->used && t->ver == ver && t->domain == domain && t->id == id) return t;
    }
    return NULL;
}

static tmpl_t *tmpl_slot(uint8_t ver, uint32_t domain, uint16_t id)
{
    tmpl_t *t = tmpl_find(ver, domain, id);
    if (t) return t;
    tmpl_t *old = &F->t[0];
    for (int i = 0; i < ROUTER_FLOW_TEMPLATES; i++) {
        if (!F->t[i].used) return &F->t[i];
        if (F->t[i].seen < old->seen) old = &F->t[i];
    }
    return old;
}

// One template record at p (left bytes). Returns its length, 0 when cut.
static size_t parse_template(uint8_t ver, uint32_t domain, const uint8_t *p, size_t left)
{
    if (left < 4) return 0;
    uint16_t id = rd16(p), n = rd16(p + 2);
    size_t at = 4;
    if (id < 256) return 0;                                     // 0..255 are set ids, not templates
    tmpl_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.ver = ver;
    tmp.domain = domain;
    tmp.id = id;
    tmp.usable = n > 0 && n <= ROUTER_FLOW_FIELDS;
    for (int k = 0; k < F_N; k++) tmp.off[k] = -1;
    uint32_t off = 0;
    for (uint16_t i = 0; i < n; i++) {
        if (at + 4 > left) return 0;
        uint16_t ie = rd16(p + at), len = rd16(p + at + 2);
        at += 4;
        if (ver == 10 && (ie & 0x8000)) {                       // enterprise: a 4-byte number follows
            if (at + 4 > left) return 0;
            at += 4;
            ie = 0;                                             // not one of ours
        }
        if (i >= ROUTER_FLOW_FIELDS) continue;
        tmp.f[i].ie = ie;
        tmp.f[i].len = len;
        if (ver == 10 && len == 65535) { tmp.varlen = true; continue; }
        if (len == 0) { tmp.usable = false; continue; }
        int w = want_of(ie);
        if (w >= 0 && !tmp.varlen && len <= 8 && off <= 0x7fff) { tmp.off[w] = (int16_t)off; tmp.len[w] = (uint8_t)len; }
        if (w >= 0 && tmp.varlen) tmp.off[w] = -2;              // found by walking each record
        off += len;
    }
    tmp.n = n <= ROUTER_FLOW_FIELDS ? n : ROUTER_FLOW_FIELDS;
    if (off == 0 && !tmp.varlen) tmp.usable = false;
    if (off > ROUTER_FLOW_SLOT) tmp.usable = false;
    tmp.fixed_len = (uint16_t)(off <= 0xffff ? off : 0);
    tmp.used = true;
    tmp.seen = up_s();
    tmpl_t *slot = tmpl_slot(ver, domain, id);
    *slot = tmp;
    s_st.templates++;
    if (!tmp.usable) s_st.unusable++;
    return at;
}

// ── Aggregation ───────────────────────────────────────────────────────────────

static void keep(uint32_t inside, uint32_t remote, uint16_t rport, uint8_t proto, bool out,
                 uint64_t bytes, uint64_t pkts, uint32_t ts)
{
    fdev_t *dv = NULL, *old = &F->dev[0];
    for (int i = 0; i < ROUTER_FLOW_DEVICES; i++) {
        fdev_t *x = &F->dev[i];
        if (x->ip == inside) { dv = x; break; }
        if (!x->ip) { if (old->ip) old = x; continue; }
        if (old->ip && x->last < old->last) old = x;
    }
    if (!dv) {
        dv = old;
        memset(dv, 0, sizeof(*dv));
        dv->ip = inside;
        dv->first = ts;
    }
    dv->last = ts;
    router_flow_dst_t *d = NULL, *lru = NULL;
    for (int i = 0; i < dv->n; i++) {
        router_flow_dst_t *x = &dv->d[i];
        if (x->ip == remote && x->port == rport && x->proto == proto) { d = x; break; }
        if (!lru || x->last < lru->last) lru = x;
    }
    if (!d) {
        if (dv->n < ROUTER_FLOW_DST) d = &dv->d[dv->n++];
        else { d = lru; dv->truncated = true; }
        memset(d, 0, sizeof(*d));
        d->ip = remote;
        d->port = rport;
        d->proto = proto;
        d->external = public_ip(remote);
        d->first = ts;
    }
    if (out) { d->bytes_out += bytes; d->pkts_out += (uint32_t)pkts; }
    else     { d->bytes_in += bytes;  d->pkts_in += (uint32_t)pkts; }
    d->flows++;
    d->last = ts;
}

typedef struct { uint64_t v[F_N]; bool have[F_N]; } rec_t;

static void record(const rec_t *r, uint32_t ts)
{
    uint32_t src = r->have[F_SRC] ? __builtin_bswap32((uint32_t)r->v[F_SRC]) : 0;
    uint32_t dst = r->have[F_DST] ? __builtin_bswap32((uint32_t)r->v[F_DST]) : 0;
    uint32_t nsrc = r->have[F_NSRC] ? __builtin_bswap32((uint32_t)r->v[F_NSRC]) : 0;
    uint32_t ndst = r->have[F_NDST] ? __builtin_bswap32((uint32_t)r->v[F_NDST]) : 0;
    uint16_t sp = (uint16_t)r->v[F_SPORT], dp = (uint16_t)r->v[F_DPORT];
    uint8_t proto = (uint8_t)r->v[F_PROTO];
    uint64_t bytes = r->v[F_BYTES], pkts = r->v[F_PKTS];
    if (!src || !dst) return;
    if (private_ip(src) && public_ip(dst))              keep(src, dst, dp, proto, true, bytes, pkts, ts);
    else if (public_ip(src) && private_ip(dst))         keep(dst, src, sp, proto, false, bytes, pkts, ts);
    else if (public_ip(src) && public_ip(dst) && private_ip(ndst)) keep(ndst, src, sp, proto, false, bytes, pkts, ts);
    else if (public_ip(src) && public_ip(dst) && private_ip(nsrc)) keep(nsrc, dst, dp, proto, true, bytes, pkts, ts);
    else { s_st.lan++; return; }
    s_st.kept++;
}

// The rate budget: true while records may still be taken this second.
static bool budget(void)
{
    int64_t now = up_s();
    if (now != s_st.sec) { s_st.sec = now; s_st.used = 0; }
    if (s_st.used >= ROUTER_IPFIX_RATE) return false;
    s_st.used++;
    return true;
}

// The data records of one set (p, left bytes) under template t.
static void parse_data(const tmpl_t *t, const uint8_t *p, size_t left, uint32_t ts)
{
    size_t at = 0;
    for (int guard = 0; guard < 1500 && at < left; guard++) {
        rec_t r;
        memset(&r, 0, sizeof(r));
        size_t start = at;
        if (!t->varlen) {
            if (t->fixed_len == 0 || at + t->fixed_len > left) return;     // the rest is padding
            for (int k = 0; k < F_N; k++)
                if (t->off[k] >= 0) { r.v[k] = rdn(p + at + t->off[k], t->len[k]); r.have[k] = true; }
            at += t->fixed_len;
        } else {
            for (uint16_t i = 0; i < t->n; i++) {
                size_t len = t->f[i].len;
                if (len == 65535) {
                    if (at + 1 > left) return;
                    len = p[at++];
                    if (len == 255) {
                        if (at + 2 > left) return;
                        len = rd16(p + at);
                        at += 2;
                    }
                }
                if (at + len > left) return;
                int w = want_of(t->f[i].ie);
                if (w >= 0 && len >= 1 && len <= 8) { r.v[w] = rdn(p + at, (unsigned)len); r.have[w] = true; }
                at += len;
            }
            if (at == start) return;                    // no progress: stop
        }
        s_st.records++;
        if (!budget()) {
            size_t rl = at - start;
            s_st.dropped += 1 + (rl ? (uint32_t)((left - at) / rl) : 0);
            return;
        }
        record(&r, ts);
    }
}

static void parse_datagram(const uint8_t *b, size_t len)
{
    if (len < 16) { s_st.bad++; return; }
    uint16_t ver = rd16(b);
    size_t at;
    uint32_t domain, ts;
    if (ver == 10) {
        size_t total = rd16(b + 2);
        if (total < 16 || total > len) { s_st.bad++; return; }
        len = total;
        ts = rd32(b + 4);
        domain = rd32(b + 12);
        at = 16;
        s_st.v10++;
    } else if (ver == 9) {
        if (len < 20) { s_st.bad++; return; }
        ts = rd32(b + 8);
        domain = rd32(b + 16);
        at = 20;
        s_st.v9++;
    } else {
        s_st.bad++;
        return;
    }
    uint32_t now = (uint32_t)time(NULL);
    if (ts < 1600000000u || ts > now + 600) ts = now;  // the router's clock unset: ours
    s_st.datagrams++;
    s_st.last = now;
    for (int guard = 0; guard < 64 && at + 4 <= len; guard++) {
        uint16_t id = rd16(b + at), sl = rd16(b + at + 2);
        if (sl < 4 || at + sl > len) { s_st.bad++; return; }
        const uint8_t *body = b + at + 4;
        size_t bl = sl - 4u;
        bool tmpl_set = ver == 10 ? id == 2 : id == 0;
        bool opt_set  = ver == 10 ? id == 3 : id == 1;
        if (tmpl_set) {
            size_t k = 0;
            for (int g = 0; g < 64 && k + 4 <= bl; g++) {
                size_t n = parse_template((uint8_t)ver, domain, body + k, bl - k);
                if (!n) break;
                k += n;
            }
        } else if (opt_set) {
            // options templates (sampling, interface names): not used
        } else if (id >= 256) {
            const tmpl_t *t = tmpl_find((uint8_t)ver, domain, id);
            if (!t || !t->usable) s_st.no_template++;
            else if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE) {
                parse_data(t, body, bl, ts);
                xSemaphoreGive(s_lock);
            }
        }
        at += sl;
    }
}

// ── Router task ───────────────────────────────────────────────────────────────

bool router_flow_init(void)
{
#if !ROUTER_IPFIX_ENABLE
    return false;
#else
    F = heap_caps_calloc(1, sizeof(*F), MALLOC_CAP_SPIRAM);
    fl_slot_t *ring = heap_caps_calloc(ROUTER_FLOW_SLOTS, sizeof(fl_slot_t), MALLOC_CAP_SPIRAM);
    s_lock = xSemaphoreCreateMutex();
    if (!F || !ring || !s_lock) {
        ESP_LOGE(TAG, "IPFIX collector not started: out of memory");
        free(F); free(ring); F = NULL;
        return false;
    }
    __atomic_store_n(&s_ring, ring, __ATOMIC_RELEASE);
    ESP_LOGI(TAG, "IPFIX / NetFlow v9 on UDP %d: %u B ring and %u B table in PSRAM, %d records/s, no socket",
             ROUTER_IPFIX_PORT, (unsigned)(ROUTER_FLOW_SLOTS * sizeof(fl_slot_t)), (unsigned)sizeof(*F),
             ROUTER_IPFIX_RATE);
    return true;
#endif
}

void router_flow_service(void)
{
    if (!s_ring) return;
    for (int k = 0; k < ROUTER_FLOW_SLOTS; k++) {
        uint32_t t = s_tail, h = __atomic_load_n(&s_head, __ATOMIC_ACQUIRE);
        if (t == h) break;
        const fl_slot_t *d = &s_ring[t % ROUTER_FLOW_SLOTS];
        parse_datagram(d->data, d->len < ROUTER_FLOW_SLOT ? d->len : ROUTER_FLOW_SLOT);
        __atomic_store_n(&s_tail, t + 1, __ATOMIC_RELEASE);
    }
    // Idle destinations go.
    static int64_t next;
    int64_t now = up_s();
    if (now < next || xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE) return;
    next = now + 60;
    uint32_t cut = (uint32_t)time(NULL) - ROUTER_FLOW_KEEP_S;
    for (int i = 0; i < ROUTER_FLOW_DEVICES; i++) {
        fdev_t *dv = &F->dev[i];
        if (!dv->ip) continue;
        int o = 0;
        for (int k = 0; k < dv->n; k++) if (dv->d[k].last >= cut) dv->d[o++] = dv->d[k];
        dv->n = (uint16_t)o;
        if (!o) memset(dv, 0, sizeof(*dv));
    }
    xSemaphoreGive(s_lock);
}

// ── Readers ───────────────────────────────────────────────────────────────────

const char *router_flow_state_key(uint8_t st)
{
    return st == ROUTER_FLOW_ST_OK ? "ok" : st == ROUTER_FLOW_ST_WAITING ? "waiting" : "off";
}

static uint8_t state(void)
{
    if (!s_ring) return ROUTER_FLOW_ST_OFF;
    return s_st.datagrams ? ROUTER_FLOW_ST_OK : ROUTER_FLOW_ST_WAITING;
}

static int cmp_bytes(const void *a, const void *b)
{
    const router_flow_dst_t *x = a, *y = b;
    uint64_t bx = x->bytes_out + x->bytes_in, by = y->bytes_out + y->bytes_in;
    return bx < by ? 1 : bx > by ? -1 : 0;
}

bool router_flow_device(uint32_t ip, router_flow_dev_t *out)
{
    memset(out, 0, sizeof(*out));
    out->state = state();
    out->ip = ip;
    if (!F || !ip || xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) != pdTRUE) return false;
    bool found = false;
    for (int i = 0; i < ROUTER_FLOW_DEVICES && !found; i++) {
        const fdev_t *dv = &F->dev[i];
        if (dv->ip != ip) continue;
        found = true;
        out->as_of = dv->last;
        out->truncated = dv->truncated;
        out->n = dv->n;
        memcpy(out->d, dv->d, sizeof(out->d[0]) * dv->n);
        out->first = dv->first;
        for (int k = 0; k < dv->n; k++) if (dv->d[k].first < out->first) out->first = dv->d[k].first;
    }
    xSemaphoreGive(s_lock);
    if (found) qsort(out->d, out->n, sizeof(out->d[0]), cmp_bytes);
    return found && out->n;
}

int router_flow_ext_count(uint32_t ip)
{
    int n = 0;
    if (!F || !ip || xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) return 0;
    for (int i = 0; i < ROUTER_FLOW_DEVICES; i++) {
        const fdev_t *dv = &F->dev[i];
        if (dv->ip != ip) continue;
        for (int k = 0; k < dv->n; k++) n += dv->d[k].external;
        break;
    }
    xSemaphoreGive(s_lock);
    return n;
}

void router_flow_counters(uint32_t *records, uint32_t *dropped)
{
    *records = s_st.records;
    *dropped = s_st.dropped;
}

size_t router_flow_status_json(char *buf, size_t cap)
{
    int devices = 0;
    if (F && xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < ROUTER_FLOW_DEVICES; i++) devices += F->dev[i].ip != 0;
        xSemaphoreGive(s_lock);
    }
    int n = snprintf(buf, cap,
        "{\"enabled\":%s,\"state\":\"%s\",\"port\":%d,\"rate\":%d,\"received\":%lu,\"ring_dropped\":%lu,"
        "\"oversize\":%lu,\"datagrams\":%lu,\"ipfix\":%lu,\"netflow9\":%lu,\"records\":%lu,\"kept\":%lu,"
        "\"lan\":%lu,\"dropped\":%lu,\"no_template\":%lu,\"templates\":%lu,\"unusable\":%lu,\"bad\":%lu,"
        "\"devices\":%d,\"last\":%lu}",
        s_ring ? "true" : "false", router_flow_state_key(state()), ROUTER_IPFIX_PORT, ROUTER_IPFIX_RATE,
        (unsigned long)s_rx, (unsigned long)s_rx_drop, (unsigned long)s_rx_cut, (unsigned long)s_st.datagrams,
        (unsigned long)s_st.v10, (unsigned long)s_st.v9, (unsigned long)s_st.records, (unsigned long)s_st.kept,
        (unsigned long)s_st.lan, (unsigned long)s_st.dropped, (unsigned long)s_st.no_template,
        (unsigned long)s_st.templates, (unsigned long)s_st.unusable, (unsigned long)s_st.bad, devices,
        (unsigned long)s_st.last);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}
