// MikroTik decoys: raw TCP listeners, datagram ring, whitelist and bounded readers. See mt_decoy.h.
//
// Everything parsed here comes from the network and is hostile: every length
// is checked against the bytes received before it is read, and only printable
// ASCII is copied out.

#include "mt_decoy.h"
#include "tripwire.h"           // TRIPWIRE_MNDP_PORT, TRIPWIRE_MACTELNET_PORT, TRIPWIRE_MT_WHITELIST
#include "wifi_manager.h"
#include "detect.h"             // detect_note_logged()
#include "mikrotik.h"           // main/admin: mikrotik_own_mac(), the router's interface MACs
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <ctype.h>
#include <string.h>

static const char *TAG = "MIKROTIK";

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

// Printable ASCII only; double quotes and backslashes become '?'. Stops at a NUL.
static void copy_text(char *out, size_t cap, const uint8_t *s, size_t n)
{
    size_t o = 0;
    if (!cap) return;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        uint8_t c = s[i];
        if (c == 0) break;
        out[o++] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '?';
    }
    out[o] = '\0';
}

// ── Raw TCP decoys (tcpip thread) ─────────────────────────────────────────────

// Every callback here runs on the tcpip thread, so each one does constant,
// bounded work: no logging, no allocation, no blocking lock, no flash.

static const uint16_t TCP_PORT[MT_TCP_N] = {
    [MT_TCP_WINBOX] = TRIPWIRE_LISTEN(TRIPWIRE_WINBOX_PORT),
    [MT_TCP_API]    = TRIPWIRE_LISTEN(TRIPWIRE_ROSAPI_PORT),
    [MT_TCP_BTEST]  = TRIPWIRE_LISTEN(TRIPWIRE_BTEST_PORT),
};

// The bandwidth-test server's hello (btest-opensource's protocol notes).
static const uint8_t BTEST_HELLO[] = { 0x01, 0x00, 0x00, 0x00 };

typedef struct {
    uint32_t ip;
    uint32_t total;
    uint16_t port;
    uint8_t  kind;
    uint8_t  n;
    uint8_t  polls;
    uint8_t  got_at;            // polls when the first data came
    bool     got;
    bool     used;
    uint8_t  buf[TRIPWIRE_RX_MAX];
} conn_t;
_Static_assert(TRIPWIRE_RX_MAX <= 255, "conn_t.n is a uint8_t");

static conn_t            s_conn[MT_RAW_CONN_MAX];  // tcpip thread only
static mt_tcp_result_t   s_res;                    // tcpip thread only: built, posted, zeroed
static QueueHandle_t     s_tcpq;
static SemaphoreHandle_t s_setup_done;
static bool              s_listening[MT_TCP_N];
static volatile uint32_t s_tcp_drop, s_tcp_refused, s_udp_drop;

// Post the connection's result and free its slot; the bytes are zeroed.
static void conn_end(conn_t *c)
{
    memset(&s_res, 0, sizeof(s_res));
    s_res.ip    = c->ip;
    s_res.total = c->total;
    s_res.port  = c->port;
    s_res.kind  = c->kind;
    s_res.n     = c->n;
    if (c->kind == MT_TCP_API)      // command and user name only, never the bytes
        s_res.api_ok = mikrotik_api_parse(c->buf, c->n, s_res.api.cmd, sizeof(s_res.api.cmd),
                                          s_res.api.user, sizeof(s_res.api.user));
    else
        memcpy(s_res.data, c->buf, c->n);
    if (xQueueSend(s_tcpq, &s_res, 0) != pdTRUE) s_tcp_drop++;
    memset(&s_res, 0, sizeof(s_res));
    memset(c, 0, sizeof(*c));       // used = false
}

// End a connection whose pcb is still valid (recv or poll callback).
static err_t conn_close(conn_t *c, struct tcp_pcb *pcb)
{
    conn_end(c);
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    return ERR_OK;
}

static err_t recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    conn_t *c = (conn_t *)arg;
    if (!p) {                                   // the client closed
        if (!c) return ERR_OK;
        return conn_close(c, pcb);
    }
    if (!c || err != ERR_OK) {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }
    size_t room = sizeof(c->buf) - c->n;
    size_t take = p->tot_len < room ? p->tot_len : room;
    if (take) c->n += (uint8_t)pbuf_copy_partial(p, c->buf + c->n, (u16_t)take, 0);
    uint32_t t = c->total + p->tot_len;
    c->total = t > TRIPWIRE_FRAME_MAX ? TRIPWIRE_FRAME_MAX + 1 : t;
    if (!c->got) { c->got = true; c->got_at = c->polls; }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    // Winbox counts its first burst until the next poll; the others stop at a full buffer.
    if (c->total > TRIPWIRE_FRAME_MAX || (c->kind != MT_TCP_WINBOX && c->n == sizeof(c->buf)))
        return conn_close(c, pcb);
    return ERR_OK;
}

static err_t poll_cb(void *arg, struct tcp_pcb *pcb)
{
    conn_t *c = (conn_t *)arg;
    if (!c) {                                   // not ours any more: legal here
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    c->polls++;
    if ((c->got && c->polls > c->got_at) || (!c->got && c->polls >= MT_NODATA_POLLS) ||
        c->polls >= MT_CONN_POLLS)
        return conn_close(c, pcb);
    return ERR_OK;
}

// The pcb is already gone: post what we have and never touch it.
static void err_cb(void *arg, err_t err)
{
    (void)err;
    conn_t *c = (conn_t *)arg;
    if (c) conn_end(c);
}

static err_t accept_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    if (err != ERR_OK || !pcb) return ERR_VAL;
    conn_t *c = NULL;
    for (int i = 0; i < MT_RAW_CONN_MAX; i++)
        if (!s_conn[i].used) { c = &s_conn[i]; break; }
    if (!c || !IP_IS_V4_VAL(pcb->remote_ip)) {
        s_tcp_refused++;
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    memset(c, 0, sizeof(*c));
    c->used = true;
    c->kind = (uint8_t)(uintptr_t)arg;
    c->ip   = ip4_addr_get_u32(ip_2_ip4(&pcb->remote_ip));
    c->port = pcb->local_port;
    tcp_arg(pcb, c);
    tcp_recv(pcb, recv_cb);
    tcp_err(pcb, err_cb);
    tcp_poll(pcb, poll_cb, MT_POLL_TICKS);
    if (c->kind == MT_TCP_BTEST &&                              // the only bytes any decoy sends
        tcp_write(pcb, BTEST_HELLO, sizeof(BTEST_HELLO), TCP_WRITE_FLAG_COPY) == ERR_OK)
        tcp_output(pcb);
    detect_note_logged(c->ip, c->port);                         // queue post, 0 timeout
    return ERR_OK;
}

static void setup_cb(void *ctx)
{
    (void)ctx;
    for (int k = 0; k < MT_TCP_N; k++) {
        if (!TCP_PORT[k]) continue;
        struct tcp_pcb *p = tcp_new_ip_type(IPADDR_TYPE_V4);
        if (!p) continue;
        ip_set_option(p, SOF_REUSEADDR);
        if (tcp_bind(p, IP4_ADDR_ANY, TCP_PORT[k]) != ERR_OK) { tcp_close(p); continue; }
        struct tcp_pcb *l = tcp_listen_with_backlog(p, TRIPWIRE_BACKLOG);
        if (!l) { tcp_close(p); continue; }                    // p is kept on failure
        tcp_arg(l, (void *)(uintptr_t)k);
        tcp_accept(l, accept_cb);
        s_listening[k] = true;
    }
    xSemaphoreGive(s_setup_done);
}

bool mikrotik_tcp_listening(mt_tcp_kind_t k)
{
    return (unsigned)k < MT_TCP_N && s_listening[k];
}

bool mikrotik_tcp_next(mt_tcp_result_t *out)
{
    return s_tcpq && xQueueReceive(s_tcpq, out, 0) == pdTRUE;
}

void mikrotik_counters(uint32_t *tcp_drop, uint32_t *tcp_refused, uint32_t *udp_drop)
{
    if (tcp_drop)    *tcp_drop = s_tcp_drop;
    if (tcp_refused) *tcp_refused = s_tcp_refused;
    if (udp_drop)    *udp_drop = s_udp_drop;
}

// ── Datagram ring (Wi-Fi RX task to tripwire task) ────────────────────────────

static mt_dgram_t *s_ring;                     // PSRAM, MT_UDP_SLOTS
static uint32_t    s_rhead, s_rtail;           // one producer, one consumer

bool mikrotik_udp_on(void)
{
    return s_ring && (TRIPWIRE_LISTEN(TRIPWIRE_MNDP_PORT) || TRIPWIRE_LISTEN(TRIPWIRE_MACTELNET_PORT));
}

void mikrotik_frame_tap(const uint8_t *f, size_t len, uint32_t our_ip, uint32_t netmask)
{
    const uint16_t p1 = TRIPWIRE_LISTEN(TRIPWIRE_MNDP_PORT), p2 = TRIPWIRE_LISTEN(TRIPWIRE_MACTELNET_PORT);
    mt_dgram_t *ring = __atomic_load_n(&s_ring, __ATOMIC_ACQUIRE);
    if ((!p1 && !p2) || !ring || !f || len < 14 + 20 + 8) return;
    if (f[12] != 0x08 || f[13] != 0x00 || (f[6] & 0x01)) return;   // IPv4, unicast source MAC
    const uint8_t *ip = f + 14;
    unsigned hl = (ip[0] & 0x0fu) * 4u;
    if ((ip[0] >> 4) != 4 || hl < 20 || 14 + hl + 8 > len || ip[9] != 17) return;
    if (rd16(ip + 6) & 0x3fff) return;                              // any fragment
    const uint8_t *udp = ip + hl;
    uint16_t dport = rd16(udp + 2);
    if (dport != p1 && dport != p2) return;
    uint32_t dst;
    memcpy(&dst, ip + 16, 4);
    bool for_us = (our_ip && dst == our_ip) || dst == 0xffffffffu ||
                  (our_ip && netmask && netmask != 0xffffffffu && dst == (our_ip | ~netmask));
    if (!for_us) return;
    size_t tot = rd16(ip + 2), ulen = rd16(udp + 4);
    if (tot < hl + 8 || 14 + tot > len || ulen < 8 || ulen > tot - hl) return;
    uint32_t h = s_rhead, t = __atomic_load_n(&s_rtail, __ATOMIC_ACQUIRE);
    if (h - t >= MT_UDP_SLOTS) { s_udp_drop++; return; }
    mt_dgram_t *d = &ring[h % MT_UDP_SLOTS];
    size_t n = ulen - 8;
    d->full_len = (uint16_t)n;
    if (n > TRIPWIRE_UDP_RX_MAX) n = TRIPWIRE_UDP_RX_MAX;
    memcpy(&d->ip, ip + 12, 4);
    memcpy(d->mac, f + 6, 6);
    d->dport = dport;
    d->len = (uint16_t)n;
    memcpy(d->data, udp + 8, n);
    __atomic_store_n(&s_rhead, h + 1, __ATOMIC_RELEASE);
}

const mt_dgram_t *mikrotik_udp_peek(void)
{
    if (!s_ring) return NULL;
    uint32_t t = s_rtail, h = __atomic_load_n(&s_rhead, __ATOMIC_ACQUIRE);
    return t == h ? NULL : &s_ring[t % MT_UDP_SLOTS];
}

void mikrotik_udp_pop(void)
{
    uint32_t t = s_rtail, h = __atomic_load_n(&s_rhead, __ATOMIC_ACQUIRE);
    if (t != h) __atomic_store_n(&s_rtail, t + 1, __ATOMIC_RELEASE);
}

// ── Setup (tripwire task) ─────────────────────────────────────────────────────

bool mikrotik_init(void)
{
    s_tcpq = xQueueCreateWithCaps(MT_TCP_QDEPTH, sizeof(mt_tcp_result_t), MALLOC_CAP_SPIRAM);
    s_setup_done = xSemaphoreCreateBinary();
    mt_dgram_t *ring = heap_caps_calloc(MT_UDP_SLOTS, sizeof(mt_dgram_t), MALLOC_CAP_SPIRAM);
    if (ring) __atomic_store_n(&s_ring, ring, __ATOMIC_RELEASE);     // the frame tap starts now
    else ESP_LOGE(TAG, "No memory for the datagram ring, MNDP and MAC-Telnet off");
    bool tcp = TCP_PORT[MT_TCP_WINBOX] || TCP_PORT[MT_TCP_API] || TCP_PORT[MT_TCP_BTEST];
    if (tcp && s_tcpq && s_setup_done) {
        if (tcpip_callback(setup_cb, NULL) == ERR_OK)
            xSemaphoreTake(s_setup_done, pdMS_TO_TICKS(2000));
        else
            ESP_LOGE(TAG, "tcpip_callback failed, TCP decoys off");
    } else if (tcp) {
        ESP_LOGE(TAG, "No memory for the result queue, TCP decoys off");
    }
    for (int k = 0; k < MT_TCP_N; k++)
        if (TCP_PORT[k] && !s_listening[k])
            ESP_LOGE(TAG, "TCP decoy on port %u not listening", (unsigned)TCP_PORT[k]);
    ESP_LOGI(TAG, "Decoys: %u B datagram ring and %u B result queue in PSRAM, %u B connection pool, no sockets",
             (unsigned)(MT_UDP_SLOTS * sizeof(mt_dgram_t)), (unsigned)(MT_TCP_QDEPTH * sizeof(mt_tcp_result_t)),
             (unsigned)sizeof(s_conn));
    return ring || s_listening[MT_TCP_WINBOX] || s_listening[MT_TCP_API] || s_listening[MT_TCP_BTEST];
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

static uint8_t  s_wl[MT_WHITELIST_MAX][6];
static int      s_wl_n;
static uint8_t  s_gw_mac[6];
static bool     s_gw_ok;
static uint32_t s_gw_ms;

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)tolower((unsigned char)c);
    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

int mikrotik_whitelist_init(void)
{
    const char *s = TRIPWIRE_MT_WHITELIST;
    s_wl_n = 0;
    while (s && *s && s_wl_n < MT_WHITELIST_MAX) {
        while (*s && hexv(*s) < 0) s++;
        if (!*s) break;
        uint8_t m[6];
        int k = 0;
        while (k < 6 && hexv(s[0]) >= 0 && hexv(s[1]) >= 0) {
            m[k++] = (uint8_t)(hexv(s[0]) << 4 | hexv(s[1]));
            s += 2;
            if (k < 6) {
                if (*s != ':' && *s != '-') break;
                s++;
            }
        }
        if (k == 6 && (*s == '\0' || *s == ',' || *s == ';' || *s == ' ')) memcpy(s_wl[s_wl_n++], m, 6);
        else ESP_LOGW(TAG, "TRIPWIRE_MT_WHITELIST: an entry is not a MAC, skipped");
        while (*s && *s != ',' && *s != ';' && *s != ' ') s++;        // to the next entry
    }
    return s_wl_n;
}

static void gw_refresh(void)
{
    uint32_t t = now_ms();
    if (s_gw_ms && t - s_gw_ms < (s_gw_ok ? 60000u : 5000u)) return;
    s_gw_ms = t ? t : 1;
    uint32_t gw;
    uint8_t m[6];
    if (wifi_manager_get_gateway(&gw) && wifi_manager_lookup_mac(gw, m)) {
        if (!s_gw_ok || memcmp(m, s_gw_mac, 6)) {
            char ms[18];
            wifi_manager_format_mac(m, ms, sizeof(ms));
            ESP_LOGI(TAG, "Whitelist: gateway %s", ms);
        }
        memcpy(s_gw_mac, m, 6);
        s_gw_ok = true;
    }
}

bool mikrotik_gateway_mac(uint8_t mac[6])
{
    gw_refresh();
    if (s_gw_ok) memcpy(mac, s_gw_mac, 6);
    return s_gw_ok;
}

mt_wl_t mikrotik_whitelist_why(const uint8_t mac[6], uint32_t ip, bool mndp)
{
    static const uint8_t zero[6] = { 0 };
    gw_refresh();
    if (mac && memcmp(mac, zero, 6)) {
        if (s_gw_ok && !memcmp(mac, s_gw_mac, 6)) return MT_WL_GATEWAY;
        if (mikrotik_own_mac(mac)) return MT_WL_ROUTER;
        for (int i = 0; i < s_wl_n; i++)
            if (!memcmp(mac, s_wl[i], 6)) return MT_WL_CONFIG;
    }
    uint32_t gw;
    if (mndp && ip && wifi_manager_get_gateway(&gw) && gw == ip) return MT_WL_GATEWAY_IP;
    return MT_WL_NONE;
}

bool mikrotik_whitelist_ready(void)
{
    if (esp_timer_get_time() >= (int64_t)MT_WL_BOOT_HOLD_S * 1000000) return true;
    gw_refresh();
    return s_gw_ok && mikrotik_own_macs_state(NULL) != 0;      // -1 client off, 1 read
}

// ── RouterOS API ──────────────────────────────────────────────────────────────

// A word's length at b[*i] (MikroTik API manual: 1 to 5 bytes, high bits
// first). False on a reserved control byte (0xF8 and up) or a cut-off length.
static bool api_len(const uint8_t *b, size_t n, size_t *i, uint32_t *len)
{
    if (*i >= n) return false;
    uint8_t c = b[*i];
    size_t k;
    uint32_t v;
    if (c < 0x80)              { k = 1; v = c; }
    else if ((c & 0xc0) == 0x80) { k = 2; v = c & 0x3f; }
    else if ((c & 0xe0) == 0xc0) { k = 3; v = c & 0x1f; }
    else if ((c & 0xf0) == 0xe0) { k = 4; v = c & 0x0f; }
    else if (c == 0xf0)          { k = 5; v = 0; }
    else return false;
    if (n - *i < k) return false;
    for (size_t j = 1; j < k; j++) v = (v << 8) | b[*i + j];
    *i += k;
    *len = v;
    return true;
}

bool mikrotik_api_parse(const uint8_t *b, size_t n, char *cmd, size_t cmd_cap,
                        char *user, size_t user_cap)
{
    if (!cmd || !user || !cmd_cap || !user_cap) return false;
    cmd[0] = user[0] = '\0';
    if (!b) return false;
    size_t i = 0;
    for (int words = 0; words < MT_API_WORDS_MAX && i < n; words++) {
        uint32_t len;
        if (!api_len(b, n, &i, &len) || len == 0) break;       // a zero-length word ends the sentence
        size_t have = n - i;
        size_t take = len < have ? len : have;
        if (take == 0) break;
        const uint8_t *w = b + i;
        if (words == 0) {
            if (w[0] != '/') return false;                      // a sentence starts with its command
            copy_text(cmd, cmd_cap, w, take);
        } else if (!user[0] && take > 6 && !memcmp(w, "=name=", 6)) {
            copy_text(user, user_cap, w + 6, take - 6);
        }
        // Any other word (the password among them) is skipped, never copied.
        if (len > have) break;                                  // runs past what we read
        i += len;
    }
    return cmd[0] != '\0';
}

// ── Bandwidth test ────────────────────────────────────────────────────────────

bool mikrotik_btest_label(const uint8_t *b, size_t n, char *out, size_t cap)
{
    if (!out || !cap) return false;
    out[0] = '\0';
    if (!b || n < 2 || b[0] > 1 || b[1] < 1 || b[1] > 3) return false;
    static const char *const DIR[] = { "", "transmit", "receive", "both" };
    strlcpy(out, b[0] ? "TCP " : "UDP ", cap);
    strlcat(out, DIR[b[1]], cap);
    return true;
}

// ── MNDP ──────────────────────────────────────────────────────────────────────

mt_mndp_kind_t mikrotik_mndp_parse(const uint8_t *b, size_t n, mt_mndp_t *o)
{
    if (!o) return MT_MNDP_OTHER;
    memset(o, 0, sizeof(*o));
    if (!b || n < 4) return MT_MNDP_OTHER;
    if (n == 4) return MT_MNDP_SOLICIT;
    size_t i = 4;
    int recs = 0;
    while (recs < MT_MNDP_TLV_MAX && n - i >= 4) {
        uint16_t t = rd16(b + i), l = rd16(b + i + 2);
        i += 4;
        if (l > n - i) break;                                   // cut short: stop here
        const uint8_t *v = b + i;
        switch (t) {
        case 1:  if (l == 6) { memcpy(o->mac, v, 6); o->has_mac = true; } break;
        case 5:  copy_text(o->identity, sizeof(o->identity), v, l); break;
        case 7:  copy_text(o->version, sizeof(o->version), v, l); break;
        case 8:  if (!o->board[0]) copy_text(o->board, sizeof(o->board), v, l); break;   // platform
        case 12: copy_text(o->board, sizeof(o->board), v, l); break;                    // board wins
        default: break;
        }
        i += l;
        recs++;
    }
    return recs ? MT_MNDP_ANNOUNCE : MT_MNDP_OTHER;
}

// ── MAC-Telnet ────────────────────────────────────────────────────────────────

bool mikrotik_mactelnet_parse(const uint8_t *b, size_t n, mt_mactelnet_t *o)
{
    if (!o) return false;
    memset(o, 0, sizeof(*o));
    if (!b || n < MT_MACTELNET_HDR || b[0] != 1) return false;   // version 1
    uint8_t t = b[1];
    if (t != 0 && t != 1 && t != 2 && t != 4 && t != 5 && t != 255) return false;
    o->ptype = t;
    memcpy(o->src, b + 2, 6);
    memcpy(o->dst, b + 8, 6);
    return true;
}

const char *mikrotik_mactelnet_ptype(uint8_t t)
{
    switch (t) {
    case 0:   return "session start";
    case 1:   return "data";
    case 2:   return "ack";
    case 4:   return "ping";
    case 5:   return "pong";
    case 255: return "session end";
    default:  return "packet";
    }
}
