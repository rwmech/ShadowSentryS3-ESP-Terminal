// Recon detection: port scans, probes, ARP sweeps, admin-port stealth. See detect.h.
//
// Everything parsed here comes off the network and is hostile: every length
// and offset is checked against the pbuf before it is read.

#include "detect.h"
#include "ignore.h"
#include "discovery.h"            // discovery_frame_tap(): source MACs and mDNS queries for discovery
#include "settings.h"
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "trap_listen.h"            // TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT
#include "http_engine.h"            // HTTP_ENG_PORT1..3 (0 when the engine is off)
#include "tripwire.h"               // TRIPWIRE_*_PORT, TRIPWIRE_LISTEN (0 when tripwires are off)
#include "mt_decoy.h"               // mikrotik_frame_tap(): datagrams for the MNDP and MAC-Telnet decoys
#include "ss_lwip_hooks.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "lwip/ip4_addr.h"
#include "lwip/def.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static const char *TAG = "DETECT";

#define DET_QUEUE_DEPTH   128
#define DET_TASK_STACK    4096
#define DET_TASK_PRIO     2
#define TICK_MS           100       // housekeeping and console poll period

#define SRC_MAX           32        // sources tracked for port scans
#define RING              32        // distinct (port, proto) remembered per source
#define SCAN_SLOTS        4         // concurrent scans with an exact port bitmap
#define ARP_SRC_MAX       16        // MACs tracked for ARP sweeps
#define SWEEP_SLOTS       2         // concurrent sweeps with an exact target bitmap
#define BITMAP_BYTES      8192      // 65536 bits: a port, or the low 16 bits of an IPv4
#define QUIET_MS          60000     // a scan or sweep ends after this much silence
#define PROBE_HOLD_MS     1500      // a probe waits this long for a scan to fold it into
#define PROBE_HOLD_LOGGED_MS 6000   // ports whose service logs each connection: wait for it
#define PROBE_REPEAT_MS   60000     // one probe event per source, port and minute
#define PROBE_PEND_MAX    16
#define PROBE_SEEN_MAX    64
#define SAMPLE_MAX        6
#define TRAP_N            21        // fits the uint32_t traps bitmap

// ── Messages, hook and ARP tap to the detector task ───────────────────────────

enum { M_TCP = 1, M_UDP = 2, M_ARP = 3, M_LOGGED = 4 };
#define MF_SYN         0x01
#define MF_ADMIN_DROP  0x02

typedef struct {
    uint8_t  kind, flags;
    uint16_t port;          // destination port, host order
    uint32_t ip;            // source IPv4 (ARP: sender), network order
    uint32_t ip2;           // ARP: target IPv4, network order
    uint8_t  mac[6];        // ARP: sender MAC
    uint8_t  _pad[2];
} det_msg_t;

static QueueHandle_t s_q;

static volatile uint32_t s_st_queued, s_st_dropped, s_st_admin, s_st_arp;
static volatile uint32_t s_st_scans, s_st_probes, s_st_sweeps;
static volatile bool     s_tap_on;

// Admin allowlist copy for the hook. Written on a settings save (admin task)
// or the console command; read per admin-port SYN on the tcpip task.
static portMUX_TYPE s_allow_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t     s_allow[SETTINGS_ADMIN_ALLOW_MAX];
static int          s_allow_n;

static inline uint16_t rd16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }

static inline bool unicast_ip(uint32_t ip_net)
{
    uint8_t b0 = (uint8_t)(ip_net & 0xff);              // first octet, network order
    return ip_net != 0 && ip_net != 0xFFFFFFFFu && b0 != 127 && b0 < 224;
}

static bool admin_allowed(uint32_t ip)
{
    bool ok = true;
    portENTER_CRITICAL(&s_allow_mux);
    if (s_allow_n) {
        ok = false;
        for (int i = 0; i < s_allow_n; i++) if (s_allow[i] == ip) ok = true;
    }
    portEXIT_CRITICAL(&s_allow_mux);
    return ok;
}

static void allow_reload(void)
{
    const settings_t *st = settings_get();
    uint32_t tmp[SETTINGS_ADMIN_ALLOW_MAX];
    int n = st->admin_allow_n;
    if (n < 0 || n > SETTINGS_ADMIN_ALLOW_MAX) n = 0;
    memcpy(tmp, st->admin_allow, sizeof(tmp));
    portENTER_CRITICAL(&s_allow_mux);
    memcpy(s_allow, tmp, sizeof(s_allow));
    s_allow_n = n;
    portEXIT_CRITICAL(&s_allow_mux);
}

static inline void post(const det_msg_t *m)
{
    if (xQueueSend(s_q, m, 0) == pdTRUE) s_st_queued++;
    else s_st_dropped++;
}

#define TCPF_SYN 0x02
#define TCPF_RST 0x04
#define TCPF_ACK 0x10

// lwIP IPv4 input hook (ss_lwip_hooks.h). tcpip task, every inbound IPv4
// packet, before lwIP has checked the header: bounded parse, one queue send.
// Debug (POST /api/debug/hooks): true makes the IPv4 hook and the ARP tap pass
// everything straight on, to split network latency.
static volatile bool s_hooks_off;

void detect_debug_hooks(bool on)
{
    s_hooks_off = !on;
    ESP_LOGW(TAG, "IPv4 hook and ARP tap %s (debug)", on ? "on" : "bypassed");
}

int ss_ip4_input_hook(struct pbuf *p, struct netif *inp)
{
    if (s_hooks_off) return 0;
    if (!s_q || !p || !inp || !p->payload || p->len < 20) return 0;
    const uint8_t *b = (const uint8_t *)p->payload;
    unsigned hl  = (b[0] & 0x0fu) * 4u;
    unsigned tot = rd16(b + 2);
    if (hl < 20 || hl > p->len || tot < hl || tot > p->tot_len) return 0;
    if (rd16(b + 6) & 0x1fff) return 0;                 // later fragment: no L4 header

    uint32_t src, dst;
    memcpy(&src, b + 12, 4);
    memcpy(&dst, b + 16, 4);
    uint32_t me = ip4_addr_get_u32(netif_ip4_addr(inp));
    if (!me || dst != me || src == me || !unicast_ip(src)) return 0;

    unsigned avail = (tot < p->len ? tot : p->len) - hl;     // L4 bytes in this pbuf
    const uint8_t *l4 = b + hl;
    det_msg_t m = { .ip = src };

    if (b[9] == 6) {                                    // TCP
        if (avail < 14) return 0;
        uint8_t fl = l4[13];
        if (fl & (TCPF_ACK | TCPF_RST)) return 0;       // replies, our own sessions, resets
        m.kind = M_TCP;
        m.port = rd16(l4 + 2);
        if (fl & TCPF_SYN) m.flags |= MF_SYN;
        if ((fl & TCPF_SYN) && (m.port == ADMIN_PORT || m.port == ADMIN_WS_PORT) &&
            !admin_allowed(src)) {
            m.flags |= MF_ADMIN_DROP;
            s_st_admin++;
            post(&m);
            pbuf_free(p);
            return 1;                                   // eaten: no SYN-ACK, no RST
        }
    } else if (b[9] == 17) {                            // UDP
        if (avail < 4) return 0;
        uint16_t sport = rd16(l4);
        if (sport == 53 || sport == 67 || sport == 123 || sport == 5353) return 0;
        m.kind = M_UDP;
        m.port = rd16(l4 + 2);
    } else {
        return 0;
    }
    if (src == ip4_addr_get_u32(netif_ip4_gw(inp))) return 0;
    post(&m);
    return 0;
}

// Station netif input wrapper (Wi-Fi RX task): peek at ARP requests, hand every
// frame to the discovery tap (source MACs) and the MikroTik decoy tap (MNDP and
// MAC-Telnet datagrams), pass all on.
static netif_input_fn s_orig_input;

static err_t arp_tap_input(struct pbuf *p, struct netif *inp)
{
    if (s_hooks_off) return s_orig_input(p, inp);
    if (p && p->payload && inp) {
        discovery_frame_tap((const uint8_t *)p->payload, p->len, ip4_addr_get_u32(netif_ip4_addr(inp)));
        mikrotik_frame_tap((const uint8_t *)p->payload, p->len, ip4_addr_get_u32(netif_ip4_addr(inp)),
                           ip4_addr_get_u32(netif_ip4_netmask(inp)));
    }
    if (s_q && p && p->payload && p->len >= 42) {
        const uint8_t *f = (const uint8_t *)p->payload;
        static const uint8_t REQ[8] = { 0, 1, 8, 0, 6, 4, 0, 1 };   // Ethernet, IPv4, who-has
        if (f[12] == 0x08 && f[13] == 0x06 && !memcmp(f + 14, REQ, sizeof(REQ))) {
            const uint8_t *a = f + 14;
            det_msg_t m = { .kind = M_ARP };
            memcpy(m.mac, a + 8, 6);
            memcpy(&m.ip, a + 14, 4);
            memcpy(&m.ip2, a + 24, 4);
            uint32_t me = ip4_addr_get_u32(netif_ip4_addr(inp));
            if (m.ip != m.ip2 && (m.ip == 0 || m.ip != me) &&
                memcmp(m.mac, inp->hwaddr, 6) != 0) {     // gratuitous, or our own
                s_st_arp++;
                post(&m);
            }
        }
    }
    return s_orig_input(p, inp);
}

// tcpip task. esp_netif sets netif->input to tcpip_input at netif_add(), so
// a netif that is removed and added again loses the wrapper; arp_tap_check()
// puts it back.
static void arp_tap_install_cb(void *arg)
{
    struct netif *n = (struct netif *)arg;
    if (n->input && n->input != arp_tap_input) {
        s_orig_input = n->input;
        n->input = arp_tap_input;
        ESP_LOGI(TAG, "ARP tap installed on the station interface");
    }
    s_tap_on = n->input == arp_tap_input;
}

static void arp_tap_check(void)
{
    esp_netif_t *en = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    struct netif *n = en ? (struct netif *)esp_netif_get_netif_impl(en) : NULL;
    if (!n) return;
    if (n->input == arp_tap_input) { s_tap_on = true; return; }
    s_tap_on = false;
    if (n->input) tcpip_callback(arp_tap_install_cb, n);
}

// ── Detector state (PSRAM, detector task only) ────────────────────────────────

typedef struct { uint16_t port; uint8_t proto; uint8_t used; uint32_t t; } pk_t;

typedef struct {
    bool     used, scanning;
    int8_t   slot;              // bitmap index, -1 = none (counts from the ring)
    uint8_t  head;
    uint8_t  protos;            // bit 0 TCP, bit 1 UDP
    uint32_t traps;             // bit per trap port hit during the scan
    uint8_t  ns;
    uint32_t ip, last;
    uint32_t start, scan_last, total, admin_drops;
    uint16_t lo, hi;
    uint16_t sample[SAMPLE_MAX];
    pk_t     ring[RING];
} src_t;

typedef struct { uint32_t t; uint32_t tip; uint8_t used; } arpk_t;

typedef struct {
    bool     used, sweeping;
    int8_t   slot;
    uint8_t  head;
    uint8_t  mac[6];
    uint32_t ip, last;
    uint32_t start, sweep_last, total;
    uint32_t lo, hi;            // target IPv4, host order
    arpk_t   ring[RING];
} asrc_t;

typedef struct { uint32_t ip; uint16_t port; uint8_t used; uint32_t due; } probe_t;
typedef struct { uint32_t ip; uint16_t port; uint8_t used; uint32_t t; } seen_t;

typedef struct {
    src_t   src[SRC_MAX];
    asrc_t  asrc[ARP_SRC_MAX];
    probe_t pend[PROBE_PEND_MAX];
    seen_t  seen[PROBE_SEEN_MAX];
    bool    bit_used[SCAN_SLOTS + SWEEP_SLOTS];
    uint8_t bits[SCAN_SLOTS + SWEEP_SLOTS][BITMAP_BYTES];
} det_state_t;

static det_state_t *S;
static uint8_t      s_gw_mac[6];
static uint32_t     s_gw_ip;

// A 0 entry is a disabled port (trap_listen.h) and never matches.
#define TRAP_STR_(x)  #x
#define TRAP_STR(x)   TRAP_STR_(x)
static const uint16_t    TRAP_PORT[TRAP_N] = { FTP_PORT, SSH_PORT, TELNET_PORT, HTTP_PORT, RTSP_PORT,
                                               TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT,
                                               HTTP_ENG_PORT1, HTTP_ENG_PORT2, HTTP_ENG_PORT3,
                                               TRIPWIRE_LISTEN(TRIPWIRE_RDP_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_VNC_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_SMB_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_REDIS_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_MYSQL_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_MSSQL_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_JETDIRECT_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_WINBOX_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_ROSAPI_PORT),
                                               TRIPWIRE_LISTEN(TRIPWIRE_BTEST_PORT) };
static const char *const TRAP_NAME[TRAP_N] = { "FTP", "SSH", "Telnet", "HTTP", "RTSP",
                                               "Telnet alt", "SSH alt", "ADB",
                                               "HTTP " TRAP_STR(HTTP_ALT_PORT1),
                                               "HTTP " TRAP_STR(HTTP_ALT_PORT2),
                                               "HTTP " TRAP_STR(HTTP_ALT_PORT3),
                                               "RDP", "VNC", "SMB", "Redis", "MySQL", "MSSQL", "JetDirect",
                                               "Winbox", "RouterOS-API", "btest" };
_Static_assert(TRAP_N <= 32, "src_t.traps is a uint32_t bitmap");
// Services that log every connection they take (the HTTP engine, ADB, the
// tripwires) call detect_note_logged(): a probe held for that source and port
// is dropped, so one connection is one event. Their probes wait
// PROBE_HOLD_LOGGED_MS (the engine's 5 s idle, the tripwire's 5 s), so a SYN
// that never became a logged connection still raises its probe. FTP, SSH,
// Telnet and RTSP log late or not at all before credentials: their probes stay.
static const bool TRAP_LOGS[TRAP_N] = { false, false, false, HTTP_ENGINE_ENABLE, false,
                                        false, false, true,
                                        true, true, true,
                                        true, true, true, true, true, true, true,
                                        true, true, true };

static inline uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static int trap_index(uint16_t port)
{
    for (int i = 0; i < TRAP_N; i++) if (TRAP_PORT[i] && TRAP_PORT[i] == port) return i;
    return -1;
}

static int bits_alloc(int first, int count)
{
    for (int i = first; i < first + count; i++) {
        if (!S->bit_used[i]) {
            S->bit_used[i] = true;
            memset(S->bits[i], 0, BITMAP_BYTES);
            return i;
        }
    }
    return -1;
}

static void bits_free(int8_t *slot)
{
    if (*slot >= 0) S->bit_used[*slot] = false;
    *slot = -1;
}

// Set bit v in slot; true if it was clear.
static bool bits_set(int slot, uint16_t v)
{
    uint8_t *byte = &S->bits[slot][v >> 3], m = (uint8_t)(1u << (v & 7));
    if (*byte & m) return false;
    *byte |= m;
    return true;
}

static const char *proto_str(uint8_t protos)
{
    return protos == 3 ? "TCP+UDP" : protos == 2 ? "UDP" : "TCP";
}

static void fmt_ip(uint32_t ip_net, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip_net };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

// One event into the log store (flash ring, microSD, dashboard, panel, alarm).
// The alarm and Telegram decide on the alert mask and the ignore list.
static void emit(attack_type_t type, uint32_t ip, const uint8_t *mac, bool alert,
                 const char *fmt, ...) __attribute__((format(printf, 5, 6)));
static void emit(attack_type_t type, uint32_t ip, const uint8_t *mac, bool alert,
                 const char *fmt, ...)
{
    attack_log_t e = { .timestamp = (uint32_t)time(NULL), .src_ip = ip, .type = type };
    if (mac) memcpy(e.src_mac, mac, 6);
    else if (ip) wifi_manager_lookup_mac(ip, e.src_mac);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e.payload, sizeof(e.payload), fmt, ap);
    va_end(ap);
    char ips[16];
    fmt_ip(ip, ips, sizeof(ips));
    ESP_LOGW(TAG, "%s: %s", ips, e.payload);
    log_store_append(&e);
    if (alert) telegram_notify(&e);
}

// ── Port scans and probes ─────────────────────────────────────────────────────

static src_t *src_get(uint32_t ip, uint32_t now)
{
    src_t *freeslot = NULL, *lru = NULL, *lru_idle = NULL;
    for (int i = 0; i < SRC_MAX; i++) {
        src_t *s = &S->src[i];
        if (s->used && s->ip == ip) return s;
        if (!s->used) { if (!freeslot) freeslot = s; continue; }
        if (!lru || now - s->last > now - lru->last) lru = s;
        if (!s->scanning && (!lru_idle || now - s->last > now - lru_idle->last)) lru_idle = s;
    }
    src_t *s = freeslot ? freeslot : lru_idle ? lru_idle : lru;
    if (s->used && s->scanning) bits_free(&s->slot);    // all 32 scanning: drop the stalest
    memset(s, 0, sizeof(*s));
    s->used = true;
    s->ip   = ip;
    s->slot = -1;
    return s;
}

// Remember (port, proto); true if it was not in the ring.
static bool ring_touch(src_t *s, uint16_t port, uint8_t proto, uint32_t now)
{
    for (int i = 0; i < RING; i++) {
        pk_t *k = &s->ring[i];
        if (k->used && k->port == port && k->proto == proto) { k->t = now; return false; }
    }
    s->ring[s->head] = (pk_t){ .port = port, .proto = proto, .used = 1, .t = now };
    s->head = (uint8_t)((s->head + 1) % RING);
    return true;
}

static void scan_count_port(src_t *s, uint16_t port, uint8_t proto, bool fresh)
{
    bool is_new = s->slot >= 0 ? bits_set(s->slot, port) : fresh;
    s->protos |= proto == M_UDP ? 2 : 1;
    if (!is_new) return;
    s->total++;
    if (s->total == 1 || port < s->lo) s->lo = port;
    if (s->total == 1 || port > s->hi) s->hi = port;
    if (s->ns < SAMPLE_MAX) s->sample[s->ns++] = port;
}

static void sample_str(const src_t *s, char *buf, size_t len)
{
    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < s->ns && o < len; i++) {
        int n = snprintf(buf + o, len - o, "%s%u", i ? " " : "", (unsigned)s->sample[i]);
        if (n < 0) break;
        o += (size_t)n;
    }
}

static void traps_str(uint32_t traps, char *buf, size_t len)
{
    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < TRAP_N && o < len; i++) {
        if (!(traps & (1u << i))) continue;
        int n = snprintf(buf + o, len - o, " %s", TRAP_NAME[i]);
        if (n < 0) break;
        o += (size_t)n;
    }
}

static void scan_start(src_t *s, uint32_t now, uint32_t win_ms, unsigned distinct)
{
    s->scanning = true;
    s->start = s->scan_last = now;
    s->total = 0;
    s->ns = 0;
    s->protos = 0;
    s->slot = (int8_t)bits_alloc(0, SCAN_SLOTS);
    for (int i = 0; i < RING; i++) {
        const pk_t *k = &s->ring[i];
        if (k->used && now - k->t <= win_ms) scan_count_port(s, k->port, k->proto, true);
    }
    // Probes still held for this source are part of the scan.
    for (int i = 0; i < PROBE_PEND_MAX; i++) {
        probe_t *p = &S->pend[i];
        if (!p->used || p->ip != s->ip) continue;
        int t = trap_index(p->port);
        if (t >= 0) s->traps |= 1u << t;
        p->used = 0;
    }
    char smp[48];
    sample_str(s, smp, sizeof(smp));
    s_st_scans++;
    emit(ATTACK_SCAN, s->ip, NULL, true, "Port scan: %u ports in %lu s (%s), %u-%u, e.g. %s%s",
         distinct, (unsigned long)settings_get()->scan_window_s, proto_str(s->protos),
         (unsigned)s->lo, (unsigned)s->hi, smp, s->admin_drops ? ", admin ports hidden" : "");
}

static void scan_end(src_t *s)
{
    char traps[96];
    traps_str(s->traps, traps, sizeof(traps));
    unsigned long secs = (unsigned long)((s->scan_last - s->start) / 1000);
    emit(ATTACK_SCAN, s->ip, NULL, false, "Scan ended: %lu ports total (%s), %u-%u, %lu s%s%s",
         (unsigned long)s->total, proto_str(s->protos), (unsigned)s->lo, (unsigned)s->hi, secs,
         traps[0] ? "; traps hit" : "", traps);
    bits_free(&s->slot);
    s->scanning = false;
    s->traps = 0;
    s->admin_drops = 0;
    memset(s->ring, 0, sizeof(s->ring));
}

static void probe_hold(uint32_t ip, uint16_t port, uint32_t now)
{
    for (int i = 0; i < PROBE_SEEN_MAX; i++) {          // one per source, port and minute
        const seen_t *k = &S->seen[i];
        if (k->used && k->ip == ip && k->port == port && now - k->t < PROBE_REPEAT_MS) return;
    }
    probe_t *slot = NULL;
    for (int i = 0; i < PROBE_PEND_MAX; i++) {
        probe_t *p = &S->pend[i];
        if (p->used && p->ip == ip && p->port == port) return;
        if (!p->used && !slot) slot = p;
    }
    if (!slot) return;                                  // 16 held already: a scan, surely
    int t = trap_index(port);
    uint32_t hold = (t >= 0 && TRAP_LOGS[t]) ? PROBE_HOLD_LOGGED_MS : PROBE_HOLD_MS;
    *slot = (probe_t){ .ip = ip, .port = port, .used = 1, .due = now + hold };
}

// seen[] slot for a new entry: a free one, else the oldest.
static seen_t *seen_slot(uint32_t now)
{
    seen_t *slot = &S->seen[0];
    for (int k = 0; k < PROBE_SEEN_MAX; k++) {
        seen_t *x = &S->seen[k];
        if (!x->used) return x;
        if (now - x->t > now - slot->t) slot = x;
    }
    return slot;
}

// A service logged this connection: no probe for it, nor for that source and
// port for the next minute (each of those connections it logs too).
static void on_logged(const det_msg_t *m, uint32_t now)
{
    for (int i = 0; i < PROBE_PEND_MAX; i++) {
        probe_t *p = &S->pend[i];
        if (p->used && p->ip == m->ip && p->port == m->port) p->used = 0;
    }
    for (int k = 0; k < PROBE_SEEN_MAX; k++) {
        seen_t *x = &S->seen[k];
        if (x->used && x->ip == m->ip && x->port == m->port) { x->t = now; return; }
    }
    *seen_slot(now) = (seen_t){ .ip = m->ip, .port = m->port, .used = 1, .t = now };
}

void detect_note_logged(uint32_t ip, uint16_t port)
{
    if (!s_q || !ip) return;
    det_msg_t m = { .kind = M_LOGGED, .port = port, .ip = ip };
    post(&m);
}

static void probe_emit_due(uint32_t now)
{
    for (int i = 0; i < PROBE_PEND_MAX; i++) {
        probe_t *p = &S->pend[i];
        if (!p->used || (int32_t)(now - p->due) < 0) continue;
        p->used = 0;
        *seen_slot(now) = (seen_t){ .ip = p->ip, .port = p->port, .used = 1, .t = now };
        int t = trap_index(p->port);
        s_st_probes++;
        emit(ATTACK_PROBE, p->ip, NULL, true, "Probe: TCP SYN to port %u (%s)",
             (unsigned)p->port, t >= 0 ? TRAP_NAME[t] : "?");
    }
}

static void on_port(const det_msg_t *m, uint32_t now)
{
    const settings_t *st = settings_get();
    uint32_t win_ms = st->scan_window_s * 1000u;
    src_t *s = src_get(m->ip, now);
    s->last = now;
    if (m->flags & MF_ADMIN_DROP) s->admin_drops++;
    int trap = (m->kind == M_TCP && (m->flags & MF_SYN)) ? trap_index(m->port) : -1;

    if (s->scanning) {
        s->scan_last = now;
        bool fresh = s->slot < 0 && ring_touch(s, m->port, m->kind, now);
        scan_count_port(s, m->port, m->kind, fresh);
        if (trap >= 0) s->traps |= 1u << trap;
        return;
    }
    ring_touch(s, m->port, m->kind, now);
    if (trap >= 0) probe_hold(m->ip, m->port, now);

    unsigned distinct = 0;
    for (int i = 0; i < RING; i++)
        if (s->ring[i].used && now - s->ring[i].t <= win_ms) distinct++;
    if (distinct >= st->scan_ports) scan_start(s, now, win_ms, distinct);
}

// ── ARP sweeps ────────────────────────────────────────────────────────────────

static asrc_t *asrc_get(const uint8_t mac[6], uint32_t now)
{
    asrc_t *freeslot = NULL, *lru = NULL, *lru_idle = NULL;
    for (int i = 0; i < ARP_SRC_MAX; i++) {
        asrc_t *a = &S->asrc[i];
        if (a->used && !memcmp(a->mac, mac, 6)) return a;
        if (!a->used) { if (!freeslot) freeslot = a; continue; }
        if (!lru || now - a->last > now - lru->last) lru = a;
        if (!a->sweeping && (!lru_idle || now - a->last > now - lru_idle->last)) lru_idle = a;
    }
    asrc_t *a = freeslot ? freeslot : lru_idle ? lru_idle : lru;
    if (a->used && a->sweeping) bits_free(&a->slot);
    memset(a, 0, sizeof(*a));
    a->used = true;
    memcpy(a->mac, mac, 6);
    a->slot = -1;
    return a;
}

static bool aring_touch(asrc_t *a, uint32_t tip, uint32_t now)
{
    for (int i = 0; i < RING; i++) {
        arpk_t *k = &a->ring[i];
        if (k->used && k->tip == tip) { k->t = now; return false; }
    }
    a->ring[a->head] = (arpk_t){ .t = now, .tip = tip, .used = 1 };
    a->head = (uint8_t)((a->head + 1) % RING);
    return true;
}

static void sweep_count(asrc_t *a, uint32_t tip, bool fresh)
{
    uint32_t h = lwip_ntohl(tip);
    bool is_new = a->slot >= 0 ? bits_set(a->slot, (uint16_t)(h & 0xffff)) : fresh;
    if (!is_new) return;
    a->total++;
    if (a->total == 1 || h < a->lo) a->lo = h;
    if (a->total == 1 || h > a->hi) a->hi = h;
}

static void sweep_range(const asrc_t *a, char *lo, char *hi)
{
    fmt_ip(lwip_htonl(a->lo), lo, 16);
    fmt_ip(lwip_htonl(a->hi), hi, 16);
}

static void sweep_start(asrc_t *a, uint32_t now, uint32_t win_ms, unsigned distinct)
{
    a->sweeping = true;
    a->start = a->sweep_last = now;
    a->total = 0;
    a->slot = (int8_t)bits_alloc(SCAN_SLOTS, SWEEP_SLOTS);
    for (int i = 0; i < RING; i++) {
        const arpk_t *k = &a->ring[i];
        if (k->used && now - k->t <= win_ms) sweep_count(a, k->tip, true);
    }
    char lo[16], hi[16], mac[WIFI_MAC_STR_LEN];
    sweep_range(a, lo, hi);
    wifi_manager_format_mac(a->mac, mac, sizeof(mac));
    const char *v = wifi_manager_mac_vendor(a->mac);
    s_st_sweeps++;
    emit(ATTACK_ARP_SWEEP, a->ip, a->mac, true, "ARP sweep: %u hosts in %lu s from %s%s%s%s, %s-%s",
         distinct, (unsigned long)settings_get()->arp_window_s, mac,
         v[0] ? " (" : "", v, v[0] ? ")" : "", lo, hi);
}

static void sweep_end(asrc_t *a)
{
    char lo[16], hi[16];
    sweep_range(a, lo, hi);
    emit(ATTACK_ARP_SWEEP, a->ip, a->mac, false, "ARP sweep ended: %lu hosts total, %s-%s, %lu s",
         (unsigned long)a->total, lo, hi, (unsigned long)((a->sweep_last - a->start) / 1000));
    bits_free(&a->slot);
    a->sweeping = false;
    memset(a->ring, 0, sizeof(a->ring));
}

static void on_arp(const det_msg_t *m, uint32_t now)
{
    // Routers ARP for every host they forward to: never a sweep.
    if ((s_gw_ip && m->ip == s_gw_ip) || !memcmp(m->mac, s_gw_mac, 6)) return;
    static const uint8_t zero[6] = { 0 };
    if (!memcmp(m->mac, zero, 6)) return;

    const settings_t *st = settings_get();
    uint32_t win_ms = st->arp_window_s * 1000u;
    asrc_t *a = asrc_get(m->mac, now);
    a->last = now;
    if (m->ip) a->ip = m->ip;               // ARP probes (sender 0.0.0.0) keep the last real IP

    if (a->sweeping) {
        a->sweep_last = now;
        bool fresh = a->slot < 0 && aring_touch(a, m->ip2, now);
        sweep_count(a, m->ip2, fresh);
        return;
    }
    aring_touch(a, m->ip2, now);
    unsigned distinct = 0;
    for (int i = 0; i < RING; i++)
        if (a->ring[i].used && now - a->ring[i].t <= win_ms) distinct++;
    if (distinct >= st->arp_targets) sweep_start(a, now, win_ms, distinct);
}

// ── Housekeeping ──────────────────────────────────────────────────────────────

static void end_quiet(uint32_t now)
{
    for (int i = 0; i < SRC_MAX; i++) {
        src_t *s = &S->src[i];
        if (s->used && s->scanning && now - s->scan_last >= QUIET_MS) scan_end(s);
    }
    for (int i = 0; i < ARP_SRC_MAX; i++) {
        asrc_t *a = &S->asrc[i];
        if (a->used && a->sweeping && now - a->sweep_last >= QUIET_MS) sweep_end(a);
    }
}

static void gateway_refresh(void)
{
    uint32_t gw = 0;
    if (!wifi_manager_get_gateway(&gw)) return;
    uint8_t mac[6];
    s_gw_ip = gw;
    if (wifi_manager_lookup_mac(gw, mac)) memcpy(s_gw_mac, mac, 6);
}

// ── USB serial console: admin allowlist recovery ──────────────────────────────

static char s_line[40];
static int  s_line_n;
static bool s_line_long;

static void console_line(char *l)
{
    while (*l == ' ') l++;
    size_t n = strlen(l);
    while (n && l[n - 1] == ' ') l[--n] = '\0';
    if (strncasecmp(l, "admin-allow", 11) != 0) return;
    const char *arg = l + 11;
    while (*arg == ' ') arg++;
    if (!strcasecmp(arg, "clear")) {
        esp_err_t r = settings_clear_admin_allow();
        if (r != ESP_OK) ESP_LOGE(TAG, "admin-allow clear failed: %s", esp_err_to_name(r));
        return;
    }
    const settings_t *st = settings_get();
    if (!st->admin_allow_n) {
        ESP_LOGW(TAG, "Admin allowlist empty: ports %d and %d open to all", ADMIN_PORT, ADMIN_WS_PORT);
        return;
    }
    for (int i = 0; i < st->admin_allow_n && i < SETTINGS_ADMIN_ALLOW_MAX; i++) {
        char ip[16];
        fmt_ip(st->admin_allow[i], ip, sizeof(ip));
        ESP_LOGW(TAG, "Admin allowlist %d: %s", i + 1, ip);
    }
    ESP_LOGW(TAG, "Type \"admin-allow clear\" to open the admin ports to all");
}

static void console_poll(void)
{
    char buf[32];
    int n = (int)read(STDIN_FILENO, buf, sizeof(buf));   // non-blocking without a UART driver
    for (int i = 0; i < n; i++) {
        char c = buf[i];
        if (c == '\r' || c == '\n') {
            if (!s_line_long && s_line_n) { s_line[s_line_n] = '\0'; console_line(s_line); }
            s_line_n = 0;
            s_line_long = false;
        } else if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7f) {
            if (s_line_n < (int)sizeof(s_line) - 1) s_line[s_line_n++] = c;
            else s_line_long = true;
        }
    }
}

// ── Task ──────────────────────────────────────────────────────────────────────

static void detect_task(void *arg)
{
    (void)arg;
    uint32_t t0 = now_ms(), last_tick = t0, last_tap = 0, last_gw = 0;
    bool reported = false;
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL, 0) | O_NONBLOCK);
    ESP_LOGI(TAG, "Recon detection running. Console: \"admin-allow\", \"admin-allow clear\"");

    for (;;) {
        det_msg_t m;
        if (xQueueReceive(s_q, &m, pdMS_TO_TICKS(TICK_MS)) == pdTRUE) {
            int batch = 0;
            do {
                uint32_t now = now_ms();
                if (m.kind == M_ARP) on_arp(&m, now);
                else if (m.kind == M_LOGGED) on_logged(&m, now);
                else on_port(&m, now);
            } while (++batch < 64 && xQueueReceive(s_q, &m, 0) == pdTRUE);
        }

        uint32_t now = now_ms();
        if (now - last_tick < TICK_MS) continue;
        last_tick = now;
        console_poll();
        probe_emit_due(now);
        end_quiet(now);
        if (now - last_tap >= 5000) { last_tap = now; arp_tap_check(); }
        if (now - last_gw >= (s_gw_ip ? 30000u : 2000u)) { last_gw = now; gateway_refresh(); }
        if (!reported && now - t0 >= 30000) {
            reported = true;
            ESP_LOGI(TAG, "30 s in: internal heap %u B free (low %u B), PSRAM state %u B, "
                     "detect stack high-water %u B of %u, ARP tap %s, queued %lu, dropped %lu",
                     (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)sizeof(det_state_t),
                     (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)DET_TASK_STACK,
                     s_tap_on ? "on" : "off",
                     (unsigned long)s_st_queued, (unsigned long)s_st_dropped);
        }
    }
}

void detect_get_stats(detect_stats_t *out)
{
    out->queued        = s_st_queued;
    out->dropped       = s_st_dropped;
    out->admin_dropped = s_st_admin;
    out->arp_requests  = s_st_arp;
    out->scans         = s_st_scans;
    out->probes        = s_st_probes;
    out->sweeps        = s_st_sweeps;
    out->arp_tap       = s_tap_on;
}

void detect_init(void)
{
    ignore_init();
    allow_reload();
    settings_on_change(allow_reload);

    size_t heap0 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    S = heap_caps_calloc(1, sizeof(*S), MALLOC_CAP_SPIRAM);
    // Queue storage and control block in PSRAM: only tasks touch it (tcpip,
    // Wi-Fi RX, detector), never an ISR, and lwIP's own pbufs already live there.
    QueueHandle_t q = xQueueCreateWithCaps(DET_QUEUE_DEPTH, sizeof(det_msg_t), MALLOC_CAP_SPIRAM);
    if (!S || !q) {
        ESP_LOGE(TAG, "No PSRAM for recon detection: scans will not be seen");
        return;
    }
    if (xTaskCreatePinnedToCore(detect_task, "detect", DET_TASK_STACK, NULL, DET_TASK_PRIO,
                                NULL, 1) != pdPASS) {
        ESP_LOGE(TAG, "No heap for the detect task: scans will not be seen");
        return;
    }
    s_q = q;            // last: the hook and the tap start queueing from here
    ESP_LOGI(TAG, "Recon detection: %u B state + %u B queue in PSRAM, internal heap %u B before, %u B after",
             (unsigned)sizeof(*S), (unsigned)(DET_QUEUE_DEPTH * sizeof(det_msg_t)),
             (unsigned)heap0, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
}
