// MikroTik router, read only: RouterOS v7 REST client, host cache, one
// device's connection tracking on demand, new-device events. See mikrotik.h.
// Fork addition, Robert Mech.
//
// Threading: one task owns the HTTP(S) client and every request (one at a
// time). Its stack is in PSRAM: it does HTTP(S), RAM work and queue sends
// only; the rare NVS write (recorded fingerprint, known MACs) is handed to a
// short-lived helper task with an internal stack. The getters copy under
// s_lock with a short timeout, so a busy task never stalls a caller.
//
// Everything the router sends is untrusted text: the reply is read in pieces
// by a bounded streaming reader (no whole-body buffer, no allocation per
// record), every value is cut to a fixed size, and callers escape on output.

#include "mikrotik.h"
#include "esp_attr.h"
#include "mikrotik_watch.h"
#include "settings.h"
#include "wifi_manager.h"
#include "log_store.h"
#include "alarm.h"
#include "discord.h"
#include "telegram.h"
#include "sd_log.h"
#include "json_esc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_http_client.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "MIKROTIK";

#define MT_HTTP_TIMEOUT_MS  10000       // per read
#define MT_REQ_MAX_MS       20000       // per request, all reads
#define MT_BACKOFF_MIN_S    30
#define MT_BACKOFF_MAX_S    1800
#define MT_FIRST_POLL_S     10          // after the task starts
#define MT_PROBE_EVERY      12          // polls between probes of a Wi-Fi menu that was missing
#define MT_SLOTS            8           // devices with a connection snapshot
#define MT_HIST             24          // destinations remembered per device (beacons)
#define MT_OBS              8           // new-connection times kept per destination
#define MT_SPORTS           8           // source ports remembered per destination
#define MT_REQ_DEPTH        8
#define MT_EVENTS_PER_POLL  8
#define MT_INCIDENT_CHECK_S 10
#define MT_LIST_BYTES       (256 * 1024)        // one poll menu
#define MT_CONN_BYTES       (256 * 1024)        // one device's connections, router-filtered
#define MT_SCAN_BYTES       (2 * 1024 * 1024)   // the whole table, when the router can't filter
#define MT_URL_MAX          384
#define MT_AUTH_MAX         160
#define MT_NVS_NS           "mikrotik"
#define MT_NVS_STACK        3072

// Beacon rule: at least MT_BEACON_MIN times with new connections, gaps within
// a quarter of their mean (or 15 s), the mean 20 s .. 1 h, few connections and
// little data each time.
#define MT_BEACON_MIN       4
#define MT_BEACON_TOL_S     15
#define MT_BEACON_MAX_NEW   2
#define MT_BEACON_MAX_BYTES (64 * 1024)

// ── State ─────────────────────────────────────────────────────────────────────

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t  proto;
    uint8_t  n_obs;                 // observations kept (<= MT_OBS)
    uint8_t  max_new;               // most new connections in one observation
    uint8_t  n_sport;
    uint16_t sport[MT_SPORTS];      // source ports in the last snapshot
    uint32_t obs[MT_OBS];           // uptime s of each observation, oldest first
    uint32_t seen;                  // uptime s it was last in a snapshot
    uint32_t first;                 // uptime s it was first in one
    uint32_t conns;                 // new connections counted
    uint64_t bytes;                 // their bytes, both ways, as last seen
} mt_hist_t;

typedef struct {
    bool     used, queued;
    uint32_t ip;
    uint8_t  mac[6];
    int64_t  req_s, fetch_s, watch_until_s, touch_s;    // uptime seconds
    mikrotik_conn_t snap;
    uint8_t  n_hist;
    mt_hist_t hist[MT_HIST];
} mt_slot_t;

// The connection snapshot being built, with each destination's source ports.
typedef struct {
    uint32_t target;
    bool     client_filter;         // the router did not filter: match here
    bool     combined;              // src-address came as "ip:port"
    bool     plain;                 // src-address came as a bare IP
    uint16_t total, external;
    bool     truncated;
    uint16_t n;
    mikrotik_dst_t d[MIKROTIK_DST_MAX];
    uint8_t  n_sport[MIKROTIK_DST_MAX];
    uint16_t sport[MIKROTIK_DST_MAX][MT_SPORTS];
} mt_build_t;

// Streaming reader of a RouterOS REST reply: a JSON array of flat objects,
// or one flat object. Nested values are skipped.
enum { P_TOP, P_ARR, P_KEYW, P_KEY, P_COLON, P_VALW, P_VSTR, P_VLIT, P_AFTER, P_SKIP, P_DONE, P_ERR };
typedef struct {
    uint8_t  st;
    bool     single, esc, sk_str, sk_esc, stop;
    uint8_t  uhex;
    uint16_t ucp;
    uint16_t sk_depth;
    uint8_t  klen, vlen;
    bool     vcut;
    uint32_t vhash;
    char     key[MIKROTIK_KEY_LEN];
    uint32_t rows;
    mikrotik_row_cb cb;
    void    *ctx;
    mikrotik_row_t *row;
} mt_reader_t;

typedef struct {
    mikrotik_host_t hosts[2][MIKROTIK_HOSTS_MAX];
    uint16_t n_hosts[2];
    uint8_t  front;                 // hosts[front] is served; the other is built
    uint32_t as_of;
    uint16_t c_lease, c_arp, c_bridge, c_wifi;
    uint8_t  known[MIKROTIK_KNOWN_MAX][6];
    uint16_t n_known;
    bool     learned;
    mt_slot_t slot[MT_SLOTS];
    mt_build_t build;
    struct { uint32_t ip; char name[48]; } dns[MIKROTIK_DNS_NAMES];    // router DNS cache, a ring
    uint16_t n_dns, dns_next;
    int64_t  dns_s;                 // uptime s of the last DNS cache read
    mikrotik_row_t row;
    mt_reader_t rd;
    settings_t set;
    char     rx[1024];
    char     url[MT_URL_MAX];
    char     auth[MT_AUTH_MAX];
    char     path[256];
    attack_log_t ev;
} mt_state_t;

typedef struct { uint8_t kind; uint32_t ip; } mt_req_t;
enum { REQ_CONN = 1, REQ_TEST, REQ_KICK };

static mt_state_t       *S;
static SemaphoreHandle_t s_lock;            // hosts[front], slots
static QueueHandle_t     s_q;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;   // s_stat
EXT_RAM_BSS_ATTR static mikrotik_status_t s_stat;    // PSRAM
static volatile bool     s_running;
static uint32_t          s_test_next;

// Certificate state: the task's request in flight, and the recorded fingerprint.
enum { TLS_NONE, TLS_OK, TLS_FIRST, TLS_MISMATCH };
static mbedtls_x509_crt *s_dummy_ca;        // a non-NULL, empty CA chain, as esp_crt_bundle does (PSRAM)
static uint8_t           s_pin[32], s_tofu[32], s_seen[32];
static bool              s_pin_set, s_tofu_set, s_seen_set;
static volatile uint8_t  s_tls_verdict;
static portMUX_TYPE      s_tls_mux = portMUX_INITIALIZER_UNLOCKED;

// Connection-table filtering: unknown until the first empty filtered reply.
enum { CT_UNKNOWN, CT_ROUTER, CT_CLIENT };
static uint8_t           s_ct_mode = CT_UNKNOWN;

// The router's own interface MACs: published under s_mux; the task reads into
// s_own_rd first. PSRAM.
EXT_RAM_BSS_ATTR static uint8_t s_own[MIKROTIK_OWN_MAX][6];
EXT_RAM_BSS_ATTR static uint8_t s_own_rd[MIKROTIK_OWN_MAX][6];
static uint8_t           s_own_n, s_own_rd_n;
static bool              s_own_known;
static uint32_t          s_own_over;        // distinct MACs past MIKROTIK_OWN_MAX in the last read

static int64_t up_s(void) { return esp_timer_get_time() / 1000000LL; }

static bool lock(int ms)
{
    return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(ms)) == pdTRUE;
}
static void unlock(void) { xSemaphoreGive(s_lock); }

static void hex32(const uint8_t b[32], char out[65])
{
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[i * 2] = H[b[i] >> 4]; out[i * 2 + 1] = H[b[i] & 15]; }
    out[64] = '\0';
}

static bool unhex32(const char *s, uint8_t out[32])
{
    if (strlen(s) != 64) return false;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// RFC 1918 only: the devices whose connections are worth asking about.
static bool ip_private(uint32_t ip)
{
    const uint8_t *b = (const uint8_t *)&ip;            // network order: b[0] first
    return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168);
}

// External: not private, loopback, link-local, multicast, broadcast or 0/8.
static bool ip_external(uint32_t ip)
{
    const uint8_t *b = (const uint8_t *)&ip;
    if (ip_private(ip) || b[0] == 0 || b[0] == 127 || b[0] >= 224) return false;
    if (b[0] == 169 && b[1] == 254) return false;
    return true;
}

static bool parse_ip(const char *s, uint32_t *out, uint16_t *port)
{
    unsigned a, b, c, d, p = 0;
    char tail = 0;
    int n = sscanf(s, "%u.%u.%u.%u:%u%c", &a, &b, &c, &d, &p, &tail);
    if (n < 4 || n > 5 || a > 255 || b > 255 || c > 255 || d > 255 || p > 65535) return false;
    uint8_t q[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    memcpy(out, q, 4);
    if (port) *port = (uint16_t)p;
    return true;
}

static bool parse_mac(const char *s, uint8_t mac[6])
{
    unsigned m[6];
    char tail = 0;
    if (strlen(s) != 17 || sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &tail) != 6)
        return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return true;
}

// Router text into a fixed field: printable ASCII only (the UI escapes it
// again; this keeps headlines and Discord clean).
static void copy_txt(char *dst, size_t cap, const char *src)
{
    size_t o = 0;
    for (; *src && o + 1 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c >= 0x20 && c <= 0x7e) dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

static void stat_set_detail(const char *d)
{
    portENTER_CRITICAL(&s_mux);
    strlcpy(s_stat.detail, d, sizeof(s_stat.detail));
    portEXIT_CRITICAL(&s_mux);
}

// ── NVS (helper task with an internal stack) ──────────────────────────────────

typedef struct { char key[16]; size_t len; uint8_t data[]; } nvs_job_t;

static void nvs_job_task(void *arg)
{
    nvs_job_t *j = arg;
    uint8_t *buf = heap_caps_malloc(j->len ? j->len : 1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    nvs_handle_t h;
    if (buf && nvs_open(MT_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        memcpy(buf, j->data, j->len);       // NVS writes from internal RAM
        esp_err_t r = nvs_set_blob(h, j->key, buf, j->len);
        if (r == ESP_OK) r = nvs_commit(h);
        nvs_close(h);
        if (r != ESP_OK) ESP_LOGW(TAG, "NVS %s not saved: %s", j->key, esp_err_to_name(r));
    }
    free(buf);
    free(j);
    vTaskDelete(NULL);
}

static void nvs_save_async(const char *key, const void *data, size_t len)
{
    nvs_job_t *j = heap_caps_malloc(sizeof(*j) + len, MALLOC_CAP_SPIRAM);
    if (!j) return;
    strlcpy(j->key, key, sizeof(j->key));
    j->len = len;
    memcpy(j->data, data, len);
    if (xTaskCreatePinnedToCore(nvs_job_task, "mt_nvs", MT_NVS_STACK, j, 1, NULL, 1) != pdPASS) {
        ESP_LOGW(TAG, "NVS %s not saved: no memory for the helper task", key);
        free(j);
    }
}

void mikrotik_nvs_save(const char *key, const void *data, size_t len) { nvs_save_async(key, data, len); }

// ── TLS: the certificate pin ──────────────────────────────────────────────────

// mbedTLS calls this for each certificate in the chain, the leaf (depth 0)
// last. Only the leaf is judged, against the pin, else the recorded
// fingerprint, else it is the first one seen (recorded once the request has
// authenticated). Anything else is refused.
static int verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx;
    if (depth > 0) { *flags = 0; return 0; }
    uint8_t fp[32];
    if (mbedtls_sha256(crt->raw.p, crt->raw.len, fp, 0) != 0) {
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        s_tls_verdict = TLS_MISMATCH;
        return 0;
    }
    portENTER_CRITICAL(&s_tls_mux);
    memcpy(s_seen, fp, 32);
    s_seen_set = true;
    const uint8_t *want = s_pin_set ? s_pin : s_tofu_set ? s_tofu : NULL;
    uint8_t verdict = !want ? TLS_FIRST : memcmp(fp, want, 32) == 0 ? TLS_OK : TLS_MISMATCH;
    portEXIT_CRITICAL(&s_tls_mux);
    s_tls_verdict = verdict;
    if (verdict == TLS_MISMATCH) *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    else *flags = 0;            // self-signed, and the name is an IP: the pin is the trust
    return 0;
}

static esp_err_t tls_attach(void *conf)
{
    mbedtls_ssl_config *c = conf;
    mbedtls_ssl_conf_authmode(c, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(c, s_dummy_ca, NULL);
    mbedtls_ssl_conf_verify(c, verify_cb, NULL);
    return ESP_OK;
}

void mikrotik_cert_forget(void)
{
    nvs_handle_t h;
    if (nvs_open(MT_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_key(h, "tofu");
        nvs_commit(h);
        nvs_close(h);
    }
    portENTER_CRITICAL(&s_tls_mux);
    s_tofu_set = false;
    memset(s_tofu, 0, sizeof(s_tofu));
    portEXIT_CRITICAL(&s_tls_mux);
    portENTER_CRITICAL(&s_mux);
    s_stat.tofu[0] = '\0';
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGW(TAG, "Recorded certificate fingerprint forgotten: the next https connection records a new one");
    mikrotik_settings_changed();
}

// ── Reply reader ──────────────────────────────────────────────────────────────

const char *mikrotik_row_get(const mikrotik_row_t *row, const char *key)
{
    for (int i = 0; i < row->n; i++)
        if (!strcmp(row->kv[i].k, key)) return row->kv[i].v;
    return "";
}

static void rd_init(mt_reader_t *p, mikrotik_row_t *row, mikrotik_row_cb cb, void *ctx)
{
    memset(p, 0, sizeof(*p));
    p->row = row;
    p->cb = cb;
    p->ctx = ctx;
    row->n = 0;
}

static void rd_val_put(mt_reader_t *p, char c)
{
    p->vhash = (p->vhash ^ (uint8_t)c) * 16777619u;
    if (p->row->n >= MIKROTIK_ROW_KV) return;
    if (p->vlen + 1 < MIKROTIK_VAL_LEN) p->row->kv[p->row->n].v[p->vlen++] = c;
    else p->vcut = true;
}

static void rd_key_put(mt_reader_t *p, char c)
{
    if (p->klen + 1 < MIKROTIK_KEY_LEN) p->key[p->klen++] = c;
}

static void rd_put(mt_reader_t *p, bool key, uint32_t cp)
{
    char u[3];
    int n = 0;
    if (cp < 0x80)        { u[n++] = (char)cp; }
    else if (cp < 0x800)  { u[n++] = (char)(0xC0 | (cp >> 6)); u[n++] = (char)(0x80 | (cp & 0x3F)); }
    else if (cp >= 0xD800 && cp <= 0xDFFF) { u[n++] = '?'; }
    else { u[n++] = (char)(0xE0 | (cp >> 12)); u[n++] = (char)(0x80 | ((cp >> 6) & 0x3F)); u[n++] = (char)(0x80 | (cp & 0x3F)); }
    for (int i = 0; i < n; i++) key ? rd_key_put(p, u[i]) : rd_val_put(p, u[i]);
}

// One byte of a string body. True when the closing quote was read.
static bool rd_str(mt_reader_t *p, bool key, char c)
{
    if (p->uhex) {
        int h = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (h >= 0) {
            p->ucp = (uint16_t)(p->ucp << 4 | (uint16_t)h);
            if (--p->uhex == 0) rd_put(p, key, p->ucp);
            return false;
        }
        p->uhex = 0;                // a bad escape: mark it, then read c as usual
        rd_put(p, key, '?');
    }
    if (p->esc) {
        p->esc = false;
        switch (c) {
        case 'n': rd_put(p, key, '\n'); break;
        case 't': rd_put(p, key, '\t'); break;
        case 'r': rd_put(p, key, '\r'); break;
        case 'b': case 'f': break;
        case 'u': p->uhex = 4; p->ucp = 0; break;
        default:  rd_put(p, key, (uint8_t)c); break;     // " \ /
        }
        return false;
    }
    if (c == '\\') { p->esc = true; return false; }
    if (c == '"') return true;
    if ((uint8_t)c < 0x20) return false;
    if (key) rd_key_put(p, c); else rd_val_put(p, c);
    return false;
}

static void rd_store(mt_reader_t *p)
{
    mikrotik_row_t *r = p->row;
    if (r->n >= MIKROTIK_ROW_KV) return;
    p->key[p->klen] = '\0';
    strlcpy(r->kv[r->n].k, p->key, MIKROTIK_KEY_LEN);
    r->kv[r->n].v[p->vlen] = '\0';
    r->kv[r->n].hash = p->vhash;
    r->kv[r->n].cut = p->vcut;
    r->n++;
}

static void rd_val_begin(mt_reader_t *p)
{
    p->vlen = 0;
    p->vcut = false;
    p->vhash = 2166136261u;
}

static void rd_emit(mt_reader_t *p)
{
    p->rows++;
    if (p->cb && !p->cb(p->ctx, p->row)) p->stop = true;
    p->row->n = 0;
    p->st = p->single ? P_DONE : P_ARR;
}

static bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static void rd_byte(mt_reader_t *p, char c)
{
    switch (p->st) {
    case P_TOP:
        if (is_ws(c)) return;
        if (c == '[') p->st = P_ARR;
        else if (c == '{') { p->single = true; p->row->n = 0; p->st = P_KEYW; }
        else p->st = P_ERR;
        return;
    case P_ARR:
        if (is_ws(c) || c == ',') return;
        if (c == '{') { p->row->n = 0; p->st = P_KEYW; }
        else if (c == ']') p->st = P_DONE;
        else p->st = P_ERR;
        return;
    case P_KEYW:
        if (is_ws(c) || c == ',') return;
        if (c == '"') { p->klen = 0; p->esc = false; p->uhex = 0; p->st = P_KEY; }
        else if (c == '}') rd_emit(p);
        else p->st = P_ERR;
        return;
    case P_KEY:
        if (rd_str(p, true, c)) p->st = P_COLON;
        return;
    case P_COLON:
        if (is_ws(c)) return;
        p->st = c == ':' ? P_VALW : P_ERR;
        return;
    case P_VALW:
        if (is_ws(c)) return;
        rd_val_begin(p);
        if (c == '"') { p->esc = false; p->uhex = 0; p->st = P_VSTR; }
        else if (c == '{' || c == '[') { p->sk_depth = 1; p->sk_str = p->sk_esc = false; p->st = P_SKIP; }
        else if (c == ',' || c == '}') p->st = P_ERR;
        else { rd_val_put(p, c); p->st = P_VLIT; }
        return;
    case P_VSTR:
        if (rd_str(p, false, c)) { rd_store(p); p->st = P_AFTER; }
        return;
    case P_VLIT:
        if (c == ',' || c == '}' || is_ws(c)) {
            rd_store(p);
            p->st = P_AFTER;
            rd_byte(p, c);
        } else {
            rd_val_put(p, c);
        }
        return;
    case P_AFTER:
        if (is_ws(c)) return;
        if (c == ',') p->st = P_KEYW;
        else if (c == '}') rd_emit(p);
        else p->st = P_ERR;
        return;
    case P_SKIP:
        if (p->sk_str) {
            if (p->sk_esc) p->sk_esc = false;
            else if (c == '\\') p->sk_esc = true;
            else if (c == '"') p->sk_str = false;
        } else if (c == '"') {
            p->sk_str = true;
        } else if (c == '{' || c == '[') {
            if (++p->sk_depth > 32) p->st = P_ERR;
        } else if (c == '}' || c == ']') {
            if (--p->sk_depth == 0) p->st = P_AFTER;
        }
        return;
    default:
        return;
    }
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// Authorization and URL from the live settings, into the task's buffers.
static bool request_setup(const char *path, bool *https)
{
    settings_copy(&S->set);
    const settings_t *st = &S->set;
    bool ok = st->mikrotik_url[0] && st->mikrotik_user[0] && st->mikrotik_password[0];
    *https = !strncmp(st->mikrotik_url, "https://", 8);
    if (ok) {
        size_t n = strlcpy(S->url, st->mikrotik_url, sizeof(S->url));
        if (n && n < sizeof(S->url) && S->url[n - 1] == '/') S->url[--n] = '\0';
        ok = n + 5 + strlen(path) < sizeof(S->url);
        if (ok) { strlcat(S->url, "/rest", sizeof(S->url)); strlcat(S->url, path, sizeof(S->url)); }
    }
    if (ok) {
        char cred[33 + 1 + 65];
        snprintf(cred, sizeof(cred), "%s:%s", st->mikrotik_user, st->mikrotik_password);
        memcpy(S->auth, "Basic ", 6);
        size_t olen = 0;
        ok = mbedtls_base64_encode((unsigned char *)S->auth + 6, sizeof(S->auth) - 7, &olen,
                                   (const unsigned char *)cred, strlen(cred)) == 0;
        S->auth[6 + (ok ? olen : 0)] = '\0';
        mbedtls_platform_zeroize(cred, sizeof(cred));
    }
    uint8_t pin[32];
    bool pin_ok = st->mikrotik_cert_sha256[0] && unhex32(st->mikrotik_cert_sha256, pin);
    portENTER_CRITICAL(&s_tls_mux);
    s_pin_set = pin_ok;
    if (pin_ok) memcpy(s_pin, pin, 32);
    portEXIT_CRITICAL(&s_tls_mux);
    memset(&S->set, 0, sizeof(S->set));
    return ok;
}

static void record_tofu(void)
{
    char hex[65];
    portENTER_CRITICAL(&s_tls_mux);
    bool rec = !s_pin_set && !s_tofu_set && s_seen_set;
    if (rec) { memcpy(s_tofu, s_seen, 32); s_tofu_set = true; }
    uint8_t fp[32];
    memcpy(fp, s_tofu, 32);
    portEXIT_CRITICAL(&s_tls_mux);
    if (!rec) return;
    hex32(fp, hex);
    nvs_save_async("tofu", fp, 32);
    portENTER_CRITICAL(&s_mux);
    strlcpy(s_stat.tofu, hex, sizeof(s_stat.tofu));
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGW(TAG, "First https connection: recorded the router's certificate, SHA-256 %s. "
                  "A different certificate will be refused until it is pinned or this is forgotten.", hex);
}

int mikrotik_rest_get(const char *path, mikrotik_row_cb cb, void *ctx, uint32_t max_bytes, uint32_t *rows)
{
    if (rows) *rows = 0;
    bool https = false;
    if (!S || !request_setup(path, &https)) return -1;

    esp_http_client_config_t cfg = {
        .url                   = S->url,
        .method                = HTTP_METHOD_GET,
        .timeout_ms            = MT_HTTP_TIMEOUT_MS,
        .disable_auto_redirect = true,
        .buffer_size           = 1024,
        .buffer_size_tx        = 768,       // request line with the .proplist, Authorization
        .keep_alive_enable     = false,
        .crt_bundle_attach     = https ? tls_attach : NULL,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) { memset(S->auth, 0, sizeof(S->auth)); return -1; }
    esp_http_client_set_header(c, "Authorization", S->auth);
    esp_http_client_set_header(c, "Accept", "application/json");
    memset(S->auth, 0, sizeof(S->auth));

    s_tls_verdict = TLS_NONE;
    int status = -1;
    if (esp_http_client_open(c, 0) != ESP_OK) {
        status = (https && s_tls_verdict == TLS_MISMATCH) ? -2 : -1;
        goto out;
    }
    esp_http_client_fetch_headers(c);
    status = esp_http_client_get_status_code(c);
    if (status != 200) {
        // The error object's "detail" (RouterOS: {"error":N,"message":..,"detail":..}).
        int n = esp_http_client_read(c, S->rx, sizeof(S->rx) - 1);
        S->rx[n > 0 ? n : 0] = '\0';
        const char *d = strstr(S->rx, "\"detail\":\"");
        char det[48] = "";
        if (d) {
            d += 10;
            size_t k = 0;
            while (d[k] && d[k] != '"' && k + 1 < sizeof(det)) { det[k] = d[k]; k++; }
            det[k] = '\0';
        }
        char why[64], clean[48];
        copy_txt(clean, sizeof(clean), det);
        snprintf(why, sizeof(why), "HTTP %d%s%s", status, clean[0] ? ": " : "", clean);
        stat_set_detail(why);
        goto out;
    }

    rd_init(&S->rd, &S->row, cb, ctx);
    uint32_t got = 0;
    int64_t t0 = esp_timer_get_time();
    for (;;) {
        int n = esp_http_client_read(c, S->rx, sizeof(S->rx));
        if (n < 0) { status = -1; stat_set_detail("connection lost mid-reply"); break; }
        if (n == 0) break;
        for (int i = 0; i < n && !S->rd.stop && S->rd.st != P_ERR && S->rd.st != P_DONE; i++)
            rd_byte(&S->rd, S->rx[i]);
        got += (uint32_t)n;
        if (S->rd.st == P_ERR) { status = -3; stat_set_detail("reply is not REST JSON"); break; }
        if (S->rd.stop || S->rd.st == P_DONE) break;
        if (got >= max_bytes) break;
        if ((esp_timer_get_time() - t0) / 1000 > MT_REQ_MAX_MS) break;
    }
    if (status == 200 && S->rd.st == P_TOP) { status = -3; stat_set_detail("empty reply"); }
    else if (status == 200 && !S->rd.stop && S->rd.st != P_DONE) status = -4;     // cut at a cap
    if (rows) *rows = S->rd.rows;

out:
    esp_http_client_close(c);
    esp_http_client_cleanup(c);
    if (https && s_tls_verdict == TLS_FIRST && status == 200) record_tofu();
    if (https) {
        char seen[65] = "";
        portENTER_CRITICAL(&s_tls_mux);
        bool ss = s_seen_set;
        uint8_t fp[32];
        memcpy(fp, s_seen, 32);
        portEXIT_CRITICAL(&s_tls_mux);
        if (ss) hex32(fp, seen);
        portENTER_CRITICAL(&s_mux);
        strlcpy(s_stat.seen, seen, sizeof(s_stat.seen));
        portEXIT_CRITICAL(&s_mux);
    }
    portENTER_CRITICAL(&s_mux);
    s_stat.last_status = status;
    portEXIT_CRITICAL(&s_mux);
    return status;
}

// ── Host cache ────────────────────────────────────────────────────────────────

static mikrotik_host_t *back_find(const uint8_t mac[6], bool add)
{
    uint8_t b = S->front ^ 1;
    for (int i = 0; i < S->n_hosts[b]; i++)
        if (!memcmp(S->hosts[b][i].mac, mac, 6)) return &S->hosts[b][i];
    if (!add || S->n_hosts[b] >= MIKROTIK_HOSTS_MAX) return NULL;
    mikrotik_host_t *h = &S->hosts[b][S->n_hosts[b]++];
    memset(h, 0, sizeof(*h));
    memcpy(h->mac, mac, 6);
    return h;
}

static bool lease_cb(void *ctx, const mikrotik_row_t *r)
{
    (void)ctx;
    uint8_t mac[6];
    const char *m = mikrotik_row_get(r, "active-mac-address");
    if (!parse_mac(m, mac) && !parse_mac(mikrotik_row_get(r, "mac-address"), mac)) return true;
    mikrotik_host_t *h = back_find(mac, true);
    if (!h) return true;
    uint32_t ip;
    if (parse_ip(mikrotik_row_get(r, "active-address"), &ip, NULL) ||
        parse_ip(mikrotik_row_get(r, "address"), &ip, NULL)) h->ip = ip;
    h->src |= MIKROTIK_SRC_LEASE;
    copy_txt(h->hostname, sizeof(h->hostname), mikrotik_row_get(r, "host-name"));
    copy_txt(h->client_id, sizeof(h->client_id), mikrotik_row_get(r, "client-id"));
    copy_txt(h->lease_status, sizeof(h->lease_status), mikrotik_row_get(r, "status"));
    copy_txt(h->last_seen, sizeof(h->last_seen), mikrotik_row_get(r, "last-seen"));
    S->c_lease++;
    return true;
}

static bool arp_cb(void *ctx, const mikrotik_row_t *r)
{
    (void)ctx;
    uint8_t mac[6];
    uint32_t ip;
    if (!parse_mac(mikrotik_row_get(r, "mac-address"), mac)) return true;
    mikrotik_host_t *h = back_find(mac, true);
    if (!h) return true;
    if (!h->ip && parse_ip(mikrotik_row_get(r, "address"), &ip, NULL)) h->ip = ip;
    h->src |= MIKROTIK_SRC_ARP;
    copy_txt(h->arp_if, sizeof(h->arp_if), mikrotik_row_get(r, "interface"));
    S->c_arp++;
    return true;
}

static bool bridge_cb(void *ctx, const mikrotik_row_t *r)
{
    (void)ctx;
    uint8_t mac[6];
    if (!strcmp(mikrotik_row_get(r, "local"), "true")) return true;     // the router's own ports
    if (!parse_mac(mikrotik_row_get(r, "mac-address"), mac)) return true;
    mikrotik_host_t *h = back_find(mac, true);
    if (!h) return true;
    h->src |= MIKROTIK_SRC_BRIDGE;
    copy_txt(h->port, sizeof(h->port), mikrotik_row_get(r, "on-interface"));
    copy_txt(h->bridge, sizeof(h->bridge), mikrotik_row_get(r, "bridge"));
    S->c_bridge++;
    return true;
}

// The three registration tables; ctx says which signal field it has.
static const struct { const char *path, *sig; } WIFI_MENUS[3] = {
    { "/interface/wifi/registration-table?.proplist=mac-address,interface,ssid,signal",            "signal" },
    { "/interface/wireless/registration-table?.proplist=mac-address,interface,signal-strength",    "signal-strength" },
    { "/caps-man/registration-table?.proplist=mac-address,interface,ssid,rx-signal",               "rx-signal" },
};

static bool wifi_cb(void *ctx, const mikrotik_row_t *r)
{
    const char *sigkey = ctx;
    uint8_t mac[6];
    if (!parse_mac(mikrotik_row_get(r, "mac-address"), mac)) return true;
    mikrotik_host_t *h = back_find(mac, true);
    if (!h) return true;
    h->src |= MIKROTIK_SRC_WIFI;
    copy_txt(h->wifi_if, sizeof(h->wifi_if), mikrotik_row_get(r, "interface"));
    copy_txt(h->ssid, sizeof(h->ssid), mikrotik_row_get(r, "ssid"));
    long sig = strtol(mikrotik_row_get(r, sigkey), NULL, 10);    // "-61" or "-61@HT20-..."
    h->signal = (sig < 0 && sig > -128) ? (int8_t)sig : 0;
    S->c_wifi++;
    return true;
}

static bool known_has(const uint8_t mac[6])
{
    for (int i = 0; i < S->n_known; i++) if (!memcmp(S->known[i], mac, 6)) return true;
    return false;
}

// Seen again: move it to the newest end, so eviction drops the longest absent.
static void known_touch(const uint8_t mac[6])
{
    for (int i = 0; i < S->n_known; i++) {
        if (memcmp(S->known[i], mac, 6)) continue;
        if (i + 1 < S->n_known) {
            memmove(S->known[i], S->known[i + 1], (size_t)(S->n_known - 1 - i) * 6);
            memcpy(S->known[S->n_known - 1], mac, 6);
        }
        return;
    }
}

static void known_add(const uint8_t mac[6])
{
    if (S->n_known >= MIKROTIK_KNOWN_MAX) {         // oldest out
        memmove(S->known[0], S->known[1], (MIKROTIK_KNOWN_MAX - 1) * 6);
        S->n_known--;
    }
    memcpy(S->known[S->n_known++], mac, 6);
}

// Code 60-02, the discovery way: not log_store_append() (this task must not
// write SPIFFS), so the event reaches Discord's event log, the incident logic
// and Telegram directly (the alert mask and ignore list apply), and the card
// gets a {"kind":"netdev"} line.
static void new_device_event(const mikrotik_host_t *h, uint32_t more)
{
    attack_log_t *e = &S->ev;
    memset(e, 0, sizeof(*e));
    e->timestamp = (uint32_t)time(NULL);
    e->src_ip = h->ip;
    memcpy(e->src_mac, h->mac, 6);
    e->type = ATTACK_NEW_DEVICE;
    const char *vendor = wifi_manager_mac_vendor(h->mac);
    const char *where = h->port[0] ? h->port : h->wifi_if[0] ? h->wifi_if : h->arp_if[0] ? h->arp_if : "";
    char held[20] = "";
    if (more) snprintf(held, sizeof(held), " (+%lu more)", (unsigned long)more);
    char name[96];
    if (h->hostname[0] && vendor[0]) snprintf(name, sizeof(name), "%s (%.30s)", h->hostname, vendor);
    else snprintf(name, sizeof(name), "%s", h->hostname[0] ? h->hostname : vendor[0] ? vendor : "unnamed");
    snprintf(e->payload, sizeof(e->payload) - strlen(held), "New device %s%s%s", name,
             where[0] ? " on " : "", where);
    strlcat(e->payload, held, sizeof(e->payload));
    discord_log_event(e);
    alarm_note_event(e);
    telegram_notify(e);

    char ip[16] = "", mac[WIFI_MAC_STR_LEN], hn[2 * MIKROTIK_NAME_LEN], vd[96], port[2 * MIKROTIK_IF_LEN],
         ap[2 * MIKROTIK_IF_LEN], ssid[72];
    if (h->ip) { ip4_addr_t a = { .addr = h->ip }; ip4addr_ntoa_r(&a, ip, sizeof(ip)); }
    wifi_manager_format_mac(h->mac, mac, sizeof(mac));
    json_esc(h->hostname, sizeof(h->hostname), hn, sizeof(hn));
    json_esc(vendor, 48, vd, sizeof(vd));
    json_esc(h->port, sizeof(h->port), port, sizeof(port));
    json_esc(h->wifi_if, sizeof(h->wifi_if), ap, sizeof(ap));
    json_esc(h->ssid, sizeof(h->ssid), ssid, sizeof(ssid));
    char *line = heap_caps_malloc(640, MALLOC_CAP_SPIRAM);
    if (!line) return;
    int n = snprintf(line, 640,
        "{\"kind\":\"netdev\",\"ts\":%lu,\"code\":\"60-02\",\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\","
        "\"hostname\":\"%s\",\"port\":\"%s\",\"ap\":\"%s\",\"ssid\":\"%s\",\"signal\":%d}\n",
        (unsigned long)e->timestamp, ip, mac, vd, hn, port, ap, ssid, (int)h->signal);
    if (n <= 0 || n >= 640) { free(line); return; }
    sd_log_line(line, (size_t)n);
}

static void check_new_devices(void)
{
    uint8_t b = S->front ^ 1;
    uint32_t raised = 0, more = 0, added = 0;
    const mikrotik_host_t *last = NULL;
    for (int i = 0; i < S->n_hosts[b]; i++) {
        mikrotik_host_t *h = &S->hosts[b][i];
        if (!(h->src & MIKROTIK_SRC_LEASE) || strcmp(h->lease_status, "bound")) continue;
        if (known_has(h->mac)) { known_touch(h->mac); continue; }
        known_add(h->mac);
        added++;
        if (!S->learned) continue;
        h->new_device = true;
        if (raised < MT_EVENTS_PER_POLL) { new_device_event(h, 0); raised++; }
        else { more++; last = h; }
    }
    if (more && last) new_device_event(last, more - 1);
    if (!S->learned && S->c_lease) {
        S->learned = true;
        ESP_LOGI(TAG, "Learned %lu devices from the DHCP leases (no events for these)", (unsigned long)added);
    }
    if (added) nvs_save_async("known", S->known, (size_t)S->n_known * 6);
    portENTER_CRITICAL(&s_mux);
    s_stat.new_devices += raised + more;
    s_stat.known = S->n_known;
    s_stat.learned = S->learned;
    portEXIT_CRITICAL(&s_mux);
}

// ── The router's own MACs ─────────────────────────────────────────────────────

static bool own_cb(void *ctx, const mikrotik_row_t *r)
{
    (void)ctx;
    static const uint8_t zero[6] = { 0 };
    uint8_t mac[6];
    if (!parse_mac(mikrotik_row_get(r, "mac-address"), mac) || !memcmp(mac, zero, 6)) return true;
    for (int i = 0; i < s_own_rd_n; i++) if (!memcmp(s_own_rd[i], mac, 6)) return true;
    if (s_own_rd_n < MIKROTIK_OWN_MAX) memcpy(s_own_rd[s_own_rd_n++], mac, 6);
    else s_own_over++;
    return true;
}

// GET /rest/interface for its mac-address fields (bridges, VLANs and ports
// often share one MAC: kept once). True on a 200.
static bool own_fetch(void)
{
    uint32_t rows = 0;
    s_own_rd_n = 0;
    s_own_over = 0;
    int st = mikrotik_rest_get("/interface?.proplist=mac-address", own_cb, NULL, MT_LIST_BYTES, &rows);
    if (st != 200) {
        ESP_LOGW(TAG, "Router interfaces not read (status %d): MNDP and MAC-Telnet whitelist keeps %u router MACs",
                 st, (unsigned)s_own_n);
        return false;
    }
    bool changed;
    portENTER_CRITICAL(&s_mux);
    changed = !s_own_known || s_own_n != s_own_rd_n || memcmp(s_own, s_own_rd, (size_t)s_own_rd_n * 6);
    memcpy(s_own, s_own_rd, (size_t)s_own_rd_n * 6);
    s_own_n = s_own_rd_n;
    s_own_known = true;
    s_stat.own_macs = s_own_n;
    s_stat.own_known = true;
    portEXIT_CRITICAL(&s_mux);
    if (changed)
        ESP_LOGI(TAG, "Router's own MACs: %u from %lu interfaces%s; MNDP and MAC-Telnet from them are not reported",
                 (unsigned)s_own_rd_n, (unsigned long)rows, s_own_over ? " (more not kept)" : "");
    return true;
}

bool mikrotik_own_mac(const uint8_t mac[6])
{
    if (!mac) return false;
    bool hit = false;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < s_own_n && !hit; i++) hit = !memcmp(s_own[i], mac, 6);
    portEXIT_CRITICAL(&s_mux);
    return hit;
}

int mikrotik_own_macs_state(uint16_t *n)
{
    bool known;
    uint16_t k;
    portENTER_CRITICAL(&s_mux);
    known = s_own_known;
    k = s_own_n;
    portEXIT_CRITICAL(&s_mux);
    if (n) *n = k;
    if (!settings_mikrotik_enabled()) return -1;    // configured and on, even before the task starts
    return known ? 1 : 0;
}

// One poll of the menus into the back table, then swap. Returns the first
// failing status, or 200.
static int poll_router(uint32_t n_poll)
{
    static uint8_t wifi_have, wifi_tried;   // bit per WIFI_MENUS entry
    uint8_t b = S->front ^ 1;
    S->n_hosts[b] = 0;
    S->c_lease = S->c_arp = S->c_bridge = S->c_wifi = 0;
    uint32_t rows;

    int st = mikrotik_rest_get("/ip/dhcp-server/lease?.proplist=mac-address,address,active-address,"
                               "active-mac-address,host-name,client-id,status,last-seen",
                               lease_cb, NULL, MT_LIST_BYTES, &rows);
    if (st == -4) stat_set_detail("lease table larger than the read cap");
    if (st != 200) return st;
    st = mikrotik_rest_get("/ip/arp?.proplist=address,mac-address,interface", arp_cb, NULL, MT_LIST_BYTES, &rows);
    if (st != 200) return st;
    st = mikrotik_rest_get("/interface/bridge/host?.proplist=mac-address,on-interface,bridge,local",
                           bridge_cb, NULL, MT_LIST_BYTES, &rows);
    if (st == -1 || st == -2 || st == 401 || st == 403) return st;      // no bridge is fine
    for (int i = 0; i < 3; i++) {
        bool due = (wifi_have & (1u << i)) || !(wifi_tried & (1u << i)) || n_poll % MT_PROBE_EVERY == 0;
        if (!due) continue;
        wifi_tried |= (uint8_t)(1u << i);
        st = mikrotik_rest_get(WIFI_MENUS[i].path, wifi_cb, (void *)WIFI_MENUS[i].sig, MT_LIST_BYTES, &rows);
        if (st == -1 || st == -2 || st == 401 || st == 403) return st;
        if (st == 200) wifi_have |= (uint8_t)(1u << i);
        else wifi_have &= (uint8_t)~(1u << i);          // no such menu on this router
    }

    // Carry first-seen and the new flag over from the served table.
    uint32_t now = (uint32_t)time(NULL);
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        uint8_t f = S->front;
        for (int i = 0; i < S->n_hosts[b]; i++) {
            mikrotik_host_t *h = &S->hosts[b][i];
            h->first_seen = now;
            for (int k = 0; k < S->n_hosts[f]; k++) {
                if (memcmp(S->hosts[f][k].mac, h->mac, 6)) continue;
                h->first_seen = S->hosts[f][k].first_seen;
                h->new_device = S->hosts[f][k].new_device;
                break;
            }
        }
        unlock();
    }
    check_new_devices();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    S->front = b;
    S->as_of = now;
    unlock();
    portENTER_CRITICAL(&s_mux);
    s_stat.hosts = S->n_hosts[b];
    s_stat.leases = S->c_lease;
    s_stat.arp = S->c_arp;
    s_stat.bridge = S->c_bridge;
    s_stat.wifi = S->c_wifi;
    s_stat.wifi_tables = wifi_have;
    portEXIT_CRITICAL(&s_mux);
    return 200;
}

bool mikrotik_host(const uint8_t *mac, uint32_t ip, mikrotik_host_t *out, uint32_t *as_of)
{
    static const uint8_t zero[6] = { 0 };
    if (!S || !s_running || !lock(100)) return false;
    const mikrotik_host_t *t = S->hosts[S->front], *hit = NULL;
    int n = S->n_hosts[S->front];
    if (mac && memcmp(mac, zero, 6))
        for (int i = 0; i < n && !hit; i++) if (!memcmp(t[i].mac, mac, 6)) hit = &t[i];
    for (int i = 0; ip && i < n && !hit; i++) if (t[i].ip == ip && (t[i].src & MIKROTIK_SRC_LEASE)) hit = &t[i];
    for (int i = 0; ip && i < n && !hit; i++) if (t[i].ip == ip) hit = &t[i];
    if (hit) *out = *hit;
    if (as_of) *as_of = S->as_of;
    unlock();
    return hit != NULL;
}

// ── Connections ───────────────────────────────────────────────────────────────

static uint8_t proto_num(const char *p)
{
    if (!strcmp(p, "tcp")) return 6;
    if (!strcmp(p, "udp")) return 17;
    if (!strcmp(p, "icmp")) return 1;
    long n = strtol(p, NULL, 10);
    return (n > 0 && n < 256) ? (uint8_t)n : 0;
}

static bool conn_cb(void *ctx, const mikrotik_row_t *r)
{
    mt_build_t *b = ctx;
    uint32_t src, dst;
    uint16_t sport = 0, dport = 0;
    const char *sa = mikrotik_row_get(r, "src-address");
    if (!parse_ip(sa, &src, &sport)) return true;
    if (strchr(sa, ':')) b->combined = true; else b->plain = true;
    if (src != b->target) return true;          // the router's filter, or ours
    if (b->total >= MIKROTIK_CONN_MAX) { b->truncated = true; return false; }
    const char *da = mikrotik_row_get(r, "dst-address");
    if (!parse_ip(da, &dst, &dport)) return true;
    const char *p;
    if (!sport && (p = mikrotik_row_get(r, "src-port"))[0]) sport = (uint16_t)strtoul(p, NULL, 10);
    if (!dport && (p = mikrotik_row_get(r, "dst-port"))[0]) dport = (uint16_t)strtoul(p, NULL, 10);
    uint8_t proto = proto_num(mikrotik_row_get(r, "protocol"));
    bool ext = ip_external(dst);
    b->total++;
    if (ext) b->external++;

    int k;
    for (k = 0; k < b->n; k++)
        if (b->d[k].ip == dst && b->d[k].port == dport && b->d[k].proto == proto) break;
    if (k == b->n) {
        if (b->n >= MIKROTIK_DST_MAX) { b->truncated = true; return true; }
        memset(&b->d[k], 0, sizeof(b->d[k]));
        b->d[k].ip = dst;
        b->d[k].port = dport;
        b->d[k].proto = proto;
        b->d[k].external = ext;
        b->n_sport[k] = 0;
        b->n++;
    }
    mikrotik_dst_t *d = &b->d[k];
    d->conns++;
    d->bytes_out += strtoull(mikrotik_row_get(r, "orig-bytes"), NULL, 10);
    d->bytes_in  += strtoull(mikrotik_row_get(r, "repl-bytes"), NULL, 10);
    d->pkts_out  += (uint32_t)strtoul(mikrotik_row_get(r, "orig-packets"), NULL, 10);
    d->pkts_in   += (uint32_t)strtoul(mikrotik_row_get(r, "repl-packets"), NULL, 10);
    copy_txt(d->tcp_state, sizeof(d->tcp_state), mikrotik_row_get(r, "tcp-state"));
    if (b->n_sport[k] < MT_SPORTS) b->sport[k][b->n_sport[k]++] = sport;
    return true;
}

static int conn_fetch_once(uint32_t ip, bool client_filter, uint32_t *rows)
{
    mt_build_t *b = &S->build;
    memset(b, 0, offsetof(mt_build_t, d));
    b->target = ip;
    b->client_filter = client_filter;
    static const char PROPS[] = ".proplist=protocol,src-address,src-port,dst-address,dst-port,"
                                "tcp-state,timeout,orig-bytes,repl-bytes,orig-packets,repl-packets";
    char ips[16];
    ip4_addr_t a = { .addr = ip };
    ip4addr_ntoa_r(&a, ips, sizeof(ips));
    if (client_filter) snprintf(S->path, sizeof(S->path), "/ip/firewall/connection?%s", PROPS);
    else snprintf(S->path, sizeof(S->path), "/ip/firewall/connection?src-address=%s&%s", ips, PROPS);
    return mikrotik_rest_get(S->path, conn_cb, b, client_filter ? MT_SCAN_BYTES : MT_CONN_BYTES, rows);
}

static bool beacon_port_skipped(uint8_t proto, uint16_t port)
{
    // TCP and UDP only (new connections are told apart by source port). Time
    // sync and DNS repeat by design (DNS has its own check in correlate.c).
    if (proto != 6 && proto != 17) return true;
    return (proto == 17 && (port == 123 || port == 5353)) || port == 53 || port == 853;
}

// Merge the snapshot into the slot's destination history and mark beacons.
static void history_update(mt_slot_t *sl, mt_build_t *b, uint32_t now, uint32_t unix_now)
{
    for (int k = 0; k < b->n; k++) {
        mikrotik_dst_t *d = &b->d[k];
        mt_hist_t *h = NULL;
        for (int i = 0; i < sl->n_hist && !h; i++)
            if (sl->hist[i].ip == d->ip && sl->hist[i].port == d->port && sl->hist[i].proto == d->proto) h = &sl->hist[i];
        if (!h) {
            if (sl->n_hist < MT_HIST) h = &sl->hist[sl->n_hist++];
            else {
                h = &sl->hist[0];
                for (int i = 1; i < MT_HIST; i++) if (sl->hist[i].seen < h->seen) h = &sl->hist[i];
            }
            memset(h, 0, sizeof(*h));
            h->ip = d->ip;
            h->port = d->port;
            h->proto = d->proto;
            h->first = now;
        }
        d->first_seen = unix_now - (now - h->first);
        d->last_seen = unix_now;
        // New connections: source ports not in the last snapshot.
        int fresh = 0;
        for (int s = 0; s < b->n_sport[k]; s++) {
            bool old = false;
            for (int t = 0; t < h->n_sport && !old; t++) old = h->sport[t] == b->sport[k][s];
            if (!old) fresh++;
        }
        memcpy(h->sport, b->sport[k], sizeof(h->sport));
        h->n_sport = b->n_sport[k];
        h->seen = now;
        if (fresh) {
            if (h->n_obs == MT_OBS) { memmove(h->obs, h->obs + 1, (MT_OBS - 1) * sizeof(h->obs[0])); h->n_obs--; }
            h->obs[h->n_obs++] = now;
            if (fresh > h->max_new) h->max_new = (uint8_t)(fresh > 255 ? 255 : fresh);
            h->conns += (uint32_t)fresh;
        }
        h->bytes = d->bytes_out + d->bytes_in;

        d->beacon_n = 0;
        d->beacon_s = 0;
        if (h->n_obs < MT_BEACON_MIN || h->max_new > MT_BEACON_MAX_NEW || beacon_port_skipped(d->proto, d->port)) continue;
        if (d->conns && h->bytes / d->conns > MT_BEACON_MAX_BYTES) continue;
        uint32_t span = h->obs[h->n_obs - 1] - h->obs[0];
        uint32_t mean = span / (uint32_t)(h->n_obs - 1);
        if (mean < 20 || mean > 3600) continue;
        uint32_t tol = mean / 4 > MT_BEACON_TOL_S ? mean / 4 : MT_BEACON_TOL_S;
        bool regular = true;
        for (int i = 1; i < h->n_obs && regular; i++) {
            uint32_t g = h->obs[i] - h->obs[i - 1];
            regular = (g > mean ? g - mean : mean - g) <= tol;
        }
        if (regular) { d->beacon_n = h->n_obs; d->beacon_s = mean; }
    }
}

// ── Destination names (the router's DNS cache) ────────────────────────────────

static bool dns_lookup(uint32_t ip, char *name, size_t len)
{
    for (int i = 0; i < S->n_dns; i++)
        if (S->dns[i].ip == ip) { strlcpy(name, S->dns[i].name, len); return true; }
    return false;
}

static int names_missing(mt_build_t *b)
{
    int miss = 0;
    for (int i = 0; i < b->n; i++) {
        mikrotik_dst_t *d = &b->d[i];
        if (d->name[0]) continue;
        if (dns_lookup(d->ip, d->name, sizeof(d->name))) d->name_src = MIKROTIK_NAME_ROUTER_DNS;
        else if (d->external) miss++;
    }
    return miss;
}

// A records whose address is one of this snapshot's unnamed external
// destinations go into the ring. Router text: cut to printable ASCII.
static bool dns_cb(void *ctx, const mikrotik_row_t *r)
{
    mt_build_t *b = ctx;
    const char *type = mikrotik_row_get(r, "type");
    if (type[0] && strcmp(type, "A")) return true;
    uint32_t ip;
    if (!parse_ip(mikrotik_row_get(r, "data"), &ip, NULL)) return true;
    bool want = false;
    for (int i = 0; i < b->n && !want; i++) want = b->d[i].external && !b->d[i].name[0] && b->d[i].ip == ip;
    if (!want) return true;
    char name[48];
    copy_txt(name, sizeof(name), mikrotik_row_get(r, "name"));
    if (!name[0]) return true;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int k = -1;
    for (int i = 0; i < S->n_dns && k < 0; i++) if (S->dns[i].ip == ip) k = i;
    if (k < 0) {
        k = S->dns_next;
        S->dns_next = (uint16_t)((S->dns_next + 1) % MIKROTIK_DNS_NAMES);
        if (S->n_dns < MIKROTIK_DNS_NAMES) S->n_dns++;
    }
    S->dns[k].ip = ip;
    strlcpy(S->dns[k].name, name, sizeof(S->dns[k].name));
    unlock();
    for (int i = 0; i < b->n; i++)
        if (b->d[i].ip == ip && !b->d[i].name[0]) {
            strlcpy(b->d[i].name, name, sizeof(b->d[i].name));
            b->d[i].name_src = MIKROTIK_NAME_ROUTER_DNS;
        }
    return true;
}

static void dns_names(mt_build_t *b)
{
    if (!names_missing(b) || up_s() - S->dns_s < MIKROTIK_DNS_EVERY_S) return;
    S->dns_s = up_s();
    uint32_t rows;
    int st = mikrotik_rest_get("/ip/dns/cache?.proplist=name,type,data", dns_cb, b, MT_LIST_BYTES, &rows);
    if (st != 200 && st != -4) ESP_LOGI(TAG, "DNS cache not read (status %d): destinations stay unnamed", st);
}

static void conn_fetch(uint32_t ip)
{
    uint32_t rows = 0;
    int st;
    bool client = s_ct_mode == CT_CLIENT;
    st = conn_fetch_once(ip, client, &rows);
    if (st == -4) { st = 200; S->build.truncated = true; }     // cut at the cap: what was read stands
    if (st == 200 && !client && S->build.total == 0 && s_ct_mode == CT_UNKNOWN) {
        // Nothing matched. Either the device has no connections, or this
        // RouterOS lists src-address as "ip:port" and its exact-match filter
        // missed: read the whole table once and see which form it uses.
        st = conn_fetch_once(ip, true, &rows);
        if (st == -4) { st = 200; S->build.truncated = true; }
        if (st == 200 && S->build.combined) {
            s_ct_mode = CT_CLIENT;
            ESP_LOGW(TAG, "This RouterOS lists src-address as ip:port: connections are filtered here, not by the router");
        } else if (st == 200 && S->build.plain) {
            s_ct_mode = CT_ROUTER;
        }
    } else if (st == 200 && !client && S->build.total) {
        s_ct_mode = CT_ROUTER;
    }
    mt_build_t *b = &S->build;

    // Busiest first.
    for (int i = 1; i < b->n; i++) {
        for (int j = i; j > 0; j--) {
            uint64_t x = b->d[j].bytes_out + b->d[j].bytes_in, y = b->d[j - 1].bytes_out + b->d[j - 1].bytes_in;
            if (x <= y) break;
            mikrotik_dst_t t = b->d[j]; b->d[j] = b->d[j - 1]; b->d[j - 1] = t;
            uint16_t sp[MT_SPORTS]; memcpy(sp, b->sport[j], sizeof(sp));
            memcpy(b->sport[j], b->sport[j - 1], sizeof(sp)); memcpy(b->sport[j - 1], sp, sizeof(sp));
            uint8_t ns = b->n_sport[j]; b->n_sport[j] = b->n_sport[j - 1]; b->n_sport[j - 1] = ns;
        }
    }
    if (st == 200) dns_names(b);
    uint16_t ext_hosts = 0;
    for (int i = 0; i < b->n; i++) {
        if (!b->d[i].external) continue;
        bool dup = false;
        for (int j = 0; j < i && !dup; j++) dup = b->d[j].external && b->d[j].ip == b->d[i].ip;
        if (!dup) ext_hosts++;
    }

    int64_t now = up_s();
    xSemaphoreTake(s_lock, portMAX_DELAY);     // getters hold it briefly; a stuck slot is worse
    mt_slot_t *sl = NULL;
    for (int i = 0; i < MT_SLOTS && !sl; i++) if (S->slot[i].used && S->slot[i].ip == ip) sl = &S->slot[i];
    if (sl) {
        sl->queued = false;
        sl->fetch_s = now;
        mikrotik_conn_t *c = &sl->snap;
        c->ip = ip;
        c->pending = false;
        if (st == 200) {
            history_update(sl, b, (uint32_t)now, (uint32_t)time(NULL));
            c->state = MIKROTIK_CONN_OK;
            c->as_of = (uint32_t)time(NULL);
            c->total = b->total;
            c->external = b->external;
            c->ext_hosts = ext_hosts;
            c->truncated = b->truncated;
            c->n_dst = b->n;
            memcpy(c->dst, b->d, (size_t)b->n * sizeof(b->d[0]));
        } else {
            c->state = MIKROTIK_CONN_ERROR;     // the last good snapshot's data stays
        }
    }
    unlock();
    portENTER_CRITICAL(&s_mux);
    s_stat.conn_fetches++;
    portEXIT_CRITICAL(&s_mux);
}

// A slot for ip: the one it has, else a free one, else the least recently
// used one that is not waiting for a fetch. Under s_lock.
static mt_slot_t *slot_for(uint32_t ip, const uint8_t *mac, int64_t now)
{
    mt_slot_t *sl = NULL, *lru = NULL;
    for (int i = 0; i < MT_SLOTS && !sl; i++)
        if (S->slot[i].used && S->slot[i].ip == ip) sl = &S->slot[i];
    for (int i = 0; i < MT_SLOTS && !sl && !lru; i++)
        if (!S->slot[i].used) lru = &S->slot[i];
    for (int i = 0; i < MT_SLOTS && !sl && !lru; i++) {
        mt_slot_t *s = &S->slot[i];
        if (s->queued) continue;
        mt_slot_t *best = s;
        for (int j = i + 1; j < MT_SLOTS; j++)
            if (!S->slot[j].queued && S->slot[j].touch_s < best->touch_s) best = &S->slot[j];
        lru = best;
    }
    if (!sl && lru) {
        sl = lru;
        memset(sl, 0, sizeof(*sl));
        sl->used = true;
        sl->ip = ip;
        sl->req_s = sl->fetch_s = -1000000;
    }
    if (sl) {
        sl->touch_s = now;
        if (mac) memcpy(sl->mac, mac, 6);
    }
    return sl;
}

bool mikrotik_conn_request(uint32_t ip, const uint8_t *mac)
{
    if (!S || !s_running || !ip_private(ip) || !lock(100)) return false;
    int64_t now = up_s();
    bool q = false;
    mt_slot_t *sl = slot_for(ip, mac, now);
    if (sl) {
        sl->watch_until_s = now + MIKROTIK_WATCH_S;
        if (!sl->queued && now - sl->req_s >= MIKROTIK_CONN_MIN_S && now - sl->fetch_s >= MIKROTIK_CONN_MIN_S) {
            sl->req_s = now;
            sl->queued = sl->snap.pending = true;
            q = true;
        }
    }
    unlock();
    if (q) {
        mt_req_t r = { .kind = REQ_CONN, .ip = ip };
        if (xQueueSend(s_q, &r, 0) != pdTRUE) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            if (sl->ip == ip) sl->queued = sl->snap.pending = false;
            unlock();
            q = false;
        }
    }
    return q;
}

bool mikrotik_conn_get(uint32_t ip, mikrotik_conn_t *out)
{
    memset(out, 0, offsetof(mikrotik_conn_t, dst));
    out->ip = ip;
    if (!S || !s_running || !lock(100)) return false;
    bool have = false;
    for (int i = 0; i < MT_SLOTS; i++) {
        mt_slot_t *s = &S->slot[i];
        if (!s->used || s->ip != ip) continue;
        memcpy(out, &s->snap, offsetof(mikrotik_conn_t, dst) + (size_t)s->snap.n_dst * sizeof(s->snap.dst[0]));
        out->pending = s->queued;
        have = s->snap.as_of != 0;
        break;
    }
    unlock();
    return have;
}

// ── Status and test ───────────────────────────────────────────────────────────

const char *mikrotik_state_key(mikrotik_state_t s)
{
    static const char *const K[] = { "off", "starting", "ok", "unreachable", "auth_failed", "cert_mismatch", "http_error" };
    return (unsigned)s < sizeof(K) / sizeof(K[0]) ? K[s] : "?";
}

void mikrotik_get_status(mikrotik_status_t *out)
{
    portENTER_CRITICAL(&s_mux);
    *out = s_stat;
    portEXIT_CRITICAL(&s_mux);
    out->running = s_running;
    if (!settings_mikrotik_enabled()) out->state = MIKROTIK_ST_OFF;
    const settings_t *st = settings_get();
    out->https = !strncmp(st->mikrotik_url, "https://", 8);
    out->pin_set = st->mikrotik_cert_sha256[0] != '\0';
}

uint32_t mikrotik_request_test(void)
{
    if (!s_running || !s_q) return 0;
    portENTER_CRITICAL(&s_mux);
    uint32_t n = ++s_test_next;
    s_stat.test_req = n;
    portEXIT_CRITICAL(&s_mux);
    mt_req_t r = { .kind = REQ_TEST };
    return xQueueSend(s_q, &r, 0) == pdTRUE ? n : 0;
}

void mikrotik_settings_changed(void)
{
    if (!s_running || !s_q) return;
    mt_req_t r = { .kind = REQ_KICK };
    xQueueSend(s_q, &r, 0);
}

typedef struct { char board[40], version[40]; } mt_res_t;

static bool res_cb(void *ctx, const mikrotik_row_t *r)
{
    mt_res_t *x = ctx;
    copy_txt(x->board, sizeof(x->board), mikrotik_row_get(r, "board-name"));
    copy_txt(x->version, sizeof(x->version), mikrotik_row_get(r, "version"));
    return false;
}

static int run_test(void)
{
    mt_res_t x = { 0 };
    uint32_t rows;
    int st = mikrotik_rest_get("/system/resource?.proplist=board-name,version", res_cb, &x, 4096, &rows);
    char text[96];
    if (st == 200) snprintf(text, sizeof(text), "%s, RouterOS %s", x.board[0] ? x.board : "?", x.version[0] ? x.version : "?");
    else if (st == -2) strlcpy(text, "certificate is not the pinned or recorded one", sizeof(text));
    else if (st == -1) strlcpy(text, "no connection", sizeof(text));
    else if (st == 401 || st == 403) strlcpy(text, "refused: check user, password, policy and allowed address", sizeof(text));
    else snprintf(text, sizeof(text), "HTTP %d", st);
    portENTER_CRITICAL(&s_mux);
    s_stat.test_done = s_stat.test_req;
    s_stat.test_status = st;
    s_stat.test_ok = st == 200;
    strlcpy(s_stat.test_text, text, sizeof(s_stat.test_text));
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGI(TAG, "Test: %s", text);
    return st;
}

// ── Task ──────────────────────────────────────────────────────────────────────

static mikrotik_state_t state_of(int st)
{
    if (st == 200) return MIKROTIK_ST_OK;
    if (st == -2) return MIKROTIK_ST_CERT;
    if (st == -1) return MIKROTIK_ST_UNREACHABLE;
    if (st == 401 || st == 403) return MIKROTIK_ST_AUTH;
    return MIKROTIK_ST_HTTP;
}

static void watch_incident(int64_t now)
{
    alarm_info_t a;
    alarm_get(&a);
    if (a.state == ALARM_IDLE || !a.src_ip || !ip_private(a.src_ip) || !lock(100)) return;
    mt_slot_t *sl = slot_for(a.src_ip, a.src_mac, now);
    if (sl && sl->watch_until_s < now + 2 * MT_INCIDENT_CHECK_S) sl->watch_until_s = now + 2 * MT_INCIDENT_CHECK_S;
    unlock();
}

// The watched device most overdue for a fetch, 0 if none.
static uint32_t watched_due(int64_t now)
{
    uint32_t ip = 0;
    int64_t oldest = now;
    if (!lock(100)) return 0;
    for (int i = 0; i < MT_SLOTS; i++) {
        mt_slot_t *s = &S->slot[i];
        if (!s->used || s->queued || s->watch_until_s < now) continue;
        if (now - s->fetch_s < MIKROTIK_WATCH_POLL_S || s->fetch_s >= oldest) continue;
        oldest = s->fetch_s;
        ip = s->ip;
    }
    if (ip) for (int i = 0; i < MT_SLOTS; i++) if (S->slot[i].used && S->slot[i].ip == ip) S->slot[i].queued = true;
    unlock();
    return ip;
}

static void mikrotik_task(void *arg)
{
    (void)arg;
    uint32_t n_poll = 0, backoff = 0;
    int64_t next_poll = up_s() + MT_FIRST_POLL_S, next_inc = 0, next_own = 0;
    mikrotik_state_t logged = MIKROTIK_ST_STARTING;
    bool hw_logged = false;
    ESP_LOGI(TAG, "Started (%u B state in PSRAM, read only, poll every %d s)", (unsigned)sizeof(*S), MIKROTIK_POLL_S);

    for (;;) {
        mt_req_t r = { 0 };
        bool got = xQueueReceive(s_q, &r, pdMS_TO_TICKS(1000)) == pdTRUE;
        int64_t now = up_s();
        bool on = settings_mikrotik_enabled();
        if (!on) {
            portENTER_CRITICAL(&s_mux);
            s_stat.state = MIKROTIK_ST_OFF;
            s_stat.next_s = 0;
            portEXIT_CRITICAL(&s_mux);
            if (got && r.kind == REQ_CONN) {
                xSemaphoreTake(s_lock, portMAX_DELAY);
                for (int i = 0; i < MT_SLOTS; i++) if (S->slot[i].ip == r.ip) S->slot[i].queued = S->slot[i].snap.pending = false;
                unlock();
            }
            if (got && r.kind == REQ_TEST) run_test();
            next_poll = now + MT_FIRST_POLL_S;
            continue;
        }
        if (!wifi_manager_is_connected()) {
            if (got && r.kind == REQ_CONN) {
                xSemaphoreTake(s_lock, portMAX_DELAY);
                for (int i = 0; i < MT_SLOTS; i++) if (S->slot[i].ip == r.ip) S->slot[i].queued = S->slot[i].snap.pending = false;
                unlock();
            }
            if (got && r.kind == REQ_TEST) {
                portENTER_CRITICAL(&s_mux);
                s_stat.test_done = s_stat.test_req;
                s_stat.test_status = -1;
                s_stat.test_ok = false;
                strlcpy(s_stat.test_text, "the board has no Wi-Fi connection", sizeof(s_stat.test_text));
                portEXIT_CRITICAL(&s_mux);
            }
            continue;
        }

        mikrotik_state_t cur;
        portENTER_CRITICAL(&s_mux);
        cur = s_stat.state;
        portEXIT_CRITICAL(&s_mux);
        bool healthy = cur == MIKROTIK_ST_OK || cur == MIKROTIK_ST_STARTING;

        if (got && r.kind == REQ_KICK) { backoff = 0; next_poll = now + 2; }
        if (got && r.kind == REQ_TEST && run_test() == 200 && !healthy) { backoff = 0; next_poll = now; }
        if (got && r.kind == REQ_CONN) {
            if (healthy) conn_fetch(r.ip);
            else {                      // the router is failing: keep the last snapshot, mark it
                xSemaphoreTake(s_lock, portMAX_DELAY);
                for (int i = 0; i < MT_SLOTS; i++) {
                    mt_slot_t *s = &S->slot[i];
                    if (s->used && s->ip == r.ip) { s->queued = s->snap.pending = false; s->snap.state = MIKROTIK_CONN_ERROR; }
                }
                unlock();
            }
        }
        if (now >= next_inc) { next_inc = now + MT_INCIDENT_CHECK_S; watch_incident(now); }
        if (healthy) {
            uint32_t ip = watched_due(now);
            if (ip) conn_fetch(ip);
            else mikrotik_watch_tick();         // router integrity: one menu when due
        }

        if (now < next_poll) {
            portENTER_CRITICAL(&s_mux);
            s_stat.next_s = (uint32_t)(next_poll - now);
            portEXIT_CRITICAL(&s_mux);
            continue;
        }
        n_poll++;
        if (now >= next_own && own_fetch()) next_own = up_s() + MIKROTIK_OWN_EVERY_S;   // else at the next poll
        int st = poll_router(n_poll);
        mikrotik_state_t ns = state_of(st);
        uint32_t t = (uint32_t)time(NULL);
        if (ns == MIKROTIK_ST_OK) {
            backoff = 0;
            next_poll = up_s() + MIKROTIK_POLL_S;
            stat_set_detail("");
        } else {
            backoff = backoff ? (backoff * 2 > MT_BACKOFF_MAX_S ? MT_BACKOFF_MAX_S : backoff * 2) : MT_BACKOFF_MIN_S;
            next_poll = up_s() + backoff;
            if (ns == MIKROTIK_ST_CERT) stat_set_detail("certificate is not the pinned or recorded one");
            else if (ns == MIKROTIK_ST_UNREACHABLE) stat_set_detail("no connection to the router");
            else if (ns == MIKROTIK_ST_AUTH) stat_set_detail("refused: check user, password, policy and allowed address");
        }
        portENTER_CRITICAL(&s_mux);
        s_stat.state = ns;
        s_stat.polls++;
        if (ns == MIKROTIK_ST_OK) s_stat.last_ok = t; else s_stat.failures++;
        s_stat.last_try = t;
        s_stat.backoff_s = backoff;
        s_stat.next_s = (uint32_t)(next_poll - up_s());
        portEXIT_CRITICAL(&s_mux);
        if (ns != logged) {             // one line per change, not per retry
            if (ns == MIKROTIK_ST_OK) ESP_LOGI(TAG, "Router answering: %u hosts (%u leases, %u ARP, %u bridge, %u Wi-Fi)",
                                               (unsigned)s_stat.hosts, (unsigned)s_stat.leases, (unsigned)s_stat.arp,
                                               (unsigned)s_stat.bridge, (unsigned)s_stat.wifi);
            else ESP_LOGW(TAG, "Router %s (status %d), retrying in %lu s, then less often",
                          mikrotik_state_key(ns), st, (unsigned long)backoff);
            logged = ns;
        }
        if (!hw_logged && ns == MIKROTIK_ST_OK) {
            hw_logged = true;
            ESP_LOGI(TAG, "Stack high-water %u B of %d after the first poll",
                     (unsigned)uxTaskGetStackHighWaterMark(NULL), MIKROTIK_TASK_STACK);
        }
    }
}

bool mikrotik_running(void) { return s_running; }

void mikrotik_start(void)
{
    if (s_running || !settings_mikrotik_enabled()) return;
    if (!S) {
        S = heap_caps_calloc(1, sizeof(*S), MALLOC_CAP_SPIRAM);
        s_dummy_ca = heap_caps_calloc(1, sizeof(*s_dummy_ca), MALLOC_CAP_SPIRAM);
        s_lock = xSemaphoreCreateMutex();
        s_q = xQueueCreateWithCaps(MT_REQ_DEPTH, sizeof(mt_req_t), MALLOC_CAP_SPIRAM);
        if (!S || !s_dummy_ca || !s_lock || !s_q) {
            ESP_LOGE(TAG, "Not started: out of memory");
            free(S);
            free(s_dummy_ca);
            S = NULL;
            s_dummy_ca = NULL;
            if (s_lock) { vSemaphoreDelete(s_lock); s_lock = NULL; }
            if (s_q) { vQueueDeleteWithCaps(s_q); s_q = NULL; }
            return;
        }
        // NVS here, on the caller's internal stack: the task never touches it.
        nvs_handle_t h;
        if (nvs_open(MT_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
            size_t n = sizeof(s_tofu);
            if (nvs_get_blob(h, "tofu", s_tofu, &n) == ESP_OK && n == sizeof(s_tofu)) s_tofu_set = true;
            n = sizeof(S->known);
            if (nvs_get_blob(h, "known", S->known, &n) == ESP_OK && n % 6 == 0) {
                S->n_known = (uint16_t)(n / 6);
                S->learned = true;
            }
            nvs_close(h);
        }
        mikrotik_watch_load();          // armed digests, from NVS on this stack
        s_stat.state = MIKROTIK_ST_STARTING;
        s_stat.known = S->n_known;
        s_stat.learned = S->learned;
        if (s_tofu_set) hex32(s_tofu, s_stat.tofu);
    }
    if (xTaskCreatePinnedToCoreWithCaps(mikrotik_task, "mikrotik", MIKROTIK_TASK_STACK, NULL, MIKROTIK_TASK_PRIO,
                                        NULL, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        ESP_LOGE(TAG, "Not started: no memory for the task");
        return;
    }
    s_running = true;
}
