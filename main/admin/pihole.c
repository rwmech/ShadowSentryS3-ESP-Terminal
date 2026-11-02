// Pi-hole v6 client. See pihole.h.

#include "pihole.h"
#include "correlate.h"          // correlate_pihole_device(), the device intelligence hook
#include "settings.h"
#include "json_esc.h"
#include "discovery.h"
#include "log_store.h"
#include "wifi_manager.h"
#include "cJSON.h"
#include "mdns.h"
#include "esp_http_client.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "PIHOLE";

#define CLOCK_VALID     1700000000u     // epoch after SNTP
#define WANT_MAX        4               // on-demand device fetches waiting
#define SESSION_SLACK_S 30              // re-auth this long before Pi-hole's expiry

// ── Cache (PSRAM) ─────────────────────────────────────────────────────────────

// How Pi-hole blocked a name, a bit each (ph_top_t.how), from the query status.
#define PH_BLK_GRAVITY   0x01           // GRAVITY, GRAVITY_CNAME: a block list
#define PH_BLK_REGEX     0x02           // REGEX, REGEX_CNAME
#define PH_BLK_DENYLIST  0x04           // DENYLIST, DENYLIST_CNAME: the user's own
#define PH_BLK_UPSTREAM  0x08           // EXTERNAL_BLOCKED_*: the upstream server
#define PH_BLK_OTHER     0x10           // SPECIAL_DOMAIN, DBBUSY
static const char *const BLK_KEY[] = { "gravity", "regex", "denylist", "upstream", "other" };   // by bit, for the JSON
_Static_assert(PIHOLE_TOP_SAMPLE <= UINT16_MAX, "ph_top_t counts are 16 bit");

// n queries of the sample; allowed + blocked <= n (UNKNOWN, IN_PROGRESS and
// statuses this firmware does not know count in neither).
typedef struct {
    char     d[PIHOLE_DOMAIN_LEN];
    uint32_t n;
    uint16_t allowed, blocked;
    uint8_t  how;                       // PH_BLK_* bits
} ph_top_t;

typedef struct {
    bool     used, mac_known;
    uint8_t  mac[6];
    uint8_t  n_ip, n_name, n_top;
    char     ip[PIHOLE_IPS][PIHOLE_IP_LEN];
    char     name[PIHOLE_NAMES][PIHOLE_NAME_LEN];
    char     vendor[PIHOLE_VENDOR_LEN];
    uint32_t first, last;               // epoch: Pi-hole's firstSeen and lastQuery
    uint32_t all_queries;               // numQueries in Pi-hole's network table
    int32_t  queries, blocked;          // top_clients over the in-memory window, -1 unknown
    uint16_t top_of;                    // queries the top list was counted over
    uint32_t top_ts;                    // epoch it was counted, 0 never
    ph_top_t top[PIHOLE_TOP_N];
} ph_dev_t;

typedef struct {
    ph_dev_t dev[PIHOLE_DEV_MAX];
    int      n;
    uint32_t as_of;                     // epoch of the sync, 0 before SNTP
} ph_table_t;

// Where requests go. The session belongs to the one it was made with.
typedef struct {
    bool     tls;
    uint16_t port;
    char     host[64];
    char     pw[129];
    char     pin[65];
} conn_t;

typedef struct { uint32_t ip; uint8_t mac[6]; bool mac_known; } known_t;

// The task's work state. Only the task touches it, except tab[], which is
// published through s_cur under s_mux.
typedef struct {
    settings_t         set;
    conn_t             c, want;
    char               resp[PIHOLE_RESP_MAX + 1];
    char               body[320];
    char               url[160];
    char               err[PIHOLE_ERR_LEN];
    char               logged_err[PIHOLE_ERR_LEN];     // the last error logged, each new one once
    discovery_talker_t talk[DISCOVERY_DEV_MAX];
    attack_log_t       recent[PIHOLE_RECENT];
    known_t            known[PIHOLE_KNOWN_MAX];
    struct { const char *d; uint32_t n; uint16_t allowed, blocked; uint8_t how; } cnt[PIHOLE_TOP_SAMPLE];
    ph_table_t         tab[2];
} work_t;

static work_t           *W;
static ph_table_t       *s_cur;         // published table, NULL before the first sync
static SemaphoreHandle_t s_mux;         // s_cur, s_st, the request fields
static TaskHandle_t      s_task;
static pihole_status_t  *s_st;          // PSRAM, from pihole_init()
static uint32_t          s_next_up;     // uptime of the next sync
static uint32_t          s_refresh_up;  // last on-demand refresh accepted
static bool              s_refresh;
static uint32_t          s_want[WANT_MAX];
static uint32_t          s_test_req;

// Task-only session state. The SID is never logged or returned.
static char     s_sid[40];
static bool     s_session;
static uint32_t s_sid_exp_up;
static uint32_t s_valid_s = 300;        // session.validity from the last login
static uint32_t s_ip;                   // resolved, network order, 0 = resolve again
static int      s_fails;
static int      s_rr;                   // round-robin cursor over the known devices
static bool     s_hw_logged;

static uint32_t up_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static uint32_t epoch(void)
{
    uint32_t t = (uint32_t)time(NULL);
    return t >= CLOCK_VALID ? t : 0;
}

static void fmt_ip(uint32_t ip, char *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static bool fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static bool fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(W->err, sizeof(W->err), fmt, ap);
    va_end(ap);
    return false;
}

// ── cJSON in PSRAM ────────────────────────────────────────────────────────────

static void *json_malloc(size_t n)
{
    return heap_caps_malloc_prefer(n, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT, MALLOC_CAP_DEFAULT);
}

// ── TLS: certificate pin ──────────────────────────────────────────────────────
//
// esp-tls calls the attach hook with the mbedtls config of each connection,
// after setting VERIFY_REQUIRED. The hook installs a verify callback and an
// empty trust chain (mbedtls wants one; esp_crt_bundle does the same). mbedtls
// calls the callback for each certificate of the chain it built, top first,
// leaf (depth 0) last; the leaf's flags decide. One TLS connection at a time
// (this task), so one context serves.

static const mbedtls_x509_crt s_dummy_ca;
static struct { uint8_t want[32]; bool matched; char seen[65]; } s_pin;

static void hex32(const uint8_t *h, char *out)
{
    static const char x[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = x[h[i] >> 4]; out[2 * i + 1] = x[h[i] & 15]; }
    out[64] = '\0';
}

static int pin_verify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx;
    uint8_t h[32];
    if (mbedtls_sha256(crt->raw.p, crt->raw.len, h, 0) == 0 && !memcmp(h, s_pin.want, 32)) s_pin.matched = true;
    if (depth == 0) {
        hex32(h, s_pin.seen);
        *flags = s_pin.matched ? 0 : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    } else {
        *flags = 0;                     // the pin, not a CA store, decides
    }
    return 0;
}

static esp_err_t pin_attach(void *conf)
{
    mbedtls_ssl_config *c = conf;
    s_pin.matched = false;
    s_pin.seen[0] = '\0';
    mbedtls_ssl_conf_verify(c, pin_verify, NULL);
    mbedtls_ssl_conf_ca_chain(c, (mbedtls_x509_crt *)&s_dummy_ca, NULL);
    return ESP_OK;
}

static bool pin_load(const char *hex)
{
    if (strlen(hex) != 64) return false;
    for (int i = 0; i < 32; i++) {
        char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        char *end;
        s_pin.want[i] = (uint8_t)strtoul(b, &end, 16);
        if (*end) return false;
    }
    return true;
}

// ── Resolve ───────────────────────────────────────────────────────────────────
//
// A dotted quad as is; else getaddrinfo (DNS, and .local by lwIP's one-shot
// mDNS query, CONFIG_LWIP_DNS_SUPPORT_MDNS_QUERIES); else, for .local, the
// mdns component's query.

static bool resolve(const conn_t *c)
{
    if (s_ip) return true;
    struct in_addr a;
    if (inet_aton(c->host, &a)) { s_ip = a.s_addr; return true; }
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    if (getaddrinfo(c->host, NULL, &hints, &res) == 0 && res) {
        s_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
        if (s_ip) return true;
    }
    size_t n = strlen(c->host);
    if (n > 6 && !strcasecmp(c->host + n - 6, ".local")) {
        char name[64];
        snprintf(name, sizeof(name), "%.*s", (int)(n - 6), c->host);
        esp_ip4_addr_t ip = { 0 };
        if (mdns_query_a(name, 2000, &ip) == ESP_OK && ip.addr) { s_ip = ip.addr; return true; }
    }
    return fail("cannot resolve %s", c->host);
}

// ── One request ───────────────────────────────────────────────────────────────
//
// To the resolved IP, with the configured name in Host. The response is read
// into W->resp (NUL-terminated, *len bytes). Returns the HTTP status, -1 on a
// transport error (the IP is resolved again next time), -2 when the response
// is over PIHOLE_RESP_MAX (skipped and counted).

static int request(const conn_t *c, esp_http_client_method_t m, const char *path,
                   const char *body, size_t blen, bool sid, size_t *len)
{
    *len = 0;
    W->resp[0] = '\0';
    char ip[16];
    fmt_ip(s_ip, ip, sizeof(ip));
    snprintf(W->url, sizeof(W->url), "%s://%s:%u%s", c->tls ? "https" : "http", ip, (unsigned)c->port, path);
    // No pin yet: the handshake still runs (and fails), so the status can show
    // the server's fingerprint for Rob to check and paste into Settings.
    if (c->tls && !pin_load(c->pin)) memset(s_pin.want, 0, sizeof(s_pin.want));
    esp_http_client_config_t cfg = {
        .url = W->url,
        .method = m,
        .timeout_ms = PIHOLE_TIMEOUT_MS,
        .buffer_size = 1024,
        .buffer_size_tx = 1024,
        .disable_auto_redirect = true,
        .crt_bundle_attach = c->tls ? pin_attach : NULL,
        .common_name = c->tls ? c->host : NULL,         // SNI; the pin decides trust
    };
    esp_http_client_handle_t h = esp_http_client_init(&cfg);
    if (!h) return -1;
    char host[72];
    if (c->port == (c->tls ? 443 : 80)) strlcpy(host, c->host, sizeof(host));
    else snprintf(host, sizeof(host), "%s:%u", c->host, (unsigned)c->port);
    esp_http_client_set_header(h, "Host", host);
    esp_http_client_set_header(h, "Accept", "application/json");
    if (sid && s_sid[0]) esp_http_client_set_header(h, "X-FTL-SID", s_sid);
    if (body) esp_http_client_set_header(h, "Content-Type", "application/json");
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->requests++;
    xSemaphoreGive(s_mux);

    int status = -1;
    if (esp_http_client_open(h, body ? (int)blen : 0) != ESP_OK) goto out;
    for (size_t sent = 0; body && sent < blen;) {
        int w = esp_http_client_write(h, body + sent, (int)(blen - sent));
        if (w <= 0) goto out;
        sent += (size_t)w;
    }
    int64_t cl = esp_http_client_fetch_headers(h);
    if (cl < 0) goto out;
    int code = esp_http_client_get_status_code(h);
    if (cl > PIHOLE_RESP_MAX) { status = -2; goto out; }
    size_t n = 0;
    while (n < PIHOLE_RESP_MAX) {
        int r = esp_http_client_read(h, W->resp + n, (int)(PIHOLE_RESP_MAX - n));
        if (r < 0) goto out;
        if (r == 0) break;
        n += (size_t)r;
    }
    if (n >= PIHOLE_RESP_MAX && !esp_http_client_is_complete_data_received(h)) { status = -2; goto out; }
    W->resp[n] = '\0';
    *len = n;
    status = code;
out:
    esp_http_client_close(h);
    esp_http_client_cleanup(h);
    if (status == -1) s_ip = 0;
    if (status == -2) {
        xSemaphoreTake(s_mux, portMAX_DELAY);
        s_st->oversized++;
        xSemaphoreGive(s_mux);
        ESP_LOGW(TAG, "Response to %.40s over %u B: skipped", path, (unsigned)PIHOLE_RESP_MAX);
        W->resp[0] = '\0';
    }
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->last_http = status == -2 ? 200 : status;
    if (c->tls) strlcpy(s_st->tls_seen, s_pin.seen, sizeof(s_st->tls_seen));
    xSemaphoreGive(s_mux);
    return status;
}

static bool transport_fail(const conn_t *c, int st, const char *what)
{
    if (st == -2) return fail("%s: response over %u KB, skipped", what, (unsigned)(PIHOLE_RESP_MAX / 1024));
    if (c->tls && s_pin.seen[0] && !s_pin.matched)
        return fail("%s: the server's certificate SHA-256 %s is not the pinned one", what, s_pin.seen);
    if (c->tls && !c->pin[0]) return fail("%s: https needs the certificate SHA-256 in Settings", what);
    return fail("%s: no connection to %s", what, c->host);
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

static const cJSON *jget(const cJSON *o, const char *k) { return cJSON_GetObjectItemCaseSensitive(o, k); }

static const char *jstr(const cJSON *o, const char *k)
{
    const cJSON *it = jget(o, k);
    return cJSON_IsString(it) && it->valuestring ? it->valuestring : NULL;
}

static double jnum(const cJSON *o, const char *k, double dflt)
{
    const cJSON *it = jget(o, k);
    return cJSON_IsNumber(it) ? it->valuedouble : dflt;
}

static uint32_t ju32(const cJSON *o, const char *k)
{
    double d = jnum(o, k, 0);
    return d <= 0 ? 0 : d >= 4294967295.0 ? UINT32_MAX : (uint32_t)d;
}

// ── Session ───────────────────────────────────────────────────────────────────

static void wipe_resp(void) { memset(W->resp, 0, sizeof(W->resp)); }

static void logout(const conn_t *c)
{
    if (s_session && s_sid[0] && s_ip) {
        size_t len;
        int st = request(c, HTTP_METHOD_DELETE, "/api/auth", NULL, 0, true, &len);
        ESP_LOGI(TAG, "Logged out (HTTP %d)", st);
    }
    memset(s_sid, 0, sizeof(s_sid));
    s_session = false;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->session = false;
    xSemaphoreGive(s_mux);
}

// Not a v6 answer on /api/auth: a v5 Pi-hole has /admin/api.php instead.
static bool not_v6(const conn_t *c, int st)
{
    size_t len;
    int v = request(c, HTTP_METHOD_GET, "/admin/api.php?versions", NULL, 0, false, &len);
    bool v5 = false;
    if (v == 200) {
        cJSON *r = cJSON_ParseWithLength(W->resp, len);
        v5 = r && jget(r, "core_current");
        cJSON_Delete(r);
    }
    if (v5) {
        xSemaphoreTake(s_mux, portMAX_DELAY);
        strlcpy(s_st->state, "v5", sizeof(s_st->state));
        xSemaphoreGive(s_mux);
        return fail("Pi-hole v5 detected: not supported in this build");
    }
    return fail("not a Pi-hole v6 API: HTTP %d on /api/auth", st);
}

static bool auth(const conn_t *c)
{
    memcpy(W->body, "{\"password\":\"", 13);
    size_t n = 13 + json_esc(c->pw, sizeof(c->pw), W->body + 13, sizeof(W->body) - 13 - 3);
    memcpy(W->body + n, "\"}", 3);
    n += 2;
    size_t len;
    int st = request(c, HTTP_METHOD_POST, "/api/auth", W->body, n, false, &len);
    memset(W->body, 0, sizeof(W->body));
    if (st < 0) return transport_fail(c, st, "login");
    cJSON *r = cJSON_ParseWithLength(W->resp, len);
    wipe_resp();                                    // it held the SID
    const cJSON *sess = r ? jget(r, "session") : NULL;
    const cJSON *er = r ? jget(r, "error") : NULL;
    const char *key = er ? jstr(er, "key") : NULL;
    const char *msg = er ? jstr(er, "message") : NULL;
    bool ok = false;
    if (sess && st == 200 && cJSON_IsTrue(jget(sess, "valid"))) {
        const char *sid = jstr(sess, "sid");        // null when the Pi-hole has no password
        memset(s_sid, 0, sizeof(s_sid));
        if (sid && strlen(sid) < sizeof(s_sid)) strlcpy(s_sid, sid, sizeof(s_sid));
        double v = jnum(sess, "validity", 300);         // -1 when the Pi-hole has no password
        s_valid_s = v > SESSION_SLACK_S * 2 && v < 86400 * 30 ? (uint32_t)v : 300;
        s_sid_exp_up = up_s() + s_valid_s - SESSION_SLACK_S;
        s_session = true;
        ok = true;
    } else if (sess && st == 401) {
        fail("password rejected (HTTP 401): use an app password from Pi-hole's Settings, Web interface / API");
    } else if (key && !strcmp(key, "api_seats_exceeded")) {
        fail("Pi-hole has no free API session seats (HTTP %d)", st);
    } else if (key && !strcmp(key, "rate_limiting")) {
        fail("Pi-hole is rate-limiting logins (HTTP %d)", st);
    } else if (key && msg && strstr(msg, "2FA")) {
        fail("Pi-hole wants a 2FA code: use an app password, which skips 2FA");
    } else if (key && !strcmp(key, "unauthorized")) {
        fail("unauthorized (HTTP %d)", st);
    } else if (!sess && !key) {
        cJSON_Delete(r);
        return not_v6(c, st);
    } else {
        fail("login failed: HTTP %d", st);
    }
    cJSON_Delete(r);
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->session = ok;
    xSemaphoreGive(s_mux);
    return ok;
}

// GET path with the session: logs in when there is none or it has lapsed, and
// once more after a 401 (Pi-hole restarted, or the session was revoked).
static int api_get(const conn_t *c, const char *path, size_t *len)
{
    for (int round = 0; round < 2; round++) {
        if (!s_session || (int32_t)(up_s() - s_sid_exp_up) >= 0) {
            s_session = false;
            if (!auth(c)) return 0;
        }
        int st = request(c, HTTP_METHOD_GET, path, NULL, 0, true, len);
        if (st == 401) { s_session = false; memset(s_sid, 0, sizeof(s_sid)); continue; }
        if (st == 200) s_sid_exp_up = up_s() + s_valid_s - SESSION_SLACK_S;   // each request restarts it
        if (st < 0) { transport_fail(c, st, path); return 0; }
        if (st != 200) { fail("%.40s: HTTP %d", path, st); return 0; }
        return st;
    }
    fail("%.40s: HTTP 401 after a fresh login", path);
    return 0;
}

static bool get_version(const conn_t *c)
{
    size_t len;
    if (!api_get(c, "/api/info/version", &len)) return false;
    cJSON *r = cJSON_ParseWithLength(W->resp, len);
    const cJSON *v = r ? jget(r, "version") : NULL;
    if (!v) { cJSON_Delete(r); return fail("/api/info/version: no version object"); }
    char out[64] = "";
    static const char *const parts[] = { "core", "web", "ftl" };
    static const char *const label[] = { "core", "web", "FTL" };
    size_t o = 0;
    for (int i = 0; i < 3; i++) {
        const cJSON *p = jget(v, parts[i]);
        const char *s = p ? jstr(jget(p, "local"), "version") : NULL;
        if (!s) continue;
        int w = snprintf(out + o, sizeof(out) - o, "%s%s %.12s", o ? ", " : "", label[i], s);
        if (w < 0 || (size_t)w >= sizeof(out) - o) break;
        o += (size_t)w;
    }
    cJSON_Delete(r);
    xSemaphoreTake(s_mux, portMAX_DELAY);
    strlcpy(s_st->version, out, sizeof(s_st->version));
    xSemaphoreGive(s_mux);
    return true;
}

// ── Sync ──────────────────────────────────────────────────────────────────────

static bool mac_parse(const char *s, uint8_t mac[6])
{
    unsigned b[6];
    char tail;
    if (!s || strlen(s) != 17 ||
        sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
    return mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5];
}

static ph_dev_t *find(ph_table_t *t, const uint8_t *mac, const char *ip)
{
    if (mac && (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]))
        for (int i = 0; i < t->n; i++)
            if (t->dev[i].mac_known && !memcmp(t->dev[i].mac, mac, 6)) return &t->dev[i];
    if (ip && ip[0])
        for (int i = 0; i < t->n; i++)
            for (int k = 0; k < t->dev[i].n_ip; k++)
                if (!strcmp(t->dev[i].ip[k], ip)) return &t->dev[i];
    return NULL;
}

static ph_dev_t *add(ph_table_t *t)
{
    if (t->n >= PIHOLE_DEV_MAX) return NULL;
    ph_dev_t *d = &t->dev[t->n++];
    memset(d, 0, sizeof(*d));
    d->used = true;
    d->queries = d->blocked = -1;
    return d;
}

static void add_name(ph_dev_t *d, const char *name)
{
    if (!name || !name[0] || d->n_name >= PIHOLE_NAMES) return;
    for (int i = 0; i < d->n_name; i++) if (!strcmp(d->name[i], name)) return;
    strlcpy(d->name[d->n_name++], name, PIHOLE_NAME_LEN);
}

static void add_ip(ph_dev_t *d, const char *ip)
{
    if (!ip || !ip[0] || d->n_ip >= PIHOLE_IPS) return;
    for (int i = 0; i < d->n_ip; i++) if (!strcmp(d->ip[i], ip)) return;
    strlcpy(d->ip[d->n_ip++], ip, PIHOLE_IP_LEN);
}

// GET /api/network/devices: devices[] {hwaddr, firstSeen, lastQuery,
// numQueries, macVendor, ips[] {ip, name}}, newest query first. hwaddr is
// "ip-<addr>" for a device without a known MAC.
static bool sync_devices(const conn_t *c, ph_table_t *t)
{
    char path[80];
    snprintf(path, sizeof(path), "/api/network/devices?max_devices=%d&max_addresses=%d",
             PIHOLE_NET_DEVICES, PIHOLE_IPS);
    size_t len;
    if (!api_get(c, path, &len)) return false;
    cJSON *r = cJSON_ParseWithLength(W->resp, len);
    const cJSON *devs = r ? jget(r, "devices") : NULL;
    if (!cJSON_IsArray(devs)) { cJSON_Delete(r); return fail("/api/network/devices: no devices array"); }
    const cJSON *it;
    cJSON_ArrayForEach(it, devs) {
        uint8_t mac[6];
        bool mk = mac_parse(jstr(it, "hwaddr"), mac);
        const cJSON *ips = jget(it, "ips");
        if (!mk && (!cJSON_IsArray(ips) || !cJSON_GetArraySize(ips))) continue;
        ph_dev_t *d = add(t);
        if (!d) break;
        d->mac_known = mk;
        if (mk) memcpy(d->mac, mac, 6);
        d->first = ju32(it, "firstSeen");
        d->last = ju32(it, "lastQuery");
        d->all_queries = ju32(it, "numQueries");
        const char *v = jstr(it, "macVendor");
        if (v) strlcpy(d->vendor, v, sizeof(d->vendor));
        const cJSON *a;
        cJSON_ArrayForEach(a, ips) {
            add_ip(d, jstr(a, "ip"));
            add_name(d, jstr(a, "name"));
        }
    }
    cJSON_Delete(r);
    return true;
}

// GET /api/stats/top_clients: clients[] {name, ip, count}; with blocked=true
// count is the client's blocked queries. Over Pi-hole's in-memory window (24 h
// by default). A client the network table lacks gets an IP-only entry.
static bool sync_clients(const conn_t *c, ph_table_t *t, bool blocked, bool *complete)
{
    char path[64];
    snprintf(path, sizeof(path), "/api/stats/top_clients?count=%d%s", PIHOLE_CLIENTS_MAX,
             blocked ? "&blocked=true" : "");
    size_t len;
    if (!api_get(c, path, &len)) return false;
    cJSON *r = cJSON_ParseWithLength(W->resp, len);
    const cJSON *cl = r ? jget(r, "clients") : NULL;
    if (!cJSON_IsArray(cl)) { cJSON_Delete(r); return fail("/api/stats/top_clients: no clients array"); }
    bool hidden = jnum(r, "total_queries", 0) < 0;     // privacy level hides clients
    int n = cJSON_GetArraySize(cl);
    if (complete) *complete = !hidden && n < PIHOLE_CLIENTS_MAX;
    if (!hidden) {
        for (int i = 0; i < t->n; i++) {
            if (blocked) t->dev[i].blocked = 0; else t->dev[i].queries = 0;
        }
        const cJSON *it;
        cJSON_ArrayForEach(it, cl) {
            const char *ip = jstr(it, "ip");
            if (!ip || !ip[0]) continue;
            ph_dev_t *d = find(t, NULL, ip);
            if (!d && !blocked && (d = add(t)) != NULL) {
                add_ip(d, ip);
                d->queries = d->blocked = 0;
            }
            if (!d) continue;
            add_name(d, jstr(it, "name"));
            // Summed over the device's addresses (IPv4 and IPv6 are separate clients).
            int32_t *dst = blocked ? &d->blocked : &d->queries;
            uint64_t sum = (uint64_t)(*dst < 0 ? 0 : *dst) + ju32(it, "count");
            *dst = sum > INT32_MAX ? INT32_MAX : (int32_t)sum;
        }
    }
    cJSON_Delete(r);
    return true;
}

// A query's status string (FTL's get_query_status_str()): 1 allowed, 2
// blocked with *how set, 0 neither (UNKNOWN, IN_PROGRESS, absent, or a status
// this firmware does not know). Blocked is FTL's is_blocked() list.
static int query_verdict(const char *st, uint8_t *how)
{
    static const struct { const char *s; uint8_t how; } BLK[] = {
        { "GRAVITY", PH_BLK_GRAVITY },        { "GRAVITY_CNAME", PH_BLK_GRAVITY },
        { "REGEX", PH_BLK_REGEX },            { "REGEX_CNAME", PH_BLK_REGEX },
        { "DENYLIST", PH_BLK_DENYLIST },      { "DENYLIST_CNAME", PH_BLK_DENYLIST },
        { "EXTERNAL_BLOCKED_IP", PH_BLK_UPSTREAM },   { "EXTERNAL_BLOCKED_NULL", PH_BLK_UPSTREAM },
        { "EXTERNAL_BLOCKED_NXRA", PH_BLK_UPSTREAM }, { "EXTERNAL_BLOCKED_EDE15", PH_BLK_UPSTREAM },
        { "SPECIAL_DOMAIN", PH_BLK_OTHER },   { "DBBUSY", PH_BLK_OTHER },
    };
    static const char *const OK[] = { "FORWARDED", "CACHE", "CACHE_STALE", "RETRIED", "RETRIED_DNSSEC" };
    if (!st) return 0;
    for (size_t i = 0; i < sizeof(OK) / sizeof(OK[0]); i++) if (!strcmp(st, OK[i])) return 1;
    for (size_t i = 0; i < sizeof(BLK) / sizeof(BLK[0]); i++)
        if (!strcmp(st, BLK[i].s)) { *how |= BLK[i].how; return 2; }
    return 0;
}

// GET /api/queries?client_ip=&length=: the client's newest queries; the top
// PIHOLE_TOP_N domains among them, by count (ties: the most recent first),
// each with its allowed and blocked counts from the queries' status.
static bool sync_top(const conn_t *c, ph_dev_t *d, uint32_t ip)
{
    char ips[16], path[96];
    fmt_ip(ip, ips, sizeof(ips));
    snprintf(path, sizeof(path), "/api/queries?client_ip=%s&length=%d", ips, PIHOLE_TOP_SAMPLE);
    size_t len;
    if (!api_get(c, path, &len)) return false;
    cJSON *r = cJSON_ParseWithLength(W->resp, len);
    const cJSON *q = r ? jget(r, "queries") : NULL;
    if (!cJSON_IsArray(q)) { cJSON_Delete(r); return fail("/api/queries: no queries array"); }
    int nd = 0, seen = 0;
    const cJSON *it;
    cJSON_ArrayForEach(it, q) {
        if (seen >= PIHOLE_TOP_SAMPLE) break;
        const char *dom = jstr(it, "domain");
        if (!dom || !dom[0]) continue;
        seen++;
        int k = 0;
        while (k < nd && strcmp(W->cnt[k].d, dom)) k++;
        if (k == nd) {
            W->cnt[nd].d = dom;
            W->cnt[nd].n = 0;
            W->cnt[nd].allowed = W->cnt[nd].blocked = 0;
            W->cnt[nd].how = 0;
            nd++;
        }
        W->cnt[k].n++;
        int v = query_verdict(jstr(it, "status"), &W->cnt[k].how);
        if (v == 1) W->cnt[k].allowed++;
        else if (v == 2) W->cnt[k].blocked++;
    }
    d->n_top = 0;
    for (int pick = 0; pick < PIHOLE_TOP_N; pick++) {
        int best = -1;
        for (int k = 0; k < nd; k++)
            if (W->cnt[k].n && (best < 0 || W->cnt[k].n > W->cnt[best].n)) best = k;
        if (best < 0) break;
        strlcpy(d->top[d->n_top].d, W->cnt[best].d, PIHOLE_DOMAIN_LEN);
        d->top[d->n_top].n = W->cnt[best].n;
        d->top[d->n_top].allowed = W->cnt[best].allowed;
        d->top[d->n_top].blocked = W->cnt[best].blocked;
        d->top[d->n_top].how = W->cnt[best].how;
        d->n_top++;
        W->cnt[best].n = 0;
    }
    d->top_of = (uint16_t)seen;
    d->top_ts = epoch();
    if (!d->top_ts) d->top_ts = 1;                     // "counted", before SNTP
    cJSON_Delete(r);
    return true;
}

// The devices the honeypot knows: the discovery table and recent attackers.
static int known_devices(void)
{
    int n = 0;
    int t = discovery_top_talkers(W->talk, DISCOVERY_DEV_MAX);
    for (int i = 0; i < t && n < PIHOLE_KNOWN_MAX; i++) {
        if (!W->talk[i].ip) continue;
        known_t *k = &W->known[n++];
        k->ip = W->talk[i].ip;
        memcpy(k->mac, W->talk[i].mac, 6);
        k->mac_known = W->talk[i].mac[0] | W->talk[i].mac[1] | W->talk[i].mac[2] |
                       W->talk[i].mac[3] | W->talk[i].mac[4] | W->talk[i].mac[5];
    }
    int a = log_store_get_recent(W->recent, PIHOLE_RECENT);
    for (int i = 0; i < a && n < PIHOLE_KNOWN_MAX; i++) {
        uint32_t ip = W->recent[i].src_ip;
        if (!ip) continue;
        bool dup = false;
        for (int k = 0; k < n && !dup; k++) dup = W->known[k].ip == ip;
        if (dup) continue;
        known_t *k = &W->known[n++];
        k->ip = ip;
        memcpy(k->mac, W->recent[i].src_mac, 6);
        k->mac_known = k->mac[0] | k->mac[1] | k->mac[2] | k->mac[3] | k->mac[4] | k->mac[5];
    }
    return n;
}

// Top domains for one IP, into its entry (an IP-only one if Pi-hole's tables
// lack it). Skipped when the counts say it sent nothing.
static bool top_for(const conn_t *c, ph_table_t *t, uint32_t ip, const uint8_t *mac, bool clients_complete)
{
    char ips[16];
    fmt_ip(ip, ips, sizeof(ips));
    ph_dev_t *d = find(t, mac, ips);
    // top_clients listed every client: absent or 0 means no queries in the window.
    if (clients_complete && (!d || d->queries == 0)) return true;
    if (!d) {
        d = add(t);
        if (!d) return true;
        add_ip(d, ips);
    }
    return sync_top(c, d, ip);
}

// Names to the discovery table, for devices whose own label is weak.
static void name_hints(const ph_table_t *t)
{
    int n = discovery_top_talkers(W->talk, DISCOVERY_DEV_MAX);
    for (int i = 0; i < n; i++) {
        char ips[16] = "";
        if (W->talk[i].ip) fmt_ip(W->talk[i].ip, ips, sizeof(ips));
        const ph_dev_t *d = find((ph_table_t *)t, W->talk[i].mac, ips);
        if (!d || !d->n_name) continue;
        char name[DISCOVERY_LABEL_LEN];
        size_t o = 0;
        for (const char *p = d->name[0]; *p && o + 1 < sizeof(name); p++)
            name[o++] = (*p > 0x20 && *p < 0x7f) ? *p : '?';    // the panel font is ASCII
        name[o] = '\0';
        struct in_addr a;
        if (o && !inet_aton(name, &a)) discovery_name_hint(W->talk[i].ip, W->talk[i].mac, name);
    }
}

static bool sync_all(const conn_t *c)
{
    W->err[0] = '\0';
    if (!resolve(c)) return false;
    char ip[16];
    fmt_ip(s_ip, ip, sizeof(ip));
    xSemaphoreTake(s_mux, portMAX_DELAY);
    strlcpy(s_st->ip, ip, sizeof(s_st->ip));
    s_st->syncing = true;
    xSemaphoreGive(s_mux);

    bool have_version;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    have_version = s_st->version[0] != '\0';
    xSemaphoreGive(s_mux);
    if (!have_version && !get_version(c)) return false;

    ph_table_t *next = (s_cur == &W->tab[0]) ? &W->tab[1] : &W->tab[0];
    next->n = 0;
    bool complete = false;
    if (!sync_devices(c, next)) return false;
    if (!sync_clients(c, next, false, &complete)) return false;
    if (!sync_clients(c, next, true, NULL)) return false;

    // Keep the top lists of the last sync; refresh some of them below.
    if (s_cur) {
        for (int i = 0; i < next->n; i++) {
            ph_dev_t *d = &next->dev[i];
            const ph_dev_t *o = find(s_cur, d->mac_known ? d->mac : NULL, d->n_ip ? d->ip[0] : NULL);
            if (o && o->top_ts) {
                memcpy(d->top, o->top, sizeof(d->top));
                d->n_top = o->n_top;
                d->top_of = o->top_of;
                d->top_ts = o->top_ts;
            }
        }
    }

    uint32_t want[WANT_MAX];
    xSemaphoreTake(s_mux, portMAX_DELAY);
    memcpy(want, s_want, sizeof(want));
    memset(s_want, 0, sizeof(s_want));
    xSemaphoreGive(s_mux);
    int done = 0;
    bool ok = true;
    for (int i = 0; i < WANT_MAX && ok && done < PIHOLE_TOP_PER_SYNC; i++) {
        if (!want[i]) continue;
        ok = top_for(c, next, want[i], NULL, complete);
        done++;
    }
    int nk = known_devices();
    for (int i = 0; i < nk && ok && done < PIHOLE_TOP_PER_SYNC; i++) {
        const known_t *k = &W->known[(s_rr + i) % nk];
        ok = top_for(c, next, k->ip, k->mac_known ? k->mac : NULL, complete);
        done++;
    }
    if (nk) s_rr = (s_rr + done) % nk;

    int with_top = 0;
    for (int i = 0; i < next->n; i++) if (next->dev[i].top_ts) with_top++;
    next->as_of = epoch();
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_cur = next;                                   // the old table is the next one now
    s_st->devices = (uint32_t)next->n;
    s_st->with_top = (uint32_t)with_top;
    xSemaphoreGive(s_mux);
    name_hints(next);
    return ok;
}

// ── Task ──────────────────────────────────────────────────────────────────────

// The connection the settings describe, into out. False if they are incomplete.
static bool conn_from(const settings_t *s, conn_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!settings_pihole_url_parse(s->pihole_url, &out->tls, out->host, sizeof(out->host), &out->port))
        return false;
    strlcpy(out->pw, s->pihole_password, sizeof(out->pw));
    strlcpy(out->pin, s->pihole_tls_sha256, sizeof(out->pin));
    return out->pw[0] != '\0';
}

static bool conn_same(const conn_t *a, const conn_t *b)
{
    return a->tls == b->tls && a->port == b->port && !strcmp(a->host, b->host) &&
           !strcmp(a->pw, b->pw) && !strcmp(a->pin, b->pin);
}

static void set_state(bool ok, bool on)
{
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->syncing = false;
    s_st->last_try_up = up_s();
    if (!on) {
        strlcpy(s_st->state, "off", sizeof(s_st->state));
    } else if (ok) {
        strlcpy(s_st->state, "ok", sizeof(s_st->state));
        s_st->error[0] = '\0';
        s_st->last_ok_up = up_s();
        s_st->last_ok_ts = epoch();
        s_st->syncs++;
    } else {
        if (strcmp(s_st->state, "v5")) strlcpy(s_st->state, "error", sizeof(s_st->state));
        strlcpy(s_st->error, W->err, sizeof(s_st->error));
        s_st->failures++;
    }
    s_st->backoff_s = 0;
    if (!ok && on) {
        uint32_t b = PIHOLE_BACKOFF_MIN_S;
        for (int i = 1; i < s_fails && b < PIHOLE_BACKOFF_MAX_S; i++) b *= 2;
        s_st->backoff_s = b > PIHOLE_BACKOFF_MAX_S ? PIHOLE_BACKOFF_MAX_S : b;
    }
    xSemaphoreGive(s_mux);
    if (!ok && on && strcmp(W->err, W->logged_err)) {        // each new error once
        ESP_LOGW(TAG, "%s", W->err);
        strlcpy(W->logged_err, W->err, sizeof(W->logged_err));
    }
    if (ok) W->logged_err[0] = '\0';
}

static void run_test(const conn_t *c, uint32_t n)
{
    W->err[0] = '\0';
    bool ok = resolve(c) && (s_session || auth(c)) && get_version(c);
    char ip[16] = "";
    if (s_ip) fmt_ip(s_ip, ip, sizeof(ip));
    xSemaphoreTake(s_mux, portMAX_DELAY);
    s_st->test_done = n;
    s_st->test_ok = ok;
    s_st->test_status = s_st->last_http;
    strlcpy(s_st->ip, ip, sizeof(s_st->ip));
    if (ok) snprintf(s_st->test_msg, sizeof(s_st->test_msg), "Connected to Pi-hole at %s (%s): %s",
                     c->host, ip, s_st->version[0] ? s_st->version : "version unknown");
    else strlcpy(s_st->test_msg, W->err, sizeof(s_st->test_msg));
    xSemaphoreGive(s_mux);
    ESP_LOGI(TAG, "Test %s", ok ? "passed" : "failed");
}

static void pihole_task(void *arg)
{
    (void)arg;
    wifi_manager_wait_for_ip();
    uint32_t next = up_s() + 5;                     // first sync soon after the start
    for (;;) {
        uint32_t now = up_s();
        bool on = settings_pihole_enabled();
        TickType_t wait = portMAX_DELAY;
        if (on) wait = (int32_t)(next - now) > 0 ? pdMS_TO_TICKS((next - now) * 1000u) : 0;
        xSemaphoreTake(s_mux, portMAX_DELAY);
        s_next_up = on ? next : 0;
        xSemaphoreGive(s_mux);
        if (wait) ulTaskNotifyTake(pdTRUE, wait);

        settings_copy(&W->set);
        bool have = conn_from(&W->set, &W->want);
        memset(&W->set, 0, sizeof(W->set));
        on = settings_pihole_enabled() && have;
        if (!conn_same(&W->c, &W->want)) {          // new URL, password or pin
            if (s_session) logout(&W->c);
            W->c = W->want;
            s_ip = 0;
            s_fails = 0;
            next = up_s();
            xSemaphoreTake(s_mux, portMAX_DELAY);
            s_st->version[0] = s_st->ip[0] = s_st->tls_seen[0] = '\0';
            strlcpy(s_st->host, W->c.host, sizeof(s_st->host));
            strlcpy(s_st->state, on ? "starting" : "off", sizeof(s_st->state));
            s_st->error[0] = '\0';
            xSemaphoreGive(s_mux);
            W->logged_err[0] = '\0';
        }
        memset(&W->want, 0, sizeof(W->want));

        xSemaphoreTake(s_mux, portMAX_DELAY);
        uint32_t test = s_test_req != s_st->test_done ? s_test_req : 0;
        bool refresh = s_refresh;
        s_refresh = false;
        s_st->enabled = on;
        xSemaphoreGive(s_mux);

        if (test) {
            if (have) run_test(&W->c, test);
            else {
                xSemaphoreTake(s_mux, portMAX_DELAY);
                s_st->test_done = test;
                s_st->test_ok = false;
                s_st->test_status = 0;
                strlcpy(s_st->test_msg, "set the Pi-hole URL and app password first", sizeof(s_st->test_msg));
                xSemaphoreGive(s_mux);
            }
        }
        if (!on) {
            if (s_session) logout(&W->c);
            set_state(false, false);
            continue;
        }
        now = up_s();
        if (!refresh && (int32_t)(next - now) > 0) continue;

        bool ok = sync_all(&W->c);
        if (ok) s_fails = 0; else s_fails++;
        set_state(ok, true);
        uint32_t backoff;
        xSemaphoreTake(s_mux, portMAX_DELAY);
        backoff = s_st->backoff_s;
        xSemaphoreGive(s_mux);
        next = up_s() + (ok ? PIHOLE_SYNC_S : backoff);
        if (!s_hw_logged) {
            s_hw_logged = true;
            UBaseType_t hw = uxTaskGetStackHighWaterMark(NULL);
            xSemaphoreTake(s_mux, portMAX_DELAY);
            s_st->stack_free = (uint32_t)hw;
            xSemaphoreGive(s_mux);
            ESP_LOGI(TAG, "First sync %s: %lu devices, stack high-water %u B free of %u, internal heap %u B",
                     ok ? "done" : "failed", (unsigned long)s_st->devices, (unsigned)hw,
                     (unsigned)PIHOLE_TASK_STACK, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        }
    }
}

// ── Public ────────────────────────────────────────────────────────────────────

static void on_settings(void)
{
    if (settings_pihole_enabled()) pihole_start();
    if (s_task) xTaskNotifyGive(s_task);
}

void pihole_init(void)
{
    // Parsed responses are thousands of small cJSON nodes: PSRAM first, for
    // every cJSON user (free() releases either kind).
    cJSON_Hooks hooks = { .malloc_fn = json_malloc, .free_fn = free };
    cJSON_InitHooks(&hooks);
    s_st = heap_caps_calloc(1, sizeof(*s_st), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_st) { ESP_LOGE(TAG, "No PSRAM for the status: Pi-hole off"); return; }
    strlcpy(s_st->state, "off", sizeof(s_st->state));
    s_mux = xSemaphoreCreateMutex();            // NULL leaves every entry point a no-op
    settings_on_change(on_settings);
}

bool pihole_start(void)
{
    if (!s_mux) return false;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    bool ok = s_task != NULL, created = false;
    if (!ok) {
        if (!W) W = heap_caps_calloc(1, sizeof(*W), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (W && xTaskCreatePinnedToCoreWithCaps(pihole_task, "pihole", PIHOLE_TASK_STACK, NULL,
                                                 PIHOLE_TASK_PRIO, &s_task, 1,
                                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) == pdPASS) {
            ok = created = true;
            s_st->running = true;
            strlcpy(s_st->state, "starting", sizeof(s_st->state));
        } else {
            s_task = NULL;
        }
    }
    xSemaphoreGive(s_mux);
    if (created) ESP_LOGI(TAG, "Task started, %u KB of state in PSRAM", (unsigned)(sizeof(work_t) / 1024));
    else if (!ok) ESP_LOGE(TAG, "Could not start: no PSRAM for %u KB of state, or no task", (unsigned)(sizeof(work_t) / 1024));
    return ok;
}

uint32_t pihole_request_test(void)
{
    settings_t *s = heap_caps_malloc(sizeof(*s), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s) return 0;
    settings_copy(s);
    bool have = s->pihole_password[0] && settings_pihole_url_parse(s->pihole_url, NULL, NULL, 0, NULL);
    memset(s, 0, sizeof(*s));
    free(s);
    if (!have || !pihole_start()) return 0;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    uint32_t n = ++s_test_req;
    if (!n) n = ++s_test_req;
    xSemaphoreGive(s_mux);
    xTaskNotifyGive(s_task);
    return n;
}

int pihole_request_refresh(uint32_t ip)
{
    if (!settings_pihole_enabled() || !s_task) return -1;
    uint32_t now = up_s();
    xSemaphoreTake(s_mux, portMAX_DELAY);
    if (s_refresh_up && now - s_refresh_up < PIHOLE_REFRESH_MIN_S) {
        int left = (int)(PIHOLE_REFRESH_MIN_S - (now - s_refresh_up));
        xSemaphoreGive(s_mux);
        return left > 0 ? left : 1;
    }
    s_refresh_up = now ? now : 1;
    s_refresh = true;
    if (ip) {
        int slot = -1;
        for (int i = 0; i < WANT_MAX; i++) {
            if (s_want[i] == ip) { slot = -2; break; }
            if (!s_want[i] && slot == -1) slot = i;
        }
        if (slot >= 0) s_want[slot] = ip;
    }
    xSemaphoreGive(s_mux);
    xTaskNotifyGive(s_task);
    return 0;
}

void pihole_get_status(pihole_status_t *out)
{
    if (!s_mux) { memset(out, 0, sizeof(*out)); strlcpy(out->state, "off", sizeof(out->state)); return; }
    xSemaphoreTake(s_mux, portMAX_DELAY);
    *out = *s_st;
    uint32_t now = up_s();
    out->next_in_s = s_next_up && (int32_t)(s_next_up - now) > 0 ? s_next_up - now : 0;
    xSemaphoreGive(s_mux);
    out->enabled = settings_pihole_enabled();
    out->running = s_task != NULL;
}

// ── JSON for one device ───────────────────────────────────────────────────────

typedef struct { char *b; size_t cap, o; bool full; } jw_t;

static void jw_raw(jw_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jw_raw(jw_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(j->b + j->o, j->cap - j->o, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= j->cap - j->o) { j->full = true; return; }
    j->o += (size_t)w;
}

// "s" escaped by json_esc(); full when it might have been cut.
static void jw_str(jw_t *j, const char *s, size_t max)
{
    if (j->full || j->cap - j->o < 4) { j->full = true; return; }
    j->b[j->o++] = '"';
    size_t room = j->cap - j->o - 1;                // keep one for the closing quote
    size_t n = json_esc(s, max, j->b + j->o, room);
    if (n + 2 >= room) { j->full = true; return; }
    j->o += n;
    j->b[j->o++] = '"';
    j->b[j->o] = '\0';
}

size_t pihole_device_json(uint32_t ip, const uint8_t mac[6], char *buf, size_t cap, bool lead)
{
    if (!buf || cap < 16 || !s_mux || !settings_pihole_enabled()) return 0;
    char ips[16] = "";
    if (ip) fmt_ip(ip, ips, sizeof(ips));
    jw_t j = { .b = buf, .cap = cap, .o = 0, .full = false };
    xSemaphoreTake(s_mux, portMAX_DELAY);
    const ph_dev_t *d = s_cur ? find(s_cur, mac, ips) : NULL;
    if (!d) { xSemaphoreGive(s_mux); return 0; }
    jw_raw(&j, "%s{\"names\":[", lead ? ",\"pihole\":" : "");
    for (int i = 0; i < d->n_name; i++) { if (i) jw_raw(&j, ","); jw_str(&j, d->name[i], PIHOLE_NAME_LEN); }
    jw_raw(&j, "],\"ips\":[");
    for (int i = 0; i < d->n_ip; i++) { if (i) jw_raw(&j, ","); jw_str(&j, d->ip[i], PIHOLE_IP_LEN); }
    jw_raw(&j, "]");
    if (d->mac_known)
        jw_raw(&j, ",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
               d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);
    if (d->vendor[0]) { jw_raw(&j, ",\"vendor\":"); jw_str(&j, d->vendor, PIHOLE_VENDOR_LEN); }
    jw_raw(&j, ",\"first\":%lu,\"last\":%lu,\"all_queries\":%lu",
           (unsigned long)d->first, (unsigned long)d->last, (unsigned long)d->all_queries);
    if (d->queries >= 0) jw_raw(&j, ",\"queries\":%ld", (long)d->queries);
    if (d->blocked >= 0) jw_raw(&j, ",\"blocked\":%ld", (long)d->blocked);
    if (d->top_ts) {
        jw_raw(&j, ",\"top_domains\":[");
        for (int i = 0; i < d->n_top; i++) {
            jw_raw(&j, "%s{\"d\":", i ? "," : "");
            jw_str(&j, d->top[i].d, PIHOLE_DOMAIN_LEN);
            const ph_top_t *t = &d->top[i];
            jw_raw(&j, ",\"n\":%lu,\"allowed\":%u,\"blocked\":%u,\"block\":[",
                   (unsigned long)t->n, (unsigned)t->allowed, (unsigned)t->blocked);
            bool first = true;
            for (int b = 0; b < (int)(sizeof(BLK_KEY) / sizeof(BLK_KEY[0])); b++)
                if (t->how & (1u << b)) { jw_raw(&j, "%s\"%s\"", first ? "" : ",", BLK_KEY[b]); first = false; }
            jw_raw(&j, "]}");
        }
        jw_raw(&j, "],\"top_of\":%u,\"top_ts\":%lu", (unsigned)d->top_of,
               (unsigned long)(d->top_ts > 1 ? d->top_ts : 0));
    }
    jw_raw(&j, ",\"as_of\":%lu}", (unsigned long)s_cur->as_of);
    xSemaphoreGive(s_mux);
    return j.full ? cap : j.o;
}

// ── Device intelligence (correlate.h) ─────────────────────────────────────────

// correlate.c's weak hook, from the published table: a read under s_mux, no
// request. Pi-hole v6's top_clients counts cover FTL's in-memory window (24 h
// by default); the top domains are counted over the device's last top_of
// queries and carry no answer address, so ip[] is 0 for each; blocked is set
// for a name Pi-hole refused every time in that sample (none of it allowed).
bool correlate_pihole_device(uint32_t ip, const uint8_t *mac, correlate_dns_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!s_mux || !settings_pihole_enabled()) return false;
    char ips[16] = "";
    if (ip) fmt_ip(ip, ips, sizeof(ips));
    bool found = false;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    const ph_dev_t *d = s_cur ? find(s_cur, mac, ips) : NULL;
    if (d) {
        found = true;
        out->as_of = s_cur->as_of;
        out->server_ip = s_ip;                      // network order, 0 when not resolved
        if (d->queries >= 0) {                      // unknown counts leave window_s 0: no DNS-bypass test
            out->window_s = 24 * 3600;
            out->total = d->queries > UINT16_MAX ? UINT16_MAX : (uint16_t)d->queries;
            out->blocked = d->blocked < 0 ? 0 : d->blocked > UINT16_MAX ? UINT16_MAX : (uint16_t)d->blocked;
        }
        if (d->top_ts) {
            for (int i = 0; i < d->n_top && out->n < CORRELATE_DNS_MAX; i++) {
                correlate_dns_q_t *q = &out->q[out->n++];
                strlcpy(q->domain, d->top[i].d, sizeof(q->domain));
                q->blocked = d->top[i].blocked && !d->top[i].allowed;
                q->ts = d->top_ts > 1 ? d->top_ts : 0;
            }
        }
    }
    xSemaphoreGive(s_mux);
    return found;
}
