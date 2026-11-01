// Fork routes on the admin port: settings, reboot, buzzer test, summary
// metrics and the microSD log viewer. See api_ext.h.
//
// Runs on the admin task (single-threaded accept loop, 8 KB stack), so the big
// buffers are PSRAM, allocated once on first use, and shared between routes.
// Everything in a request and everything read back from the card is untrusted:
// every length is checked and every string is JSON-escaped on the way out.

#include "api_ext.h"
#include "json_esc.h"
#include "settings.h"
#include "sd_log.h"
#include "alarm.h"
#include "buzzer.h"
#include "ws_server.h"
#include "log_store.h"
#include "wifi_manager.h"
#include "discord.h"
#include "ignore.h"
#include "detect.h"
#include "whatsapp.h"
#include "notify.h"
#include "ui.h"
#include "wifi_monitor.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/ip4_addr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char *TAG = "API";

#define BODY_MAX        4096            // POST body cap, larger gets 413
#define OUT_MAX         (24 * 1024)     // JSON response buffer
#define CHUNK           4096            // file streaming
#define TAIL_BYTES      (256 * 1024)    // tail=1 sends at most this much
#define LOG_FILES_MAX   400             // newest day files listed
#define TOP_N           10
#define SEND_TIMEOUT_S  10

typedef struct { char name[20]; uint32_t size; } log_file_t;

static char        *s_out;
static char        *s_body;
static char        *s_chunk;
static sd_stats_t  *s_stats;
static log_file_t  *s_files;

static bool bufs_ready(void)
{
    if (!s_out)   s_out   = heap_caps_malloc(OUT_MAX, MALLOC_CAP_SPIRAM);
    if (!s_body)  s_body  = heap_caps_malloc(BODY_MAX + 1, MALLOC_CAP_SPIRAM);
    if (!s_chunk) s_chunk = heap_caps_malloc(CHUNK, MALLOC_CAP_SPIRAM);
    if (!s_stats) s_stats = heap_caps_malloc(sizeof(*s_stats), MALLOC_CAP_SPIRAM);
    if (!s_files) s_files = heap_caps_malloc(LOG_FILES_MAX * sizeof(*s_files), MALLOC_CAP_SPIRAM);
    return s_out && s_body && s_chunk && s_stats && s_files;
}

// ── JSON builder (bounded; sets full instead of overflowing) ──────────────────

typedef struct { char *buf; size_t len, cap; bool full; } jb_t;

static void jb_init(jb_t *j) { j->buf = s_out; j->len = 0; j->cap = OUT_MAX; j->full = false; s_out[0] = '\0'; }

static void jb_raw(jb_t *j, const char *s, size_t n)
{
    if (j->full || j->len + n >= j->cap) { j->full = true; return; }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

#define JB_LIT(j, lit) jb_raw((j), (lit), sizeof(lit) - 1)

static void jb_printf(jb_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_printf(jb_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(j->buf + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= j->cap - j->len) { j->full = true; j->buf[j->len] = '\0'; return; }
    j->len += (size_t)n;
}

// A JSON string literal, escaped by json_esc() (bytes that are not UTF-8 become
// U+FFFD), reading at most max bytes of s. The admin task is the only caller,
// so one static buffer serves; it holds max up to 170 bytes fully escaped.
static void jb_str(jb_t *j, const char *s, size_t max)
{
    static char esc[1024];
    JB_LIT(j, "\"");
    size_t n = json_esc(s, max, esc, sizeof(esc));
    jb_raw(j, esc, n);
    JB_LIT(j, "\"");
}

static void jb_bool(jb_t *j, const char *key, bool v) { jb_printf(j, "\"%s\":%s", key, v ? "true" : "false"); }

// ── HTTP helpers ──────────────────────────────────────────────────────────────

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

static bool send_head(int sock, const char *status, const char *ctype, size_t len, const char *extra)
{
    char hdr[384];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "%s"
        "Connection: close\r\n\r\n",
        status, ctype, (unsigned)len, extra ? extra : "");
    if (n <= 0 || n >= (int)sizeof(hdr)) return false;
    return send_all(sock, hdr, (size_t)n);
}

static void send_json(int sock, jb_t *j)
{
    if (j->full) {
        static const char e[] = "{\"error\":\"response too large\"}";
        if (send_head(sock, "500 Internal Server Error", "application/json", sizeof(e) - 1, NULL))
            send_all(sock, e, sizeof(e) - 1);
        return;
    }
    if (send_head(sock, "200 OK", "application/json", j->len, NULL))
        send_all(sock, j->buf, j->len);
}

static void send_error(int sock, const char *status, const char *msg)
{
    char body[200];
    jb_t j = { .buf = body, .len = 0, .cap = sizeof(body), .full = false };
    JB_LIT(&j, "{\"error\":");
    jb_str(&j, msg, 120);
    JB_LIT(&j, "}");
    if (j.full) { strlcpy(body, "{\"error\":\"?\"}", sizeof(body)); j.len = strlen(body); }
    if (send_head(sock, status, "application/json", j.len, NULL))
        send_all(sock, body, j.len);
}

static void send_204(int sock)
{
    static const char r[] = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    send_all(sock, r, sizeof(r) - 1);
}

// Header block end ("\r\n\r\n"), or NULL if the headers didn't fit the first recv.
static const char *headers_end(const char *req) { return strstr(req, "\r\n\r\n"); }

// The value of a header (case-insensitive name incl. ':'), searched only in the
// header block. Returns a pointer to the value (leading blanks skipped) or NULL.
static const char *header_value(const char *req, const char *hend, const char *name)
{
    size_t nl = strlen(name);
    for (const char *p = strchr(req, '\n'); p && p < hend; p = strchr(p, '\n')) {
        p++;
        if (p >= hend) break;
        if (strncasecmp(p, name, nl) == 0) {
            p += nl;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
    }
    return NULL;
}

bool api_ext_csrf_ok(const char *req)
{
    const char *hend = headers_end(req);
    if (!hend) hend = req + strlen(req);
    return header_value(req, hend, "X-ShadowSentry:") != NULL;
}

// Content-Length: -1 absent or malformed, else the value (capped above BODY_MAX).
static long content_length(const char *req, const char *hend)
{
    const char *p = header_value(req, hend, "Content-Length:");
    if (!p || *p < '0' || *p > '9') return -1;
    long v = 0;
    for (; *p >= '0' && *p <= '9'; p++) {
        v = v * 10 + (*p - '0');
        if (v > BODY_MAX) return BODY_MAX + 1;
    }
    if (*p != '\r' && *p != ' ' && *p != '\t') return -1;
    return v;
}

// Read the whole body into s_body (NUL-terminated), honouring Content-Length.
// Returns NULL on success, or the status line to answer with.
static const char *read_body(int sock, const char *req, int req_len, size_t *out_len, const char **why)
{
    const char *hend = headers_end(req);
    if (!hend) { *why = "request headers too large"; return "431 Request Header Fields Too Large"; }
    long cl = content_length(req, hend);
    if (cl < 0)        { *why = "Content-Length required"; return "411 Length Required"; }
    if (cl > BODY_MAX) { *why = "body too large"; return "413 Payload Too Large"; }

    size_t start = (size_t)(hend + 4 - req);
    size_t have  = (req_len > 0 && (size_t)req_len > start) ? (size_t)req_len - start : 0;
    if (have > (size_t)cl) have = (size_t)cl;
    memcpy(s_body, req + start, have);
    while (have < (size_t)cl) {                 // recv timeout set by admin_panel.c
        int n = recv(sock, s_body + have, (size_t)cl - have, 0);
        if (n <= 0) { *why = "body incomplete"; return "408 Request Timeout"; }
        have += (size_t)n;
    }
    s_body[have] = '\0';
    *out_len = have;
    return NULL;
}

// "METHOD /path?query HTTP/1.1": copy method, path and query, all bounded.
static bool parse_request_line(const char *req, char *method, size_t mlen,
                               char *path, size_t plen, char *query, size_t qlen)
{
    const char *sp = strchr(req, ' ');
    if (!sp || (size_t)(sp - req) >= mlen) return false;
    memcpy(method, req, (size_t)(sp - req));
    method[sp - req] = '\0';

    const char *t = sp + 1, *e = t;
    while (*e && *e != ' ' && *e != '\r' && *e != '\n') e++;
    const char *q = memchr(t, '?', (size_t)(e - t));
    const char *pe = q ? q : e;
    if ((size_t)(pe - t) >= plen) return false;
    memcpy(path, t, (size_t)(pe - t));
    path[pe - t] = '\0';
    query[0] = '\0';
    if (q) {
        q++;
        if ((size_t)(e - q) >= qlen) return false;
        memcpy(query, q, (size_t)(e - q));
        query[e - q] = '\0';
    }
    return true;
}

// key=value from a query string, exact key, no decoding (callers validate).
static bool query_param(const char *query, const char *key, char *out, size_t outlen)
{
    size_t kl = strlen(key);
    for (const char *p = query; p && *p; ) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > kl && p[kl] == '=' && strncmp(p, key, kl) == 0) {
            size_t vl = seg - kl - 1;
            if (vl >= outlen) return false;
            memcpy(out, p + kl + 1, vl);
            out[vl] = '\0';
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

// ── Addresses (detect-core) ───────────────────────────────────────────────────

// The client's IPv4 (network order), 0 if unknown.
static uint32_t peer_ip(int sock)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    if (getpeername(sock, (struct sockaddr *)&a, &l) == 0 && a.sin_family == AF_INET)
        return a.sin_addr.s_addr;
    return 0;
}

// Strict dotted quad, four decimal octets 0-255, no leading junk or tail.
static bool parse_ipv4(const char *t, uint32_t *out)
{
    uint8_t b[4];
    for (int i = 0; i < 4; i++) {
        if (*t < '0' || *t > '9') return false;
        unsigned v = 0, digits = 0;
        while (*t >= '0' && *t <= '9') {
            v = v * 10 + (unsigned)(*t++ - '0');
            if (++digits > 3 || v > 255) return false;
        }
        b[i] = (uint8_t)v;
        if (i < 3 && *t++ != '.') return false;
    }
    if (*t) return false;
    memcpy(out, b, 4);                          // b[0] first: network order
    return true;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff, exactly.
static bool parse_mac(const char *t, uint8_t mac[6])
{
    if (strlen(t) != 17) return false;
    for (int i = 0; i < 6; i++) {
        int h = hexval(t[i * 3]), l = hexval(t[i * 3 + 1]);
        if (h < 0 || l < 0) return false;
        if (i < 5 && t[i * 3 + 2] != ':' && t[i * 3 + 2] != '-') return false;
        mac[i] = (uint8_t)(h << 4 | l);
    }
    return true;
}

static void jb_ip(jb_t *j, uint32_t ip)
{
    char b[16] = "";
    if (ip) { ip4_addr_t a = { .addr = ip }; ip4addr_ntoa_r(&a, b, sizeof(b)); }
    jb_printf(j, "\"%s\"", b);
}

// ── Settings ──────────────────────────────────────────────────────────────────

// "Set" means configured: the config.h placeholders start with 'Y' ("YOUR_...").
static bool secret_set(const char *s) { return s[0] && s[0] != 'Y'; }

static void get_settings(int sock)
{
    uint32_t client = peer_ip(sock);
    settings_t s;
    settings_copy_saved(&s);
    const settings_t *live = settings_get();
    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{\"wifi_ssid\":");   jb_str(&j, s.wifi_ssid, sizeof(s.wifi_ssid));
    JB_LIT(&j, ",\"tg_chat_id\":");  jb_str(&j, s.tg_chat_id, sizeof(s.tg_chat_id));
    JB_LIT(&j, ",\"tz\":");           jb_str(&j, s.tz, sizeof(s.tz));
    jb_printf(&j, ",\"alarm_remind_s\":%lu,\"alarm_quiet_s\":%lu,\"brightness\":%u,",
              (unsigned long)s.alarm_remind_s, (unsigned long)s.alarm_quiet_s, (unsigned)s.brightness);
    jb_bool(&j, "alarm_sound", s.alarm_sound);              JB_LIT(&j, ",");
    jb_bool(&j, "boot_chirp", s.boot_chirp);                JB_LIT(&j, ",");
    jb_bool(&j, "touch_click", s.touch_click);              JB_LIT(&j, ",");
    jb_bool(&j, "admin_password_set", s.admin_password[0]); JB_LIT(&j, ",");
    jb_bool(&j, "wifi_password_set", s.wifi_password[0]);   JB_LIT(&j, ",");
    jb_bool(&j, "tg_token_set", secret_set(s.tg_token));    JB_LIT(&j, ",");
    jb_bool(&j, "wifi_overridden", settings_wifi_overridden()); JB_LIT(&j, ",");
    jb_bool(&j, "telegram_enabled", settings_telegram_enabled()); JB_LIT(&j, ",");
    jb_bool(&j, "discord_webhook_set", s.discord_webhook[0]);  JB_LIT(&j, ",");   // never the URL
    jb_bool(&j, "discord_enabled", settings_discord_enabled()); JB_LIT(&j, ",");
    jb_bool(&j, "discord_log_events", s.discord_log_events);   JB_LIT(&j, ",");
    JB_LIT(&j, "\"whatsapp_phone\":"); jb_str(&j, s.whatsapp_phone, sizeof(s.whatsapp_phone)); JB_LIT(&j, ",");
    jb_bool(&j, "whatsapp_apikey_set", s.whatsapp_apikey[0]);  JB_LIT(&j, ",");   // never the key
    jb_bool(&j, "whatsapp_enabled", settings_whatsapp_enabled()); JB_LIT(&j, ",");
    jb_bool(&j, "reboot_pending", settings_reboot_pending());
    JB_LIT(&j, ",\"running_wifi_ssid\":");
    char ssid[sizeof(live->wifi_ssid)];
    strlcpy(ssid, live->wifi_ssid, sizeof(ssid));
    jb_str(&j, ssid, sizeof(ssid));
    // Detection: alert switches (bit per attack_type_t), thresholds, admin allowlist.
    jb_printf(&j, ",\"type_count\":%d,\"alert_mask\":%lu,\"scan_ports\":%lu,\"scan_window_s\":%lu,"
              "\"arp_targets\":%lu,\"arp_window_s\":%lu,\"admin_allow\":[",
              ATTACK_TYPE_COUNT, (unsigned long)s.alert_mask, (unsigned long)s.scan_ports,
              (unsigned long)s.scan_window_s, (unsigned long)s.arp_targets, (unsigned long)s.arp_window_s);
    for (int i = 0; i < s.admin_allow_n && i < SETTINGS_ADMIN_ALLOW_MAX; i++) {
        if (i) JB_LIT(&j, ",");
        jb_ip(&j, s.admin_allow[i]);
    }
    JB_LIT(&j, "],\"client_ip\":");
    jb_ip(&j, client);
    JB_LIT(&j, "}");
    memset(&s, 0, sizeof(s));
    send_json(sock, &j);
}

static char s_err[96];

// Apply a string field if present. Secrets are applied only when non-empty, so
// a blank form field leaves the saved value alone.
static const char *take_str(const cJSON *root, const char *key, char *dst, size_t cap, bool secret)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!it || cJSON_IsNull(it)) return NULL;
    if (!cJSON_IsString(it) || !it->valuestring) {
        snprintf(s_err, sizeof(s_err), "%s must be a string", key);
        return s_err;
    }
    size_t n = strlen(it->valuestring);
    if (secret && n == 0) return NULL;
    if (n >= cap) {
        snprintf(s_err, sizeof(s_err), "%s is too long (max %u)", key, (unsigned)(cap - 1));
        return s_err;
    }
    memcpy(dst, it->valuestring, n + 1);
    return NULL;
}

static const char *take_u32(const cJSON *root, const char *key, uint32_t *dst, uint32_t max)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!it || cJSON_IsNull(it)) return NULL;
    double d = cJSON_IsNumber(it) ? it->valuedouble : -1;
    if (d < 0 || d > (double)max || d != (double)(uint32_t)d) {
        snprintf(s_err, sizeof(s_err), "%s must be a whole number 0-%lu", key, (unsigned long)max);
        return s_err;
    }
    *dst = (uint32_t)d;
    return NULL;
}

static const char *take_bool(const cJSON *root, const char *key, bool *dst)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!it || cJSON_IsNull(it)) return NULL;
    if (!cJSON_IsBool(it)) {
        snprintf(s_err, sizeof(s_err), "%s must be true or false", key);
        return s_err;
    }
    *dst = cJSON_IsTrue(it);
    return NULL;
}

// "admin_allow": an array of up to 8 IPv4 strings. A non-empty list must hold
// the requesting client's own address, so a save can never lock Rob out.
static const char *take_allow(const cJSON *root, settings_t *s, uint32_t client)
{
    const cJSON *al = cJSON_GetObjectItemCaseSensitive(root, "admin_allow");
    if (!al || cJSON_IsNull(al)) return NULL;
    if (!cJSON_IsArray(al)) return "admin_allow must be an array of IPv4 addresses";
    if (cJSON_GetArraySize(al) > SETTINGS_ADMIN_ALLOW_MAX) return "admin allowlist holds at most 8 addresses";
    uint32_t ips[SETTINGS_ADMIN_ALLOW_MAX];
    int n = 0;
    bool mine = false;
    const cJSON *it;
    cJSON_ArrayForEach(it, al) {
        if (!cJSON_IsString(it) || !it->valuestring || !parse_ipv4(it->valuestring, &ips[n]) || !ips[n]) {
            snprintf(s_err, sizeof(s_err), "admin allowlist entry %d is not an IPv4 address", n + 1);
            return s_err;
        }
        if (ips[n] == client) mine = true;
        n++;
    }
    if (n && !mine) {
        char ip[16] = "?";
        if (client) { ip4_addr_t a = { .addr = client }; ip4addr_ntoa_r(&a, ip, sizeof(ip)); }
        snprintf(s_err, sizeof(s_err), "the admin allowlist must include your own address, %s", ip);
        return s_err;
    }
    memset(s->admin_allow, 0, sizeof(s->admin_allow));
    memcpy(s->admin_allow, ips, (size_t)n * sizeof(ips[0]));
    s->admin_allow_n = (uint8_t)n;
    return NULL;
}

static void wipe_item(cJSON *root, const char *key)
{
    cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (it && cJSON_IsString(it) && it->valuestring)
        memset(it->valuestring, 0, strlen(it->valuestring));
}

// cJSON recurses per nesting level (limit 1000), which a 4 KB body of "[[[["
// would turn into a stack overflow on this 8 KB task. Settings are flat.
static bool json_depth_ok(const char *s, size_t n, int max)
{
    int depth = 0;
    bool str = false, esc = false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') str = false;
        } else if (c == '"') {
            str = true;
        } else if (c == '{' || c == '[') {
            if (++depth > max) return false;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
        }
    }
    return true;
}

static void post_settings(int sock, const char *req, int req_len)
{
    size_t blen = 0;
    const char *why = NULL;
    const char *status = read_body(sock, req, req_len, &blen, &why);
    if (status) { send_error(sock, status, why); return; }
    if (!json_depth_ok(s_body, blen, 4)) {
        memset(s_body, 0, blen);
        send_error(sock, "400 Bad Request", "JSON nested too deeply");
        return;
    }

    cJSON *root = cJSON_ParseWithLength(s_body, blen);
    memset(s_body, 0, blen);                    // it held the passwords
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        send_error(sock, "400 Bad Request", "body must be a JSON object");
        return;
    }

    settings_t s;
    settings_copy_saved(&s);
    uint32_t bright = s.brightness;
    const char *err = NULL;
    if (!err) err = take_str(root, "admin_password", s.admin_password, sizeof(s.admin_password), true);
    if (!err) err = take_str(root, "wifi_ssid", s.wifi_ssid, sizeof(s.wifi_ssid), false);
    if (!err) err = take_str(root, "wifi_password", s.wifi_password, sizeof(s.wifi_password), true);
    bool open_net = false;      // a blank password means "unchanged", so open needs saying
    if (!err) err = take_bool(root, "wifi_open", &open_net);
    if (open_net) s.wifi_password[0] = '\0';
    if (!err) err = take_str(root, "tg_token", s.tg_token, sizeof(s.tg_token), true);
    if (!err) err = take_str(root, "tg_chat_id", s.tg_chat_id, sizeof(s.tg_chat_id), false);
    if (!err) err = take_str(root, "tz", s.tz, sizeof(s.tz), false);
    if (!err) err = take_u32(root, "alarm_remind_s", &s.alarm_remind_s, 86400);
    if (!err) err = take_u32(root, "alarm_quiet_s", &s.alarm_quiet_s, 86400);
    if (!err) err = take_u32(root, "brightness", &bright, 100);
    if (!err) err = take_bool(root, "alarm_sound", &s.alarm_sound);
    if (!err) err = take_bool(root, "boot_chirp", &s.boot_chirp);
    if (!err) err = take_bool(root, "touch_click", &s.touch_click);
    if (!err) err = take_str(root, "discord_webhook", s.discord_webhook, sizeof(s.discord_webhook), true);
    bool dc_clear = false;      // blank means "unchanged", so clearing needs saying
    if (!err) err = take_bool(root, "discord_webhook_clear", &dc_clear);
    if (dc_clear) s.discord_webhook[0] = '\0';
    if (!err) err = take_bool(root, "discord_log_events", &s.discord_log_events);
    if (!err) err = take_u32(root, "alert_mask", &s.alert_mask, 0xFFFFFFFFu);
    if (!err) err = take_u32(root, "scan_ports", &s.scan_ports, 86400);
    if (!err) err = take_u32(root, "scan_window_s", &s.scan_window_s, 86400);
    if (!err) err = take_u32(root, "arp_targets", &s.arp_targets, 86400);
    if (!err) err = take_u32(root, "arp_window_s", &s.arp_window_s, 86400);
    if (!err) err = take_allow(root, &s, peer_ip(sock));
    // Types this firmware does not know yet stay on.
    s.alert_mask |= ~((1u << ATTACK_TYPE_COUNT) - 1u);
    if (!err) err = take_str(root, "whatsapp_phone", s.whatsapp_phone, sizeof(s.whatsapp_phone), false);
    if (!err) err = take_str(root, "whatsapp_apikey", s.whatsapp_apikey, sizeof(s.whatsapp_apikey), true);
    bool wa_clear = false;      // blank means "unchanged", so clearing needs saying
    if (!err) err = take_bool(root, "whatsapp_apikey_clear", &wa_clear);
    if (wa_clear) s.whatsapp_apikey[0] = '\0';
    s.brightness = (uint8_t)bright;
    bool pw_changed = false;
    {
        const cJSON *it = cJSON_GetObjectItemCaseSensitive(root, "admin_password");
        pw_changed = it && cJSON_IsString(it) && it->valuestring && it->valuestring[0];
    }
    wipe_item(root, "admin_password");
    wipe_item(root, "wifi_password");
    wipe_item(root, "tg_token");
    wipe_item(root, "discord_webhook");
    wipe_item(root, "whatsapp_apikey");
    cJSON_Delete(root);

    bool reboot = false;
    esp_err_t r = ESP_ERR_INVALID_ARG;
    if (!err) r = settings_save(&s, &err, &reboot);
    memset(&s, 0, sizeof(s));
    if (r != ESP_OK) {
        send_error(sock, r == ESP_ERR_INVALID_ARG ? "400 Bad Request" : "500 Internal Server Error",
                   err ? err : "save failed");
        return;
    }
    ESP_LOGI(TAG, "Settings saved from the dashboard%s", pw_changed ? " (admin password changed)" : "");
    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"ok\":true,\"reboot\":%s,\"password_changed\":%s}",
              reboot ? "true" : "false", pw_changed ? "true" : "false");
    send_json(sock, &j);
}

// The test runs on the Discord task (an HTTPS post takes seconds and must not
// hold the admin task); the page polls /api/discord/status for the result.
static void post_discord_test(int sock)
{
    if (!settings_discord_enabled()) { send_error(sock, "409 Conflict", "Discord webhook not set"); return; }
    uint32_t n = discord_request_test();
    if (!n) { send_error(sock, "503 Service Unavailable", "Discord task not running"); return; }
    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"queued\":true,\"test\":%lu}", (unsigned long)n);
    send_json(sock, &j);
}

static void get_discord_status(int sock)
{
    discord_status_t d;
    discord_get_status(&d);
    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{");
    jb_bool(&j, "enabled", settings_discord_enabled());
    JB_LIT(&j, ",");
    jb_bool(&j, "log_events", settings_get()->discord_log_events);
    JB_LIT(&j, ",");
    jb_bool(&j, "test_ok", d.test_ok);
    jb_printf(&j, ",\"test_req\":%lu,\"test_done\":%lu,\"test_status\":%d,\"last_status\":%d,"
                  "\"posted\":%lu,\"failed\":%lu,\"dropped\":%lu}",
              (unsigned long)d.test_req, (unsigned long)d.test_done, d.test_status, d.last_status,
              (unsigned long)d.posted, (unsigned long)d.failed, (unsigned long)d.dropped);
    send_json(sock, &j);
}

// Same pattern as Discord: the test runs on the WhatsApp task.
static void post_whatsapp_test(int sock)
{
    if (!settings_whatsapp_enabled()) { send_error(sock, "409 Conflict", "WhatsApp phone or apikey not set"); return; }
    uint32_t n = whatsapp_request_test();
    if (!n) { send_error(sock, "503 Service Unavailable", "WhatsApp task not running"); return; }
    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"queued\":true,\"test\":%lu}", (unsigned long)n);
    send_json(sock, &j);
}

static void get_whatsapp_status(int sock)
{
    whatsapp_status_t w;
    whatsapp_get_status(&w);
    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{");
    jb_bool(&j, "enabled", settings_whatsapp_enabled());
    JB_LIT(&j, ",");
    jb_bool(&j, "test_ok", w.test_ok);
    jb_printf(&j, ",\"test_req\":%lu,\"test_done\":%lu,\"test_status\":%d,\"last_status\":%d,"
                  "\"sent\":%lu,\"failed\":%lu,\"dropped\":%lu}",
              (unsigned long)w.test_req, (unsigned long)w.test_done, w.test_status, w.last_status,
              (unsigned long)w.sent, (unsigned long)w.failed, (unsigned long)w.dropped);
    send_json(sock, &j);
}

static void post_reboot(int sock)
{
    ESP_LOGW(TAG, "Reboot requested from the dashboard");
    send_204(sock);
    sd_log_flush();                             // save the summary metrics first
    shutdown(sock, SHUT_RDWR);
    close(sock);
    vTaskDelay(pdMS_TO_TICKS(500));
    notify_restart_intent(NOTIFY_RESTART_DASHBOARD);
    esp_restart();
}

// ── Summary metrics ───────────────────────────────────────────────────────────

static uint32_t local_day(time_t t)
{
    struct tm tm;
    localtime_r(&t, &tm);
    return (uint32_t)((tm.tm_year + 1900) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday);
}

static void get_summary(int sock)
{
    sd_status_t st;
    sd_log_status(&st);
    sd_log_stats(s_stats);
    const sd_stats_t *m = s_stats;
    alarm_info_t a;
    alarm_get(&a);

    time_t now = time(NULL);
    bool clock_ok = now >= 1600000000;
    uint32_t now_hour = (uint32_t)(now / 3600);

    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"now\":%lld,\"clock_ok\":%s,\"uptime_s\":%llu,\"flash_total\":%lu,",
              (long long)now, clock_ok ? "true" : "false",
              (unsigned long long)(esp_timer_get_time() / 1000000ULL),
              (unsigned long)log_store_total_count());

    JB_LIT(&j, "\"sd\":{");
    jb_bool(&j, "mounted", st.mounted);
    JB_LIT(&j, ",\"card\":");
    jb_str(&j, st.card_name, sizeof(st.card_name));
    jb_printf(&j, ",\"total_mb\":%llu,\"free_mb\":%llu,\"lines\":%lu,\"errors\":%lu,\"dropped\":%lu},",
              (unsigned long long)(st.total_bytes >> 20), (unsigned long long)(st.free_bytes >> 20),
              (unsigned long)st.lines_written, (unsigned long)st.write_errors, (unsigned long)st.dropped);

    jb_printf(&j, "\"total\":%lu,\"first_ts\":%lu,\"last_ts\":%lu,\"by_type\":[",
              (unsigned long)m->total, (unsigned long)m->first_ts, (unsigned long)m->last_ts);
    for (int i = 0; i < ATTACK_TYPE_COUNT; i++) jb_printf(&j, "%s%lu", i ? "," : "", (unsigned long)m->by_type[i]);
    JB_LIT(&j, "],");
    detect_stats_t ds;
    detect_get_stats(&ds);
    jb_printf(&j, "\"detect\":{\"queued\":%lu,\"dropped\":%lu,\"admin_dropped\":%lu,\"arp_requests\":%lu,"
              "\"scans\":%lu,\"probes\":%lu,\"sweeps\":%lu,\"arp_tap\":%s},",
              (unsigned long)ds.queued, (unsigned long)ds.dropped, (unsigned long)ds.admin_dropped,
              (unsigned long)ds.arp_requests, (unsigned long)ds.scans, (unsigned long)ds.probes,
              (unsigned long)ds.sweeps, ds.arp_tap ? "true" : "false");

    // 24 hourly counts, oldest first, ending with the current hour.
    uint32_t last24 = 0;
    jb_printf(&j, "\"hour_end\":%lu,\"hourly\":[", (unsigned long)now_hour);
    for (int k = 23; k >= 0; k--) {
        uint32_t c = 0;
        if (clock_ok) {
            uint32_t hr = now_hour - (uint32_t)k, slot = hr % 24;
            if (m->hour_key[slot] == hr) c = m->hour_count[slot];
        }
        last24 += c;
        jb_printf(&j, "%s%lu", k == 23 ? "" : ",", (unsigned long)c);
    }
    jb_printf(&j, "],\"last_24h\":%lu,", (unsigned long)last24);

    // Daily series, oldest first: [[YYYYMMDD, count], ...]
    uint32_t today = clock_ok ? local_day(now) : 0, today_n = 0;
    int order[STATS_DAYS], nd = 0;
    for (int i = 0; i < STATS_DAYS; i++) {
        if (!m->day_key[i] || !m->day_count[i]) continue;
        if (m->day_key[i] == today) today_n = m->day_count[i];
        int k = nd++;
        while (k > 0 && m->day_key[order[k - 1]] > m->day_key[i]) { order[k] = order[k - 1]; k--; }
        order[k] = i;
    }
    jb_printf(&j, "\"today\":%lu,\"today_key\":%lu,\"daily\":[", (unsigned long)today_n, (unsigned long)today);
    for (int i = 0; i < nd; i++)
        jb_printf(&j, "%s[%lu,%lu]", i ? "," : "",
                  (unsigned long)m->day_key[order[i]], (unsigned long)m->day_count[order[i]]);
    JB_LIT(&j, "],");

    // Top sources by count.
    bool used[STATS_SRC_MAX] = {0};
    JB_LIT(&j, "\"top_sources\":[");
    for (int n = 0; n < TOP_N; n++) {
        int best = -1;
        for (int i = 0; i < STATS_SRC_MAX; i++)
            if (!used[i] && m->src[i].count && (best < 0 || m->src[i].count > m->src[best].count)) best = i;
        if (best < 0) break;
        used[best] = true;
        const stat_src_t *s = &m->src[best];
        char ip[16], mac[WIFI_MAC_STR_LEN];
        ip4_addr_t ia = { .addr = s->ip };
        ip4addr_ntoa_r(&ia, ip, sizeof(ip));
        wifi_manager_format_mac(s->mac, mac, sizeof(mac));
        jb_printf(&j, "%s{\"ip\":\"%s\",\"mac\":", n ? "," : "", ip);
        jb_str(&j, mac, sizeof(mac));
        JB_LIT(&j, ",\"vendor\":");
        jb_str(&j, wifi_manager_mac_vendor(s->mac), 64);
        jb_printf(&j, ",\"count\":%lu,\"first_ts\":%lu,\"last_ts\":%lu,\"last_type\":%u}",
                  (unsigned long)s->count, (unsigned long)s->first_ts, (unsigned long)s->last_ts,
                  s->last_type < ATTACK_TYPE_COUNT ? (unsigned)s->last_type : 255u);
    }
    JB_LIT(&j, "],");

    // Top credential pairs (attacker-supplied: escaped, length-bounded).
    bool cused[STATS_CRED_MAX] = {0};
    JB_LIT(&j, "\"top_creds\":[");
    for (int n = 0; n < TOP_N; n++) {
        int best = -1;
        for (int i = 0; i < STATS_CRED_MAX; i++)
            if (!cused[i] && m->cred[i].count && (best < 0 || m->cred[i].count > m->cred[best].count)) best = i;
        if (best < 0) break;
        cused[best] = true;
        const stat_cred_t *c = &m->cred[best];
        if (n) JB_LIT(&j, ",");
        JB_LIT(&j, "{\"user\":");
        jb_str(&j, c->user, sizeof(c->user));
        JB_LIT(&j, ",\"pass\":");
        jb_str(&j, c->pass, sizeof(c->pass));
        jb_printf(&j, ",\"count\":%lu}", (unsigned long)c->count);
    }
    JB_LIT(&j, "],");

    char alarm_j[WS_ALARM_JSON_MAX];     // was 256: the alarm object came out cut (invalid JSON)
    ws_format_alarm_json(&a, alarm_j, sizeof(alarm_j));
    jb_printf(&j, "\"incidents\":%lu,\"alarm\":%s}", (unsigned long)a.id, alarm_j);
    send_json(sock, &j);
}

// ── Log files ─────────────────────────────────────────────────────────────────

// YYYY-MM-DD.jsonl or nosync.jsonl, nothing else: the name goes into a path.
static bool valid_log_name(const char *n)
{
    if (strcmp(n, "nosync.jsonl") == 0) return true;
    if (strlen(n) != 16) return false;
    for (int i = 0; i < 10; i++) {
        bool dash = (i == 4 || i == 7);
        if (dash ? n[i] != '-' : (n[i] < '0' || n[i] > '9')) return false;
    }
    return strcmp(n + 10, ".jsonl") == 0;
}

// Newest first; nosync.jsonl (no date) last.
static int file_cmp(const void *pa, const void *pb)
{
    const log_file_t *a = pa, *b = pb;
    bool an = a->name[0] == 'n', bn = b->name[0] == 'n';
    if (an != bn) return an ? 1 : -1;
    return -strcmp(a->name, b->name);
}

static void get_logs(int sock)
{
    sd_status_t st;
    sd_log_status(&st);
    int n = 0;
    DIR *d = st.mounted ? opendir(SD_LOG_DIR) : NULL;
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!valid_log_name(de->d_name)) continue;
            int slot = n;
            if (n == LOG_FILES_MAX) {               // full: replace the oldest dated one
                slot = -1;
                for (int i = 0; i < n; i++)
                    if (slot < 0 || file_cmp(&s_files[i], &s_files[slot]) > 0) slot = i;
                log_file_t cand;
                strlcpy(cand.name, de->d_name, sizeof(cand.name));
                if (file_cmp(&cand, &s_files[slot]) >= 0) continue;
            } else {
                n++;
            }
            strlcpy(s_files[slot].name, de->d_name, sizeof(s_files[slot].name));
        }
        closedir(d);
    }
    for (int i = 0; i < n; i++) {
        char path[48];
        struct stat sb;
        snprintf(path, sizeof(path), SD_LOG_DIR "/%s", s_files[i].name);
        s_files[i].size = stat(path, &sb) == 0 ? (uint32_t)sb.st_size : 0;
    }
    qsort(s_files, (size_t)n, sizeof(*s_files), file_cmp);

    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{");
    jb_bool(&j, "mounted", st.mounted);
    jb_printf(&j, ",\"tail_bytes\":%d,\"files\":[", TAIL_BYTES);
    for (int i = 0; i < n; i++)
        jb_printf(&j, "%s{\"name\":\"%s\",\"size\":%lu}", i ? "," : "",
                  s_files[i].name, (unsigned long)s_files[i].size);   // names validated above
    JB_LIT(&j, "]}");
    send_json(sock, &j);
}

static void get_log_file(int sock, const char *query)
{
    char name[20], flag[4];
    if (!query_param(query, "f", name, sizeof(name)) || !valid_log_name(name)) {
        send_error(sock, "400 Bad Request", "f must be YYYY-MM-DD.jsonl or nosync.jsonl");
        return;
    }
    bool tail = query_param(query, "tail", flag, sizeof(flag)) && strcmp(flag, "1") == 0;
    bool dl   = query_param(query, "dl", flag, sizeof(flag)) && strcmp(flag, "1") == 0;

    sd_status_t st;
    sd_log_status(&st);
    if (!st.mounted) { send_error(sock, "503 Service Unavailable", "no microSD card"); return; }

    char path[48];
    snprintf(path, sizeof(path), SD_LOG_DIR "/%s", name);
    FILE *f = fopen(path, "rb");
    if (!f) { send_error(sock, "404 Not Found", "no such log file"); return; }
    struct stat sb;
    if (fstat(fileno(f), &sb) != 0 || sb.st_size < 0) {
        fclose(f);
        send_error(sock, "500 Internal Server Error", "stat failed");
        return;
    }
    // Size fixed now: the writer may append while we stream, we stop here.
    long size = (long)sb.st_size, start = 0;
    if (tail && size > TAIL_BYTES) {
        start = size - TAIL_BYTES;
        if (fseek(f, start, SEEK_SET) == 0) {
            size_t got = fread(s_chunk, 1, CHUNK, f);
            char *nl = memchr(s_chunk, '\n', got);
            start = nl ? start + (long)(nl - s_chunk) + 1 : size;   // start on a whole line
        }
        if (fseek(f, start, SEEK_SET) != 0) start = size;
    }

    char extra[80] = "";
    if (dl) snprintf(extra, sizeof(extra), "Content-Disposition: attachment; filename=\"%s\"\r\n", name);
    size_t remaining = (size_t)(size - start);
    if (send_head(sock, "200 OK", "application/x-ndjson; charset=utf-8", remaining, extra)) {
        while (remaining) {
            size_t want = remaining < CHUNK ? remaining : CHUNK;
            size_t got = fread(s_chunk, 1, want, f);
            if (got == 0 || !send_all(sock, s_chunk, got)) break;   // short: client sees it
            remaining -= got;
        }
    }
    fclose(f);
}

// ── Ignore list: GET /api/ignore, POST /api/ignore (detect-core) ──────────────
//
// POST {"action":"add","ip":"192.168.0.50","mac":"aa:bb:cc:dd:ee:ff","code":"17-01","note":"NAS"}
//   ip and mac are optional, one is required; "" means none. code is
//   optional: absent or "" ignores the whole device, else one code from the
//   table (describe.h, GET /api/codes) from that device only.
// POST {"action":"remove","index":3,"ip":"...","mac":"...","code":"..."}
//   ip and mac (and code, if given) must still match entry 3 as listed, so a
//   panel add in between can't make the dashboard remove the wrong entry
//   (409 if it moved).

static void get_ignore(int sock)
{
    ignore_entry_t *l = (ignore_entry_t *)s_chunk;          // 32 x 56 B fits CHUNK
    _Static_assert(IGNORE_MAX * sizeof(ignore_entry_t) <= CHUNK, "ignore list must fit s_chunk");
    int n = ignore_list(l, IGNORE_MAX);
    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"max\":%d,\"entries\":[", IGNORE_MAX);
    for (int i = 0; i < n; i++) {
        static const uint8_t zero[6] = { 0 };
        bool has_mac = memcmp(l[i].mac, zero, 6) != 0;
        char mac[WIFI_MAC_STR_LEN] = "";
        if (has_mac) wifi_manager_format_mac(l[i].mac, mac, sizeof(mac));
        jb_printf(&j, "%s{\"index\":%d,\"ip\":", i ? "," : "", i);
        jb_ip(&j, l[i].ip);
        JB_LIT(&j, ",\"mac\":");
        jb_str(&j, mac, sizeof(mac));
        JB_LIT(&j, ",\"vendor\":");
        jb_str(&j, has_mac ? wifi_manager_mac_vendor(l[i].mac) : "", 64);
        JB_LIT(&j, ",\"code\":");
        jb_str(&j, l[i].code, sizeof(l[i].code));
        JB_LIT(&j, ",\"code_name\":");
        const char *cn = l[i].code[0] ? describe_code_name(l[i].code) : NULL;
        jb_str(&j, cn ? cn : "", 32);
        JB_LIT(&j, ",\"note\":");
        jb_str(&j, l[i].note, sizeof(l[i].note));
        jb_printf(&j, ",\"ts\":%lu}", (unsigned long)l[i].added_ts);
    }
    JB_LIT(&j, "]}");
    send_json(sock, &j);
}

// Optional "ip" / "mac" strings: absent or "" = none. Returns an error or NULL.
static const char *take_addr(const cJSON *root, uint32_t *ip, uint8_t mac[6])
{
    *ip = 0;
    memset(mac, 0, 6);
    const cJSON *a = cJSON_GetObjectItemCaseSensitive(root, "ip");
    const cJSON *m = cJSON_GetObjectItemCaseSensitive(root, "mac");
    if (a && !cJSON_IsNull(a)) {
        if (!cJSON_IsString(a) || !a->valuestring) return "ip must be a string";
        if (a->valuestring[0] && (!parse_ipv4(a->valuestring, ip) || !*ip)) return "ip must be an IPv4 address like 192.168.0.50";
    }
    if (m && !cJSON_IsNull(m)) {
        if (!cJSON_IsString(m) || !m->valuestring) return "mac must be a string";
        if (m->valuestring[0] && !parse_mac(m->valuestring, mac)) return "mac must look like aa:bb:cc:dd:ee:ff";
    }
    return NULL;
}

static void post_ignore(int sock, const char *req, int req_len)
{
    size_t blen = 0;
    const char *why = NULL;
    const char *status = read_body(sock, req, req_len, &blen, &why);
    if (status) { send_error(sock, status, why); return; }
    if (!json_depth_ok(s_body, blen, 2)) { send_error(sock, "400 Bad Request", "JSON nested too deeply"); return; }
    cJSON *root = cJSON_ParseWithLength(s_body, blen);
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        send_error(sock, "400 Bad Request", "body must be a JSON object");
        return;
    }
    const cJSON *act = cJSON_GetObjectItemCaseSensitive(root, "action");
    const char *action = cJSON_IsString(act) && act->valuestring ? act->valuestring : "";
    uint32_t ip;
    uint8_t mac[6];
    static const uint8_t zero[6] = { 0 };
    const char *err = take_addr(root, &ip, mac);
    const char *st = "400 Bad Request";
    esp_err_t r = ESP_OK;
    const cJSON *cd = cJSON_GetObjectItemCaseSensitive(root, "code");
    const char *code = "";
    if (!err && cd && !cJSON_IsNull(cd)) {
        if (!cJSON_IsString(cd) || !cd->valuestring) err = "code must be a string";
        else if (cd->valuestring[0] && !describe_code_name(cd->valuestring)) err = "code is not in the code table (GET /api/codes)";
        else code = cd->valuestring;
    }

    if (err) {
        /* reported below */
    } else if (!strcmp(action, "add")) {
        const cJSON *nt = cJSON_GetObjectItemCaseSensitive(root, "note");
        const char *note = cJSON_IsString(nt) && nt->valuestring ? nt->valuestring : "";
        if (!ip && !memcmp(mac, zero, 6)) err = "give an IP, a MAC or both";
        else if (strlen(note) >= IGNORE_NOTE_MAX) err = "note is too long (max 39)";
        else {
            r = ignore_add(ip, memcmp(mac, zero, 6) ? mac : NULL, code, note);
            if (r == ESP_ERR_NO_MEM) { st = "409 Conflict"; err = "the ignore list is full (32)"; }
            else if (r != ESP_OK)    { st = "500 Internal Server Error"; err = "could not save the ignore list"; }
        }
    } else if (!strcmp(action, "remove")) {
        const cJSON *ix = cJSON_GetObjectItemCaseSensitive(root, "index");
        ignore_entry_t *l = (ignore_entry_t *)s_chunk;
        int n = ignore_list(l, IGNORE_MAX);
        double d = cJSON_IsNumber(ix) ? ix->valuedouble : -1;
        int i = (d >= 0 && d < IGNORE_MAX) ? (int)d : -1;      // range first: no UB cast
        if (i < 0 || d != (double)i || i >= n) err = "index out of range";
        else if (l[i].ip != ip || memcmp(l[i].mac, mac, 6) || (cd && strcmp(l[i].code, code))) {
            st = "409 Conflict"; err = "the list changed, reload it";
        }
        else if (ignore_remove(i) != ESP_OK) { st = "500 Internal Server Error"; err = "could not save the ignore list"; }
    } else {
        err = "action must be add or remove";
    }
    cJSON_Delete(root);
    if (err) { send_error(sock, st, err); return; }
    ESP_LOGI(TAG, "Ignore list %s from the dashboard", action);
    get_ignore(sock);
}

// ── Alarm: ack, resolve, ignore; GET /api/codes ───────────────────────────────
//
// POST /api/alarm/ack (alias /api/ack): RED -> YELLOW.
// POST /api/alarm/resolve (alias /api/alarm/clear): RED or YELLOW -> GREEN.
// POST /api/alarm/ignore {"scope":"error"|"device"}: ignore the incident's
//   code from its source, or the whole source, then resolve the incident,
//   whatever other codes it saw.
// Each answers 200 {"alarm":{...}} (the /api/status shape) once the alarm
// task has applied it, or after ALARM_WAIT_MS with the state as it stands;
// 409 when there is nothing to act on. Logs and metrics are never touched.

#define ALARM_WAIT_MS   600

static void send_alarm(int sock, const alarm_info_t *a)
{
    char inner[WS_ALARM_JSON_MAX];
    ws_format_alarm_json(a, inner, sizeof(inner));
    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{\"alarm\":");
    jb_raw(&j, inner, strlen(inner));
    JB_LIT(&j, "}");
    send_json(sock, &j);
}

// Wait for the alarm task to leave state `from` in incident `id` (or for a
// new incident). Returns the state as it stands.
static void alarm_wait(uint32_t id, alarm_state_t from, alarm_info_t *a)
{
    for (int t = 0; t < ALARM_WAIT_MS; t += 20) {
        vTaskDelay(pdMS_TO_TICKS(20));
        alarm_get(a);
        if (a->id != id || a->state != from) return;
    }
}

static void post_alarm_ack(int sock)
{
    alarm_info_t a;
    alarm_get(&a);
    if (a.state != ALARM_ACTIVE) { send_error(sock, "409 Conflict", "no unacknowledged (red) incident"); return; }
    alarm_ack(ALARM_BY_DASHBOARD);
    ESP_LOGI(TAG, "Incident #%lu acknowledged from the dashboard", (unsigned long)a.id);
    alarm_wait(a.id, a.state, &a);
    send_alarm(sock, &a);
}

static void post_alarm_resolve(int sock)
{
    alarm_info_t a;
    alarm_get(&a);
    if (a.state == ALARM_IDLE) { send_error(sock, "409 Conflict", "no open incident"); return; }
    alarm_resolve(ALARM_BY_DASHBOARD);
    ESP_LOGI(TAG, "Incident #%lu resolved from the dashboard", (unsigned long)a.id);
    alarm_wait(a.id, a.state, &a);
    send_alarm(sock, &a);
}

static void post_alarm_ignore(int sock, const char *req, int req_len)
{
    size_t blen = 0;
    const char *why = NULL;
    const char *status = read_body(sock, req, req_len, &blen, &why);
    if (status) { send_error(sock, status, why); return; }
    if (!json_depth_ok(s_body, blen, 2)) { send_error(sock, "400 Bad Request", "JSON nested too deeply"); return; }
    cJSON *root = cJSON_ParseWithLength(s_body, blen);
    const cJSON *sc = root ? cJSON_GetObjectItemCaseSensitive(root, "scope") : NULL;
    int scope = !cJSON_IsString(sc) || !sc->valuestring ? -1
              : !strcmp(sc->valuestring, "error") ? 0 : !strcmp(sc->valuestring, "device") ? 1 : -1;
    cJSON_Delete(root);
    if (scope < 0) { send_error(sock, "400 Bad Request", "scope must be error or device"); return; }

    alarm_info_t a;
    alarm_get(&a);
    if (a.state == ALARM_IDLE) { send_error(sock, "409 Conflict", "no open incident"); return; }
    esp_err_t r = scope ? alarm_ignore_device(ALARM_BY_DASHBOARD) : alarm_ignore_error(ALARM_BY_DASHBOARD);
    if (r == ESP_ERR_NO_MEM)        { send_error(sock, "409 Conflict", "the ignore list is full (32)"); return; }
    if (r == ESP_ERR_INVALID_STATE) { send_error(sock, "409 Conflict", "no open incident with a source"); return; }
    if (r != ESP_OK)                { send_error(sock, "500 Internal Server Error", "could not save the ignore list"); return; }
    alarm_wait(a.id, a.state, &a);
    send_alarm(sock, &a);
}

static void get_codes(int sock)
{
    jb_t j;
    jb_init(&j);
    JB_LIT(&j, "{\"codes\":[");
    for (int i = 0; i < describe_code_count(); i++) {
        const char *name = NULL;
        int tier = 0;
        const char *code = describe_code_at(i, &name, &tier);
        jb_printf(&j, "%s{\"code\":\"%s\",\"name\":", i ? "," : "", code);   // fixed table text
        jb_str(&j, name, 32);
        jb_printf(&j, ",\"tier\":%d}", tier);
    }
    JB_LIT(&j, "]}");
    send_json(sock, &j);
}

// ── POST /api/debug/panel {"paused":bool} (debug, not in the dashboard) ───────
//
// Stops the UI task running LVGL, so the panel neither refreshes nor uses the
// SPI bus, to split network latency between the panel and the rest.

// One debug toggle: reads {"<key>":bool}, calls set(), answers {"<key>":bool}.
// Also POST /api/debug/promisc {"on":bool} (the Wi-Fi monitor's promiscuous
// mode) and POST /api/debug/hooks {"on":bool} (detect's IPv4 hook and ARP tap).
static void post_debug_toggle(int sock, const char *req, int req_len, const char *key, void (*set)(bool))
{
    // These routes run before the dispatcher's bufs_ready(): without this, the
    // first request after a boot being a toggle wrote the body through a NULL
    // s_body (a StoreProhibited panic).
    if (!bufs_ready()) { send_error(sock, "503 Service Unavailable", "out of memory"); return; }
    size_t blen = 0;
    const char *why = NULL;
    const char *status = read_body(sock, req, req_len, &blen, &why);
    if (status) { send_error(sock, status, why); return; }
    cJSON *root = cJSON_ParseWithLength(s_body, blen);
    const cJSON *p = root ? cJSON_GetObjectItemCaseSensitive(root, key) : NULL;
    if (!cJSON_IsBool(p)) {
        cJSON_Delete(root);
        send_error(sock, "400 Bad Request", "need one boolean field");
        return;
    }
    bool v = cJSON_IsTrue(p);
    cJSON_Delete(root);
    set(v);
    jb_t j;
    jb_init(&j);
    jb_printf(&j, "{\"%s\":%s}", key, v ? "true" : "false");
    send_json(sock, &j);
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

bool api_ext_handle(int sock, const char *req, int req_len)
{
    char method[8], path[48], query[96];
    if (!parse_request_line(req, method, sizeof(method), path, sizeof(path), query, sizeof(query)))
        return false;
    bool get = strcmp(method, "GET") == 0, post = strcmp(method, "POST") == 0;
    if (post && !strcmp(path, "/api/debug/panel"))   { post_debug_toggle(sock, req, req_len, "paused", ui_debug_pause); return true; }
    if (post && !strcmp(path, "/api/debug/promisc")) { post_debug_toggle(sock, req, req_len, "on", wifi_monitor_debug_promisc); return true; }
    if (post && !strcmp(path, "/api/debug/hooks"))   { post_debug_toggle(sock, req, req_len, "on", detect_debug_hooks); return true; }

    enum { R_NONE, R_SET_GET, R_SET_POST, R_REBOOT, R_BUZZ, R_SUMMARY, R_LOGS, R_FILE,
           R_DC_TEST, R_DC_STATUS, R_IGN_GET, R_IGN_POST, R_WA_TEST, R_WA_STATUS,
           R_AL_ACK, R_AL_RESOLVE, R_AL_IGNORE, R_CODES } r = R_NONE;
    if      (get  && !strcmp(path, "/api/settings"))    r = R_SET_GET;
    else if (post && !strcmp(path, "/api/settings"))    r = R_SET_POST;
    else if (post && !strcmp(path, "/api/reboot"))      r = R_REBOOT;
    else if (post && !strcmp(path, "/api/buzzer/test")) r = R_BUZZ;
    else if (get  && !strcmp(path, "/api/summary"))     r = R_SUMMARY;
    else if (get  && !strcmp(path, "/api/logs"))        r = R_LOGS;
    else if (get  && !strcmp(path, "/api/logs/file"))   r = R_FILE;
    else if (post && !strcmp(path, "/api/discord/test"))   r = R_DC_TEST;
    else if (get  && !strcmp(path, "/api/discord/status")) r = R_DC_STATUS;
    else if (get  && !strcmp(path, "/api/ignore"))      r = R_IGN_GET;
    else if (post && !strcmp(path, "/api/ignore"))      r = R_IGN_POST;
    else if (post && !strcmp(path, "/api/whatsapp/test"))   r = R_WA_TEST;
    else if (get  && !strcmp(path, "/api/whatsapp/status")) r = R_WA_STATUS;
    else if (post && (!strcmp(path, "/api/alarm/ack") || !strcmp(path, "/api/ack")))           r = R_AL_ACK;
    else if (post && (!strcmp(path, "/api/alarm/resolve") || !strcmp(path, "/api/alarm/clear"))) r = R_AL_RESOLVE;
    else if (post && !strcmp(path, "/api/alarm/ignore")) r = R_AL_IGNORE;
    else if (get  && !strcmp(path, "/api/codes"))        r = R_CODES;
    if (r == R_NONE) return false;

    // A client that stops reading can't hold the single admin task for ever.
    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (!bufs_ready()) { send_error(sock, "503 Service Unavailable", "out of memory"); return true; }
    switch (r) {
    case R_SET_GET:  get_settings(sock); break;
    case R_SET_POST: post_settings(sock, req, req_len); break;
    case R_REBOOT:   post_reboot(sock); break;
    case R_BUZZ:     buzzer_test(); send_204(sock); break;
    case R_SUMMARY:  get_summary(sock); break;
    case R_LOGS:     get_logs(sock); break;
    case R_FILE:     get_log_file(sock, query); break;
    case R_DC_TEST:  post_discord_test(sock); break;
    case R_DC_STATUS: get_discord_status(sock); break;
    case R_IGN_GET:  get_ignore(sock); break;
    case R_IGN_POST: post_ignore(sock, req, req_len); break;
    case R_WA_TEST:  post_whatsapp_test(sock); break;
    case R_WA_STATUS: get_whatsapp_status(sock); break;
    case R_AL_ACK:     post_alarm_ack(sock); break;
    case R_AL_RESOLVE: post_alarm_resolve(sock); break;
    case R_AL_IGNORE:  post_alarm_ignore(sock, req, req_len); break;
    case R_CODES:      get_codes(sock); break;
    default: break;
    }
    return true;
}
