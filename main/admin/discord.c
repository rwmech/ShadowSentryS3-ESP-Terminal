// Discord webhook alerts: incident embeds, reminders and a deduplicated event
// log. See discord.h. Fork addition, Robert Mech.
//
// Threading: the alarm listener runs on the alarm task, the log_store listener
// on whichever task appended (a trap task can have 3 KB of stack), so both only
// copy into a queue. discord_task owns everything else: the key table, the
// incident tracking and the one HTTPS sender. Big buffers are PSRAM.

#include "discord.h"
#include "notify.h"
#include "alarm.h"
#include "log_store.h"
#include "settings.h"
#include "wifi_manager.h"
#include "ignore.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/idf_additions.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char *TAG = "DISCORD";

#define DC_EVENT_QUEUE      96      // attack_log_t each (~236 B), PSRAM
#define DC_ALARM_QUEUE      8
#define DC_NOTICE_QUEUE     4       // notify_msg_t each (~390 B), PSRAM
#define DC_BODY_MAX         8192    // JSON body, PSRAM
#define DC_CONTENT_CAP      2048    // raw content before escaping, PSRAM
#define DC_CONTENT_MAX      1900    // Discord's limit is 2000 characters
#define DC_TAIL_RESERVE     100     // "+N more" and "not counted" lines, closing fence
#define DC_RESP_MAX         384
#define DC_HTTP_TIMEOUT_MS  10000
#define DC_RETRIES          3       // transport errors and 5xx
#define DC_429_RETRIES      3       // 429s, on top of the above
#define DC_RETRY_DELAY_MS   3000
#define DC_WIFI_WAIT_MS     15000
#define DC_MIN_GAP_MS       1000    // between posts; the webhook allows ~5 per 2 s
#define DC_MAX_WAIT_MS      60000   // cap on any 429 / rate-limit wait
#define DC_BATCH_MIN_S      5       // an early (size) flush waits at least this long
#define DC_BATCH_KEYS       32      // lines per batch post
#define DC_KEYS             64      // dedup table entries, PSRAM
#define DC_SUMMARY_LEN      64
#define DC_RECENT           8       // recent events kept for the incident-open embed
#define DC_REMIND_MIN_S     30
#define DC_DRAIN_MAX        128     // events handled per loop before checking the rest

#define COLOR_RED     0xE53935
#define COLOR_AMBER   0xFFB300
#define COLOR_GREEN   0x43A047
#define COLOR_ORANGE  0xFB8C00
#define COLOR_BLURPLE 0x5865F2

enum { ACK_PANEL = 0, ACK_DASHBOARD = 1 };

typedef struct {
    alarm_info_t cur;
    alarm_info_t prev;      // the listener's previous snapshot: final count of a superseded incident
    uint8_t      ack_src;
    bool         rearmed;   // IDLE reached by re-arm, not by the quiet timer
} dc_alarm_msg_t;

typedef struct {
    bool     used, posted, sel;
    bool     ignored;       // source on the ignore list at its latest event
    uint8_t  type;
    uint32_t ip;
    uint32_t pending;       // events since the last post
    int64_t  last_seen;     // monotonic s
    int64_t  last_post;
    char     summary[DC_SUMMARY_LEN];   // printable ASCII, no backticks
} dc_key_t;

typedef struct {
    uint32_t ip, ts;
    uint8_t  type;
    char     user[32];
    char     payload[128];
} dc_recent_t;

static QueueHandle_t     s_evq, s_alq, s_ntq;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;
static discord_status_t  s_stat;                // guarded by s_mux
static bool              s_running;
static alarm_info_t      s_prev;                // alarm listener only
static alarm_info_t      s_carry;               // ACTIVE incident found at init
static volatile uint32_t s_dash_ack_tick;       // 0 = none

// Task-only state.
static char         *s_body, *s_content, *s_url, *s_resp;
static settings_t   *s_set;
static dc_key_t     *s_keys;
static dc_recent_t  *s_recent;
static int           s_recent_next;
static attack_log_t  s_ev;
static int           s_resp_len;
static int           s_hdr_retry_ms, s_rl_remaining, s_rl_reset_ms;
static TickType_t    s_next_ok;                 // pacing: no post before this tick
static bool          s_stack_logged;

// Incident being reminded about.
static bool          s_inc_active;
static alarm_info_t  s_inc;
static int64_t       s_inc_seen;                // monotonic s when we saw it open
static int64_t       s_next_remind;

static int64_t       s_last_batch;
static uint32_t      s_dropped_reported, s_lost, s_lost_reported;
static bool          s_log_was_on;

static int64_t mono_s(void) { return esp_timer_get_time() / 1000000LL; }

static const char *const TYPE_SHORT[] = {"RTSP", "HTTP", "Telnet", "SSH", "FTP", "ARP", "WiFi", "Shell",
                                         "Scan", "Probe", "Sweep", "ADB"};
static const char *const TYPE_LONG[]  = {"RTSP login", "HTTP request", "Telnet login", "SSH login",
                                         "FTP login", "ARP spoofing / MITM", "Wi-Fi deauth flood",
                                         "Interactive shell", "Port scan", "Probe", "ARP sweep",
                                         "ADB (Android Debug Bridge)"};
_Static_assert(sizeof(TYPE_SHORT) / sizeof(TYPE_SHORT[0]) == ATTACK_TYPE_COUNT, "TYPE_SHORT: one per attack_type_t");
_Static_assert(sizeof(TYPE_LONG) / sizeof(TYPE_LONG[0]) == ATTACK_TYPE_COUNT, "TYPE_LONG: one per attack_type_t");
static const char *type_short(uint8_t t) { return t < ATTACK_TYPE_COUNT ? TYPE_SHORT[t] : "?"; }
static const char *type_long(uint8_t t)  { return t < ATTACK_TYPE_COUNT ? TYPE_LONG[t] : "unknown"; }

static void count_drop(void)
{
    portENTER_CRITICAL(&s_mux);
    s_stat.dropped++;
    portEXIT_CRITICAL(&s_mux);
}

// ── Listeners (copy and enqueue only) ─────────────────────────────────────────

static void on_alarm(const alarm_info_t *a)
{
    // Transitions only: count-only updates arrive every second.
    if (a->state != s_prev.state || a->id != s_prev.id) {
        dc_alarm_msg_t m = { .cur = *a, .prev = s_prev, .ack_src = ACK_PANEL };
        uint32_t t = s_dash_ack_tick;
        if (a->state == ALARM_ACKED && t && (xTaskGetTickCount() - t) < pdMS_TO_TICKS(5000)) {
            m.ack_src = ACK_DASHBOARD;
        }
        if (a->state == ALARM_ACKED) s_dash_ack_tick = 0;
        if (a->state == ALARM_IDLE) m.rearmed = alarm_closed_by_rearm();   // we are on the alarm task
        if (xQueueSend(s_alq, &m, 0) != pdTRUE) count_drop();
    }
    s_prev = *a;
}

static void on_event(const attack_log_t *e)
{
    if (xQueueSend(s_evq, e, 0) != pdTRUE) count_drop();
}

void discord_note_dashboard_ack(void)
{
    s_dash_ack_tick = xTaskGetTickCount() | 1;
}

// notify.c backend: the boot message only (incidents post from on_alarm).
static bool notice_send(const notify_msg_t *m)
{
    return s_ntq && xQueueSend(s_ntq, m, 0) == pdTRUE;
}

static const notify_backend_t s_backend = {
    .name    = "Discord",
    .kinds   = NOTIFY_BIT(NOTIFY_BOOT),
    .enabled = settings_discord_enabled,
    .send    = notice_send,
};

void discord_init(void)
{
    s_evq = xQueueCreateWithCaps(DC_EVENT_QUEUE, sizeof(attack_log_t), MALLOC_CAP_SPIRAM);
    s_alq = xQueueCreate(DC_ALARM_QUEUE, sizeof(dc_alarm_msg_t));
    if (!s_evq || !s_alq) {
        ESP_LOGE(TAG, "No memory for the queues, Discord alerts off");
        return;
    }
    alarm_get(&s_prev);
    if (s_prev.state == ALARM_ACTIVE) s_carry = s_prev;   // survived a reboot
    alarm_add_listener(on_alarm);
    log_store_add_listener(on_event);
    s_ntq = xQueueCreateWithCaps(DC_NOTICE_QUEUE, sizeof(notify_msg_t), MALLOC_CAP_SPIRAM);
    if (s_ntq) notify_register(&s_backend);
}

uint32_t discord_request_test(void)
{
    if (!s_running) return 0;
    portENTER_CRITICAL(&s_mux);
    uint32_t n = ++s_stat.test_req;
    portEXIT_CRITICAL(&s_mux);
    return n;
}

void discord_get_status(discord_status_t *out)
{
    portENTER_CRITICAL(&s_mux);
    *out = s_stat;
    portEXIT_CRITICAL(&s_mux);
}

// ── Strings ───────────────────────────────────────────────────────────────────

// Attacker text to printable ASCII: control and non-ASCII bytes become '?'
// (invalid UTF-8 would make Discord reject the body), backticks become '\''
// so the text can't close its code span or block. Reads at most max bytes.
static void clean(char *dst, size_t cap, const char *src, size_t max)
{
    size_t o = 0;
    for (size_t i = 0; i < max && src[i] && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '`') c = '\'';
        else if (c < 0x20 || c > 0x7e) c = '?';
        dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

static void ip_str(uint32_t ip, char out[16])
{
    ip4_addr_t a = { .addr = ip };
    ip4addr_ntoa_r(&a, out, 16);
}

static void fmt_dur(uint32_t s, char *out, size_t cap)
{
    if (s < 60)         snprintf(out, cap, "%lu s", (unsigned long)s);
    else if (s < 3600)  snprintf(out, cap, "%lu min %lu s", (unsigned long)(s / 60), (unsigned long)(s % 60));
    else if (s < 86400) snprintf(out, cap, "%lu h %lu min", (unsigned long)(s / 3600), (unsigned long)(s % 3600 / 60));
    else                snprintf(out, cap, "%lu d %lu h", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600));
}

static bool clock_ok(void) { return time(NULL) >= 1600000000; }

static void device_str(char *out, size_t cap)
{
    char ip[WIFI_IP_STR_LEN];
    wifi_manager_get_ip_str(ip, sizeof(ip));
#if defined(MDNS_ENABLE) && MDNS_ENABLE
    snprintf(out, cap, "%s (%s.local)", ip[0] ? ip : "no IP", MDNS_HOSTNAME);
#else
    snprintf(out, cap, "%s (%s)", ip[0] ? ip : "no IP", DEVICE_HOSTNAME);
#endif
}

// ── Bounded JSON builder over s_body ──────────────────────────────────────────

typedef struct { char *b; size_t len, cap; bool full; } jb_t;

static void jb_init(jb_t *j) { j->b = s_body; j->len = 0; j->cap = DC_BODY_MAX; j->full = false; s_body[0] = '\0'; }

static void jb_raw(jb_t *j, const char *s, size_t n)
{
    if (j->full || j->len + n >= j->cap) { j->full = true; return; }
    memcpy(j->b + j->len, s, n);
    j->len += n;
    j->b[j->len] = '\0';
}

static void jb_lit(jb_t *j, const char *s) { jb_raw(j, s, strlen(s)); }

static void jb_fmt(jb_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_fmt(jb_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(j->b + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= j->cap - j->len) { j->full = true; j->b[j->len] = '\0'; return; }
    j->len += (size_t)n;
}

// A JSON string: pre + s + post, escaped. '@' gets a zero-width space after it
// (belt and braces next to allowed_mentions), non-ASCII becomes '?'.
static void jb_str3(jb_t *j, const char *pre, const char *s, const char *post)
{
    jb_lit(j, "\"");
    const char *parts[3] = { pre, s, post };
    for (int p = 0; p < 3; p++) {
        for (const char *c = parts[p]; c && *c; c++) {
            unsigned char ch = (unsigned char)*c;
            char e[8];
            if (ch == '"' || ch == '\\') { e[0] = '\\'; e[1] = (char)ch; jb_raw(j, e, 2); }
            else if (ch == '\n') jb_raw(j, "\\n", 2);
            else if (ch < 0x20 || ch == 0x7f) { snprintf(e, sizeof(e), "\\u%04x", ch); jb_raw(j, e, 6); }
            else if (ch > 0x7f) jb_raw(j, "?", 1);
            else if (ch == '@') jb_raw(j, "@\\u200b", 7);
            else jb_raw(j, (const char *)&ch, 1);
        }
    }
    jb_lit(j, "\"");
}

static void jb_str(jb_t *j, const char *s) { jb_str3(j, NULL, s, NULL); }

#define JB_HEAD "{\"username\":\"ShadowSentry\",\"allowed_mentions\":{\"parse\":[]},"

static void embed_begin(jb_t *j, const char *title, uint32_t color, const char *desc)
{
    jb_init(j);
    jb_lit(j, JB_HEAD "\"embeds\":[{\"title\":");
    jb_str(j, title);
    if (desc) { jb_lit(j, ",\"description\":"); jb_str(j, desc); }
    jb_fmt(j, ",\"color\":%lu,\"fields\":[", (unsigned long)color);
}

// Field values must be non-empty. code wraps the value in backticks (the value
// has none, see clean()), so attacker text renders literally.
static void field(jb_t *j, bool *first, const char *name, const char *value, bool inl, bool code)
{
    if (!value || !value[0]) { value = "-"; code = false; }
    jb_lit(j, *first ? "{\"name\":" : ",{\"name\":");
    *first = false;
    jb_str(j, name);
    jb_lit(j, ",\"value\":");
    jb_str3(j, code ? "`" : NULL, value, code ? "`" : NULL);
    jb_lit(j, inl ? ",\"inline\":true}" : ",\"inline\":false}");
}

static void embed_end(jb_t *j, uint32_t ts)
{
    jb_lit(j, "]");
    time_t t = ts ? (time_t)ts : time(NULL);
    if (t >= 1600000000) {
        struct tm tm;
        char iso[32];
        gmtime_r(&t, &tm);
        strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tm);
        jb_fmt(j, ",\"timestamp\":\"%s\"", iso);
    }
    char dev[64];
    device_str(dev, sizeof(dev));
    jb_lit(j, ",\"footer\":{\"text\":");
    jb_str3(j, "ShadowSentry S3 at ", dev, NULL);
    jb_lit(j, "}}]}");
}

// ── HTTPS sender ──────────────────────────────────────────────────────────────

static esp_err_t http_event(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_HEADER && evt->header_key && evt->header_value) {
        double v = strtod(evt->header_value, NULL);
        int ms = (v > 0 && v < 3600) ? (int)(v * 1000.0) : 0;
        if (!strcasecmp(evt->header_key, "Retry-After"))                s_hdr_retry_ms = ms;
        else if (!strcasecmp(evt->header_key, "X-RateLimit-Reset-After")) s_rl_reset_ms = ms;
        else if (!strcasecmp(evt->header_key, "X-RateLimit-Remaining"))  s_rl_remaining = atoi(evt->header_value);
    } else if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data && evt->data_len > 0) {
        int room = DC_RESP_MAX - 1 - s_resp_len;
        int n = evt->data_len < room ? evt->data_len : room;
        if (n > 0) {
            memcpy(s_resp + s_resp_len, evt->data, n);
            s_resp_len += n;
            s_resp[s_resp_len] = '\0';
        }
    }
    return ESP_OK;
}

// One POST. Returns the HTTP status, or -1 on a transport error.
static int post_once(const char *body, size_t len)
{
    esp_http_client_config_t cfg = {
        .url               = s_url,
        .method            = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms        = DC_HTTP_TIMEOUT_MS,
        .event_handler     = http_event,
        .buffer_size_tx    = 1024,      // request line carries the 120-odd byte webhook path
        .disable_auto_redirect = true,  // the body goes to discord.com and nowhere else
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return -1;
    esp_http_client_set_header(c, "Content-Type", "application/json");
    esp_http_client_set_post_field(c, body, (int)len);
    s_resp[0] = '\0';
    s_resp_len = 0;
    s_hdr_retry_ms = 0;
    s_rl_remaining = -1;
    s_rl_reset_ms = 0;
    int status = esp_http_client_perform(c) == ESP_OK ? esp_http_client_get_status_code(c) : -1;
    esp_http_client_cleanup(c);
    return status;
}

static int clamp_wait(int ms)
{
    if (ms < 250) ms = 250;
    return ms > DC_MAX_WAIT_MS ? DC_MAX_WAIT_MS : ms;
}

// 429 wait: the body's retry_after (seconds, may be fractional), else the
// Retry-After header, else 2 s.
static int retry_after_ms(void)
{
    const char *p = strstr(s_resp, "\"retry_after\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            double v = strtod(p + 1, NULL);
            if (v > 0 && v < 3600) return clamp_wait((int)(v * 1000.0));
        }
    }
    return clamp_wait(s_hdr_retry_ms ? s_hdr_retry_ms : 2000);
}

static void pace(void)
{
    TickType_t now = xTaskGetTickCount();
    if ((int32_t)(s_next_ok - now) > 0) vTaskDelay(s_next_ok - now);
}

// Post s_body with retries. Returns the final HTTP status, -1 transport
// error, 0 no webhook configured. Logs only the outcome, never the URL.
static int dc_send(const jb_t *j)
{
    if (j->full) {
        ESP_LOGW(TAG, "Discord: message too large, dropped");
        return -1;
    }
    if (!settings_discord_enabled()) return 0;
    settings_copy(s_set);
    strlcpy(s_url, s_set->discord_webhook, sizeof(s_set->discord_webhook));
    memset(s_set, 0, sizeof(*s_set));
    if (!s_url[0]) return 0;

    int status = -1, r429 = 0;
    for (int attempt = 1; attempt <= DC_RETRIES; ) {
        for (int w = 0; !wifi_manager_is_connected() && w < DC_WIFI_WAIT_MS; w += 500)
            vTaskDelay(pdMS_TO_TICKS(500));
        pace();
        status = post_once(j->b, j->len);
        int gap = DC_MIN_GAP_MS;
        if (s_rl_remaining == 0 && s_rl_reset_ms > gap) gap = clamp_wait(s_rl_reset_ms);
        s_next_ok = xTaskGetTickCount() + pdMS_TO_TICKS(gap);

        if (status >= 200 && status < 300) break;
        if (status == 429 && r429 < DC_429_RETRIES) {
            r429++;
            vTaskDelay(pdMS_TO_TICKS(retry_after_ms()));
            continue;
        }
        if (status >= 400 && status < 500) break;     // bad webhook or body: a retry won't help
        if (++attempt <= DC_RETRIES) vTaskDelay(pdMS_TO_TICKS(DC_RETRY_DELAY_MS));
    }
    memset(s_url, 0, sizeof(s_set->discord_webhook));

    bool ok = status >= 200 && status < 300;
    if (ok) ESP_LOGI(TAG, "Discord: posted");
    else    ESP_LOGW(TAG, "Discord: failed status %d", status);
    portENTER_CRITICAL(&s_mux);
    s_stat.last_status = status;
    if (ok) s_stat.posted++; else s_stat.failed++;
    portEXIT_CRITICAL(&s_mux);

    if (!s_stack_logged) {
        s_stack_logged = true;
        ESP_LOGI(TAG, "Stack high-water %u B of %u after the first post",
                 (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)DISCORD_TASK_STACK);
    }
    return status;
}

// ── Incident embeds ───────────────────────────────────────────────────────────

static const dc_recent_t *find_recent(uint32_t ip, uint8_t type, uint32_t ts)
{
    const dc_recent_t *best = NULL;
    for (int k = 1; k <= DC_RECENT; k++) {               // newest first
        const dc_recent_t *r = &s_recent[(s_recent_next - k + DC_RECENT) % DC_RECENT];
        if (r->ip != ip || r->type != type || !r->ts) continue;
        if (r->ts == ts) return r;
        if (!best) best = r;
    }
    return best;
}

static uint32_t open_for_s(const alarm_info_t *a, int64_t seen_mono)
{
    if (clock_ok() && a->first_ts >= 1600000000) {
        time_t now = time(NULL);
        return now > (time_t)a->first_ts ? (uint32_t)(now - a->first_ts) : 0;
    }
    int64_t d = mono_s() - seen_mono;
    return d > 0 ? (uint32_t)d : 0;
}

static void post_opened(const alarm_info_t *a)
{
    const dc_recent_t *r = find_recent(a->src_ip, a->type, a->first_ts);
    char title[48], ip[16], mac[WIFI_MAC_STR_LEN], macv[96], user[40], pay[136];
    snprintf(title, sizeof(title), "Incident #%lu opened", (unsigned long)a->id);
    ip_str(a->src_ip, ip);
    wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
    const char *vendor = wifi_manager_mac_vendor(a->src_mac);
    snprintf(macv, sizeof(macv), "%s%s%.60s%s", mac, vendor[0] ? " (" : "", vendor, vendor[0] ? ")" : "");
    user[0] = pay[0] = '\0';
    if (r) {
        clean(user, sizeof(user), r->user, sizeof(r->user));
        clean(pay, sizeof(pay), r->payload, sizeof(r->payload));
    }
    char dev[64];
    device_str(dev, sizeof(dev));

    jb_t j;
    bool first = true;
    embed_begin(&j, title, COLOR_RED, NULL);
    field(&j, &first, "Source IP", ip, true, false);
    field(&j, &first, "MAC", macv, true, false);
    field(&j, &first, "Attack", type_long(a->type), true, false);
    if (user[0]) field(&j, &first, "Username", user, true, true);
    if (pay[0])  field(&j, &first, "Payload", pay, false, true);
    field(&j, &first, "Device", dev, false, false);
    embed_end(&j, a->first_ts);
    dc_send(&j);
}

static void post_acked(const alarm_info_t *a, uint8_t src)
{
    char title[48], ip[16], cnt[16], dur[32];
    snprintf(title, sizeof(title), "Incident #%lu acknowledged", (unsigned long)a->id);
    ip_str(a->src_ip, ip);
    snprintf(cnt, sizeof(cnt), "%lu", (unsigned long)a->count);
    fmt_dur(open_for_s(a, s_inc_seen), dur, sizeof(dur));
    jb_t j;
    bool first = true;
    embed_begin(&j, title, COLOR_AMBER,
                src == ACK_DASHBOARD ? "Acknowledged from the dashboard." : "Acknowledged on the front panel.");
    field(&j, &first, "Source IP", ip, true, false);
    field(&j, &first, "Events so far", cnt, true, false);
    field(&j, &first, "Open for", dur, true, false);
    embed_end(&j, 0);
    dc_send(&j);
}

static void post_closed(const alarm_info_t *a, const char *why)
{
    char title[48], ip[16], cnt[16], dur[32];
    snprintf(title, sizeof(title), "Incident #%lu closed", (unsigned long)a->id);
    ip_str(a->src_ip, ip);
    snprintf(cnt, sizeof(cnt), "%lu", (unsigned long)a->count);
    fmt_dur(a->last_ts > a->first_ts ? a->last_ts - a->first_ts : 0, dur, sizeof(dur));
    jb_t j;
    bool first = true;
    embed_begin(&j, title, COLOR_GREEN, why);
    field(&j, &first, "Source IP", ip, true, false);
    field(&j, &first, "Events", cnt, true, false);
    field(&j, &first, "Duration (first to last event)", dur, true, false);
    embed_end(&j, 0);
    dc_send(&j);
}

static void post_reminder(const alarm_info_t *a)
{
    char title[56], ip[16], cnt[16], dur[32];
    snprintf(title, sizeof(title), "Incident #%lu still unacknowledged", (unsigned long)a->id);
    ip_str(a->src_ip, ip);
    snprintf(cnt, sizeof(cnt), "%lu", (unsigned long)a->count);
    fmt_dur(open_for_s(a, s_inc_seen), dur, sizeof(dur));
    jb_t j;
    bool first = true;
    embed_begin(&j, title, COLOR_ORANGE, NULL);
    field(&j, &first, "Source IP", ip, true, false);
    field(&j, &first, "Attack", type_long(a->type), true, false);
    field(&j, &first, "Events", cnt, true, false);
    field(&j, &first, "Open for", dur, true, false);
    embed_end(&j, 0);
    dc_send(&j);
}

static void post_test(void)
{
    char dev[64];
    device_str(dev, sizeof(dev));
    jb_t j;
    bool first = true;
    embed_begin(&j, "ShadowSentry test", COLOR_BLURPLE,
                "The webhook works. Incident alerts and the event log post here.");
    field(&j, &first, "Device", dev, false, false);
    field(&j, &first, "Event log", settings_get()->discord_log_events ? "on" : "off", true, false);
    embed_end(&j, 0);
    int st = dc_send(&j);
    portENTER_CRITICAL(&s_mux);
    s_stat.test_status = st;
    s_stat.test_ok = st >= 200 && st < 300;
    portEXIT_CRITICAL(&s_mux);
}

// A notify.c message (boot): green, amber or red by severity.
static void post_notice(const notify_msg_t *m)
{
    static const uint32_t COLOR[] = { COLOR_GREEN, COLOR_AMBER, COLOR_RED };
    jb_t j;
    embed_begin(&j, m->title, COLOR[m->severity <= NOTIFY_ALERT ? m->severity : NOTIFY_ALERT], m->text);
    embed_end(&j, 0);
    dc_send(&j);
}

static int remind_s(void)
{
    uint32_t r = settings_get()->alarm_remind_s;
    return r < DC_REMIND_MIN_S ? DC_REMIND_MIN_S : (int)r;
}

static void track_open(const alarm_info_t *a, int64_t now)
{
    s_inc_active  = true;
    s_inc         = *a;
    s_inc_seen    = now;
    s_next_remind = now + remind_s();
}

static void handle_alarm(const dc_alarm_msg_t *m, int64_t now)
{
    const alarm_info_t *a = &m->cur, *p = &m->prev;
    bool on = settings_discord_enabled();

    if (a->state == ALARM_ACTIVE && (p->state != ALARM_ACTIVE || p->id != a->id)) {
        // An acked incident is closed implicitly when another source opens a new one.
        if (on && p->state == ALARM_ACKED && p->id && p->id != a->id) {
            char why[64];
            snprintf(why, sizeof(why), "Closed: incident #%lu opened from another source.", (unsigned long)a->id);
            post_closed(p, why);
        }
        track_open(a, now);
        if (on) post_opened(a);
    } else if (a->state == ALARM_ACKED && p->state == ALARM_ACTIVE) {
        s_inc_active = false;
        if (on) post_acked(a, m->ack_src);
    } else if (a->state == ALARM_IDLE && p->state != ALARM_IDLE) {
        s_inc_active = false;
        if (on && m->rearmed) {
            post_closed(a, "Closed: re-armed.");
        } else if (on) {
            char q[24], why[64];
            fmt_dur(settings_get()->alarm_quiet_s, q, sizeof(q));
            snprintf(why, sizeof(why), "Closed after %s without events.", q);
            post_closed(a, why);
        }
    }
}

static void check_reminder(int64_t now)
{
    if (!s_inc_active || now < s_next_remind) return;
    alarm_info_t a;
    alarm_get(&a);
    if (a.state != ALARM_ACTIVE || a.id != s_inc.id) {
        s_inc_active = false;        // the transition is on its way
        return;
    }
    s_next_remind = now + remind_s();
    if (settings_discord_enabled()) post_reminder(&a);
}

// ── Deduplicated event log ────────────────────────────────────────────────────

static void app(char *out, size_t cap, size_t *o, const char *s)
{
    while (*s && *o + 1 < cap) out[(*o)++] = *s++;
    out[*o] = '\0';
}

// The dedup summary: shell -> "ran <first token>", credential traps ->
// "login user:pass", HTTP -> "<method> <path>", anything else -> the first 40
// characters of the payload. All attacker text goes through clean().
static void summarise(const attack_log_t *e, char *out, size_t cap)
{
    const char *p = e->payload;
    const size_t plen = strnlen(p, sizeof(e->payload));
    char a[48], b[32];
    size_t o = 0;
    out[0] = '\0';
    switch (e->type) {
    case ATTACK_SHELL:
        if (plen >= 2 && p[0] == '$' && p[1] == ' ') {
            size_t i = 2, n = 0;
            while (i < plen && (p[i] == ' ' || p[i] == '\t')) i++;
            while (i + n < plen && p[i + n] != ' ' && p[i + n] != '\t' && p[i + n] != ';' &&
                   p[i + n] != '|' && p[i + n] != '&' && n < 32) n++;
            clean(a, sizeof(a), p + i, n);
            app(out, cap, &o, "ran ");
            app(out, cap, &o, a[0] ? a : "?");
            return;
        }
        if (plen == sizeof("shell session opened") - 1 && !memcmp(p, "shell session opened", plen)) {
            clean(a, sizeof(a), e->username, sizeof(e->username));
            app(out, cap, &o, "shell opened as ");
            app(out, cap, &o, a[0] ? a : "?");
            return;
        }
        break;
    case ATTACK_TELNET: case ATTACK_SSH: case ATTACK_FTP: case ATTACK_RTSP:
        if (e->username[0] || e->password[0]) {
            clean(a, 25, e->username, sizeof(e->username));
            clean(b, 25, e->password, sizeof(e->password));
            app(out, cap, &o, "login ");
            app(out, cap, &o, a);
            app(out, cap, &o, ":");
            app(out, cap, &o, b);
            return;
        }
        break;
    case ATTACK_HTTP: {
        size_t n = 0;
        for (int sp = 0; n < plen && n < sizeof(a) - 1; n++)
            if (p[n] == ' ' && ++sp == 2) break;
        clean(a, sizeof(a), p, n);
        app(out, cap, &o, a);
        return;
    }
    default:
        break;
    }
    clean(a, 41, p, plen);
    app(out, cap, &o, a[0] ? a : "(no detail)");
}

static void handle_event(const attack_log_t *e, int64_t now)
{
    dc_recent_t *r = &s_recent[s_recent_next];
    s_recent_next = (s_recent_next + 1) % DC_RECENT;
    r->ip = e->src_ip;
    r->ts = e->timestamp ? e->timestamp : 1;
    r->type = (uint8_t)e->type;
    strlcpy(r->user, e->username, sizeof(r->user));
    strlcpy(r->payload, e->payload, sizeof(r->payload));

    if (!s_log_was_on) return;

    char sum[DC_SUMMARY_LEN];
    summarise(e, sum, sizeof(sum));
    bool ign = ignore_match(e->src_ip, e->src_mac);      // as the SD line: at log time
    dc_key_t *free_k = NULL, *idle_k = NULL, *old_k = NULL;
    for (int i = 0; i < DC_KEYS; i++) {
        dc_key_t *k = &s_keys[i];
        if (!k->used) { if (!free_k) free_k = k; continue; }
        if (k->ip == e->src_ip && k->type == (uint8_t)e->type && !strcmp(k->summary, sum)) {
            k->pending++;
            k->last_seen = now;
            k->ignored = ign;
            return;
        }
        if (!k->pending && (!idle_k || k->last_seen < idle_k->last_seen)) idle_k = k;
        if (!old_k || k->last_seen < old_k->last_seen) old_k = k;
    }
    dc_key_t *k = free_k ? free_k : idle_k ? idle_k : old_k;
    if (k->used && k->pending) s_lost += k->pending;     // table full of live keys
    memset(k, 0, sizeof(*k));
    k->used = true;
    k->ip = e->src_ip;
    k->type = (uint8_t)e->type;
    k->pending = 1;
    k->last_seen = now;
    k->ignored = ign;
    strlcpy(k->summary, sum, sizeof(k->summary));
}

static bool eligible(const dc_key_t *k, int64_t now)
{
    return k->used && k->pending && (!k->posted || now - k->last_post >= DISCORD_KEY_WINDOW_S);
}

static size_t display_len(const char *s, size_t n)
{
    size_t d = n;
    for (size_t i = 0; i < n; i++) if (s[i] == '@') d++;     // each '@' gains a zero-width space
    return d;
}

static void flush_batch(int64_t now)
{
    s_last_batch = now;
    discord_status_t st;
    discord_get_status(&st);
    uint32_t dropped = st.dropped - s_dropped_reported;
    uint32_t lost    = s_lost - s_lost_reported;

    size_t clen = 0, disp;
    int lines = 0, more = 0;
    app(s_content, DC_CONTENT_CAP, &clen, "```\n");
    disp = clen;
    for (int i = 0; i < DC_KEYS; i++) {
        dc_key_t *k = &s_keys[i];
        if (!eligible(k, now)) continue;
        if (lines >= DC_BATCH_KEYS) { more++; continue; }
        char ip[16], cnt[24], line[160];
        ip_str(k->ip, ip);
        cnt[0] = '\0';
        if (k->posted)          snprintf(cnt, sizeof(cnt), " +%lu more", (unsigned long)k->pending);
        else if (k->pending > 1) snprintf(cnt, sizeof(cnt), " x%lu", (unsigned long)k->pending);
        int n = snprintf(line, sizeof(line), "%-15s %-6s %s%s%s\n", ip, type_short(k->type), k->summary, cnt,
                         k->ignored ? " (ignored)" : "");
        if (n <= 0) continue;
        if ((size_t)n >= sizeof(line)) { n = sizeof(line) - 1; line[n - 1] = '\n'; }
        size_t d = display_len(line, (size_t)n);
        if (disp + d + DC_TAIL_RESERVE > DC_CONTENT_MAX) { more++; continue; }
        app(s_content, DC_CONTENT_CAP, &clen, line);
        disp += d;
        lines++;
        k->sel = true;
    }
    if (!lines && !dropped && !lost) return;
    char tail[80];
    if (more) {
        snprintf(tail, sizeof(tail), "+%d more in the next batch\n", more);
        app(s_content, DC_CONTENT_CAP, &clen, tail);
    }
    if (dropped || lost) {
        snprintf(tail, sizeof(tail), "%lu events not counted (busy)\n", (unsigned long)(dropped + lost));
        app(s_content, DC_CONTENT_CAP, &clen, tail);
    }
    app(s_content, DC_CONTENT_CAP, &clen, "```");
    s_dropped_reported = st.dropped;
    s_lost_reported = s_lost;

    jb_t j;
    jb_init(&j);
    jb_lit(&j, JB_HEAD "\"content\":");
    jb_str(&j, s_content);
    jb_lit(&j, "}");
    dc_send(&j);      // a failed batch is not retried later: its counts are gone

    for (int i = 0; i < DC_KEYS; i++) {
        dc_key_t *k = &s_keys[i];
        if (!k->sel) continue;
        k->sel = false;
        k->pending = 0;
        k->posted = true;
        k->last_post = now;
    }
}

static void check_batch(int64_t now)
{
    bool log_on = settings_get()->discord_log_events && settings_discord_enabled();
    if (log_on != s_log_was_on) {
        memset(s_keys, 0, DC_KEYS * sizeof(*s_keys));
        s_log_was_on = log_on;
        s_last_batch = now;
    }
    if (!log_on) return;

    size_t chars = 0;
    int n = 0;
    for (int i = 0; i < DC_KEYS; i++) {
        dc_key_t *k = &s_keys[i];
        if (!k->used) continue;
        if (!k->pending && now - k->last_seen >= DISCORD_KEY_IDLE_S) { k->used = false; continue; }
        if (eligible(k, now)) { n++; chars += strlen(k->summary) + 40; }
    }
    if (!n) return;
    bool due   = now - s_last_batch >= DISCORD_BATCH_S;
    bool early = chars >= DC_CONTENT_MAX - DC_TAIL_RESERVE && now - s_last_batch >= DC_BATCH_MIN_S;
    if (due || early) flush_batch(now);
}

// ── Task ──────────────────────────────────────────────────────────────────────

void discord_task(void *arg)
{
    (void)arg;
    s_body    = heap_caps_malloc(DC_BODY_MAX, MALLOC_CAP_SPIRAM);
    s_content = heap_caps_malloc(DC_CONTENT_CAP, MALLOC_CAP_SPIRAM);
    s_resp    = heap_caps_malloc(DC_RESP_MAX, MALLOC_CAP_SPIRAM);
    s_set     = heap_caps_malloc(sizeof(settings_t), MALLOC_CAP_SPIRAM);
    s_url     = heap_caps_malloc(sizeof(s_set->discord_webhook), MALLOC_CAP_SPIRAM);
    s_keys    = heap_caps_calloc(DC_KEYS, sizeof(*s_keys), MALLOC_CAP_SPIRAM);
    s_recent  = heap_caps_calloc(DC_RECENT, sizeof(*s_recent), MALLOC_CAP_SPIRAM);
    if (!s_evq || !s_alq || !s_body || !s_content || !s_resp || !s_set || !s_url || !s_keys || !s_recent) {
        ESP_LOGE(TAG, "No memory, Discord alerts off");
        vTaskDelete(NULL);
        return;
    }
    s_running = true;
    int64_t now = mono_s();
    s_last_batch = now;
    if (s_carry.state == ALARM_ACTIVE) {
        track_open(&s_carry, now);
        s_next_remind = now;         // say at once that it is still open
    }
    ESP_LOGI(TAG, "Ready (webhook %s, event log %s)",
             settings_discord_enabled() ? "set" : "not set",
             settings_get()->discord_log_events ? "on" : "off");

    for (;;) {
        bool got = xQueueReceive(s_evq, &s_ev, pdMS_TO_TICKS(500)) == pdTRUE;
        now = mono_s();
        check_batch(now);            // applies a log on/off change before counting
        for (int n = 0; got && n < DC_DRAIN_MAX; n++) {
            handle_event(&s_ev, now);
            got = xQueueReceive(s_evq, &s_ev, 0) == pdTRUE;
        }
        if (got) handle_event(&s_ev, now);

        // After the events, so the opening event is in s_recent when its
        // incident's embed is built (the trap appends before the alarm sees it).
        dc_alarm_msg_t m;
        while (xQueueReceive(s_alq, &m, 0) == pdTRUE) handle_alarm(&m, now);

        static notify_msg_t nm;      // task only; off the stack
        while (s_ntq && xQueueReceive(s_ntq, &nm, 0) == pdTRUE) post_notice(&nm);

        discord_status_t st;
        discord_get_status(&st);
        if (st.test_req != st.test_done) {
            post_test();
            portENTER_CRITICAL(&s_mux);
            s_stat.test_done = st.test_req;
            portEXIT_CRITICAL(&s_mux);
        }

        now = mono_s();
        check_reminder(now);
        check_batch(now);
    }
}
