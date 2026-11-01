// WhatsApp alerts via CallMeBot: a notification-layer backend for the boot
// message and incident transitions. See whatsapp.h. Fork addition, Robert Mech.
//
// Threading: notify_send() hands a copy to the queue from the caller's task
// (the alarm task, or app_main at boot). whatsapp_task owns the one HTTPS
// sender, the pacing and the hourly cap. Big buffers are PSRAM.

#include "whatsapp.h"
#include "esp_attr.h"
#include "notify.h"
#include "settings.h"
#include "wifi_manager.h"
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
#include <stdio.h>
#include <string.h>

static const char *TAG = "WHATSAPP";

#define WA_API_URL          "https://api.callmebot.com/whatsapp.php"
#define WA_URL_MAX          1536        // fits the longest message fully %-encoded (~1350)
#define WA_TEXT_MAX         (NOTIFY_TITLE_MAX + NOTIFY_TEXT_MAX + 16)
#define WA_HTTP_TIMEOUT_MS  15000
#define WA_RETRIES          2           // transport errors and 5xx
#define WA_RETRY_DELAY_MS   10000
#define WA_WIFI_WAIT_MS     15000
#define WA_WINDOW_S         3600        // hourly cap window

static QueueHandle_t      s_q;
static portMUX_TYPE       s_mux = portMUX_INITIALIZER_UNLOCKED;
static whatsapp_status_t  s_stat;               // guarded by s_mux
static bool               s_running;

// Task-only state.
static char              *s_url, *s_text;
static settings_t        *s_set;
EXT_RAM_BSS_ATTR static notify_msg_t s_msg;    // PSRAM, as the task's stack
static TickType_t         s_next_ok;            // pacing: no send before this tick
static int64_t            s_window_start;       // monotonic s
static int                s_window_count;
static bool               s_cap_logged, s_stack_logged;

static int64_t mono_s(void) { return esp_timer_get_time() / 1000000LL; }

static void count_drop(void)
{
    portENTER_CRITICAL(&s_mux);
    s_stat.dropped++;
    portEXIT_CRITICAL(&s_mux);
}

// ── Notification-layer backend ────────────────────────────────────────────────

static bool backend_send(const notify_msg_t *m)
{
    if (s_q && xQueueSend(s_q, m, 0) == pdTRUE) return true;
    count_drop();
    return false;
}

// Only while the task runs: main.c starts it only if WhatsApp was configured
// at boot, so enabling it in Settings takes effect after a reboot.
static bool backend_enabled(void)
{
    return s_running && settings_whatsapp_enabled();
}

static const notify_backend_t s_backend = {
    .name    = "WhatsApp",
    .kinds   = NOTIFY_BIT(NOTIFY_BOOT) | NOTIFY_ALL_INCIDENTS,
    .enabled = backend_enabled,
    .send    = backend_send,
};

void whatsapp_init(void)
{
    s_q = xQueueCreateWithCaps(WHATSAPP_QUEUE_DEPTH, sizeof(notify_msg_t), MALLOC_CAP_SPIRAM);
    if (!s_q) {
        ESP_LOGE(TAG, "No memory for the queue, WhatsApp alerts off");
        return;
    }
    notify_register(&s_backend);
}

uint32_t whatsapp_request_test(void)
{
    if (!s_running) return 0;
    portENTER_CRITICAL(&s_mux);
    uint32_t n = ++s_stat.test_req;
    portEXIT_CRITICAL(&s_mux);
    return n;
}

void whatsapp_get_status(whatsapp_status_t *out)
{
    portENTER_CRITICAL(&s_mux);
    *out = s_stat;
    portEXIT_CRITICAL(&s_mux);
}

// ── URL building ──────────────────────────────────────────────────────────────

// Append src percent-encoded (RFC 3986: only unreserved characters stay as
// they are, so '+', '&', '=', '#', space and newline are all encoded).
// Returns false if it would not fit; dst stays NUL-terminated either way.
static bool url_append_enc(char *dst, size_t cap, size_t *len, const char *src)
{
    static const char HEX[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        unsigned char c = *p;
        bool keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (*len + (keep ? 1 : 3) >= cap) { dst[*len] = '\0'; return false; }
        if (keep) {
            dst[(*len)++] = (char)c;
        } else {
            dst[(*len)++] = '%';
            dst[(*len)++] = HEX[c >> 4];
            dst[(*len)++] = HEX[c & 0x0F];
        }
    }
    dst[*len] = '\0';
    return true;
}

static bool url_append(char *dst, size_t cap, size_t *len, const char *s)
{
    size_t n = strlen(s);
    if (*len + n >= cap) { dst[*len] = '\0'; return false; }
    memcpy(dst + *len, s, n + 1);
    *len += n;
    return true;
}

// Build s_url for text. The phone and apikey come from a settings copy that
// is wiped straight after. Returns false when not configured or too long.
static bool build_url(const char *text)
{
    settings_copy(s_set);
    bool ok = s_set->whatsapp_phone[0] && s_set->whatsapp_apikey[0];
    size_t len = 0;
    s_url[0] = '\0';
    ok = ok && url_append(s_url, WA_URL_MAX, &len, WA_API_URL "?phone=")
            && url_append_enc(s_url, WA_URL_MAX, &len, s_set->whatsapp_phone)
            && url_append(s_url, WA_URL_MAX, &len, "&text=")
            && url_append_enc(s_url, WA_URL_MAX, &len, text)
            && url_append(s_url, WA_URL_MAX, &len, "&apikey=")
            && url_append_enc(s_url, WA_URL_MAX, &len, s_set->whatsapp_apikey);
    memset(s_set, 0, sizeof(*s_set));
    if (!ok) memset(s_url, 0, WA_URL_MAX);
    return ok;
}

// ── HTTPS sender ──────────────────────────────────────────────────────────────

// One GET. Returns the HTTP status, or -1 on a transport error. The body is
// not read: CallMeBot documents no response format.
static int get_once(void)
{
    esp_http_client_config_t cfg = {
        .url                   = s_url,
        .method                = HTTP_METHOD_GET,
        .crt_bundle_attach     = esp_crt_bundle_attach,
        .timeout_ms            = WA_HTTP_TIMEOUT_MS,
        .buffer_size_tx        = WA_URL_MAX + 256,  // the request line carries the whole URL
        .disable_auto_redirect = true,              // the apikey goes to callmebot.com only
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return -1;
    int status = esp_http_client_perform(c) == ESP_OK ? esp_http_client_get_status_code(c) : -1;
    esp_http_client_cleanup(c);
    return status;
}

static void pace(void)
{
    TickType_t now = xTaskGetTickCount();
    if ((int32_t)(s_next_ok - now) > 0) vTaskDelay(s_next_ok - now);
}

// The hourly cap. Tests count too, but are never refused.
static bool cap_take(bool test)
{
    int64_t now = mono_s();
    if (!s_window_start || now - s_window_start >= WA_WINDOW_S) {
        s_window_start = now;
        s_window_count = 0;
        s_cap_logged = false;
    }
    if (!test && s_window_count >= WHATSAPP_HOURLY_MAX) {
        if (!s_cap_logged) {
            s_cap_logged = true;
            ESP_LOGW(TAG, "WhatsApp: %d messages this hour, dropping until the hour is up",
                     WHATSAPP_HOURLY_MAX);
        }
        return false;
    }
    s_window_count++;
    return true;
}

// Send text with retries. Returns the final HTTP status, -1 transport error,
// 0 not configured. Logs only the outcome, never the URL.
static int wa_send(const char *text, bool test)
{
    if (!settings_whatsapp_enabled()) return 0;
    if (!cap_take(test)) { count_drop(); return -1; }

    int status = -1;
    for (int attempt = 1; attempt <= WA_RETRIES; attempt++) {
        for (int w = 0; !wifi_manager_is_connected() && w < WA_WIFI_WAIT_MS; w += 500)
            vTaskDelay(pdMS_TO_TICKS(500));
        pace();
        if (!build_url(text)) {
            ESP_LOGW(TAG, "WhatsApp: not configured or message too long, dropped");
            status = 0;
            break;
        }
        status = get_once();
        memset(s_url, 0, WA_URL_MAX);
        s_next_ok = xTaskGetTickCount() + pdMS_TO_TICKS(WHATSAPP_MIN_GAP_MS);
        if (status >= 200 && status < 300) break;
        if (status >= 400 && status < 500) break;     // bad phone or apikey: a retry won't help
        if (attempt < WA_RETRIES) vTaskDelay(pdMS_TO_TICKS(WA_RETRY_DELAY_MS));
    }

    bool ok = status >= 200 && status < 300;
    if (ok) ESP_LOGI(TAG, "WhatsApp: sent");
    else    ESP_LOGW(TAG, "WhatsApp: failed status %d", status);
    portENTER_CRITICAL(&s_mux);
    s_stat.last_status = status;
    if (ok) s_stat.sent++; else s_stat.failed++;
    portEXIT_CRITICAL(&s_mux);

    if (!s_stack_logged) {
        s_stack_logged = true;
        ESP_LOGI(TAG, "Stack high-water %u B of %u after the first send",
                 (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)WHATSAPP_TASK_STACK);
    }
    return status;
}

// Plain text: "ShadowSentry: <title>" on the first line (the boot title
// already names the device), then the body.
static void send_msg(const notify_msg_t *m)
{
    snprintf(s_text, WA_TEXT_MAX, "%s%s\n%s",
             m->kind == NOTIFY_BOOT ? "" : "ShadowSentry: ", m->title, m->text);
    wa_send(s_text, false);
}

static void send_test(void)
{
    char dev[WIFI_IP_STR_LEN];
    wifi_manager_get_ip_str(dev, sizeof(dev));
    snprintf(s_text, WA_TEXT_MAX,
             "ShadowSentry test\nWhatsApp works. Boot and incident alerts come here.\nDevice: %s",
             dev[0] ? dev : "no IP");
    int st = wa_send(s_text, true);
    portENTER_CRITICAL(&s_mux);
    s_stat.test_status = st;
    s_stat.test_ok = st >= 200 && st < 300;
    portEXIT_CRITICAL(&s_mux);
}

// ── Task ──────────────────────────────────────────────────────────────────────

void whatsapp_task(void *arg)
{
    (void)arg;
    s_url  = heap_caps_malloc(WA_URL_MAX, MALLOC_CAP_SPIRAM);
    s_text = heap_caps_malloc(WA_TEXT_MAX, MALLOC_CAP_SPIRAM);
    s_set  = heap_caps_malloc(sizeof(settings_t), MALLOC_CAP_SPIRAM);
    if (!s_q || !s_url || !s_text || !s_set) {
        ESP_LOGE(TAG, "No memory, WhatsApp alerts off");
        vTaskDelete(NULL);
        return;
    }
    s_running = true;
    ESP_LOGI(TAG, "Ready (%s, at most %d messages an hour, %d s apart)",
             settings_whatsapp_enabled() ? "configured" : "not configured",
             WHATSAPP_HOURLY_MAX, WHATSAPP_MIN_GAP_MS / 1000);

    for (;;) {
        if (xQueueReceive(s_q, &s_msg, pdMS_TO_TICKS(500)) == pdTRUE) send_msg(&s_msg);

        whatsapp_status_t st;
        whatsapp_get_status(&st);
        if (st.test_req != st.test_done) {
            send_test();
            portENTER_CRITICAL(&s_mux);
            s_stat.test_done = st.test_req;
            portEXIT_CRITICAL(&s_mux);
        }
    }
}
