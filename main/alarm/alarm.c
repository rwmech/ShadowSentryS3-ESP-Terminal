#include "settings.h"   // alarm_remind_s / alarm_quiet_s, read live
#include "alarm.h"
#include "buzzer.h"
#include "log_store.h"
#include "ignore.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "ALARM";

#define ALARM_QUEUE_DEPTH    32
#define ALARM_TASK_STACK     4096
#define ALARM_TASK_PRIO      4
#define ALARM_MAX_LISTENERS  6     // UI, WebSocket, SD log, Discord, plus 2 spare
#define NVS_NS               "alarm"
#define NVS_KEY              "incident"

typedef enum { MSG_EVENT, MSG_ACK, MSG_CLEAR } msg_kind_t;

typedef struct {
    msg_kind_t kind;
    uint8_t    by;          // alarm_by_t, for ACK and CLEAR
    uint32_t   ip;
    uint8_t    mac[6];
    uint8_t    type;
    uint32_t   ts;
} alarm_msg_t;

static QueueHandle_t     s_queue;
static SemaphoreHandle_t s_mutex;
static alarm_info_t      s_info;            // guarded by s_mutex
static int64_t           s_last_event_s;    // monotonic, alarm task only
static int64_t           s_last_remind_s;   // monotonic, alarm task only
static bool              s_rearmed;         // alarm task only: the last close was a re-arm

static void (*s_listeners[ALARM_MAX_LISTENERS])(const alarm_info_t *info);
static int s_listener_count = 0;

static int64_t mono_s(void) { return esp_timer_get_time() / 1000000LL; }

void alarm_add_listener(void (*cb)(const alarm_info_t *info))
{
    if (!cb) return;
    if (s_listener_count >= ALARM_MAX_LISTENERS) {
        ESP_LOGE(TAG, "Alarm listener table full (%d), listener dropped", ALARM_MAX_LISTENERS);
        return;
    }
    s_listeners[s_listener_count++] = cb;
}

bool alarm_closed_by_rearm(void)
{
    return s_rearmed;
}

static alarm_cond_t cond_of(alarm_state_t st)
{
    return st == ALARM_ACTIVE ? ALARM_COND_RED : st == ALARM_ACKED ? ALARM_COND_YELLOW : ALARM_COND_GREEN;
}

void alarm_get(alarm_info_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_info;
    xSemaphoreGive(s_mutex);
    out->cond = cond_of(out->state);
}

const char *alarm_cond_key(alarm_cond_t c)
{
    return c == ALARM_COND_RED ? "red" : c == ALARM_COND_YELLOW ? "yellow" : "green";
}

const char *alarm_by_key(uint8_t by)
{
    return by == ALARM_BY_PANEL ? "panel" : by == ALARM_BY_DASHBOARD ? "dashboard" : "";
}

void alarm_ack(alarm_by_t by)
{
    if (!s_queue) return;
    alarm_msg_t m = { .kind = MSG_ACK, .by = (uint8_t)by };
    xQueueSend(s_queue, &m, 0);
}

void alarm_resolve(alarm_by_t by)
{
    if (!s_queue) return;
    alarm_msg_t m = { .kind = MSG_CLEAR, .by = (uint8_t)by };
    xQueueSend(s_queue, &m, 0);
}

void alarm_clear(void)
{
    alarm_resolve(ALARM_BY_PANEL);
}

esp_err_t alarm_ignore_error(alarm_by_t by)
{
    (void)by;
    return ESP_ERR_NOT_SUPPORTED;       // TODO(alert-core): step 0 stub
}

esp_err_t alarm_ignore_device(alarm_by_t by)
{
    (void)by;
    return ESP_ERR_NOT_SUPPORTED;       // TODO(alert-core): step 0 stub
}

bool alarm_should_alert(const attack_log_t *e)
{
    if (!e) return false;
    if ((unsigned)e->type < 32 && !(settings_get()->alert_mask & (1u << e->type))) return false;
    return !ignore_match(e->src_ip, e->src_mac, describe_code(e));
}

// log_store listener: runs on the appending honeypot task (as small as 3 KB of
// stack), so it only copies five fields into the queue. Types switched off and
// ignored sources never reach the queue: logged, no incident.
static void on_event(const attack_log_t *e)
{
    if (!alarm_should_alert(e)) return;
    alarm_msg_t m = { .kind = MSG_EVENT, .ip = e->src_ip,
                      .type = (uint8_t)e->type, .ts = e->timestamp };
    memcpy(m.mac, e->src_mac, sizeof(m.mac));
    xQueueSend(s_queue, &m, 0);   // full queue = burst already raising the alarm
}

void alarm_note_event(const attack_log_t *e)
{
    if (s_queue && e) on_event(e);
}

// ── Persistence ───────────────────────────────────────────────────────────────

static void persist(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, NVS_KEY, &s_info, sizeof(s_info));
    nvs_commit(h);
    nvs_close(h);
}

static void restore(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    alarm_info_t saved;
    size_t len = sizeof(saved);
    if (nvs_get_blob(h, NVS_KEY, &saved, &len) == ESP_OK && len == sizeof(saved)) {
        s_info = saved;
        // An acknowledged incident's quiet timer can't survive a reboot; close it.
        if (s_info.state == ALARM_ACKED) s_info.state = ALARM_IDLE;
    }
    nvs_close(h);
}

// ── Task ──────────────────────────────────────────────────────────────────────

static void notify(void)
{
    alarm_info_t snap;
    alarm_get(&snap);
    for (int i = 0; i < s_listener_count; i++) s_listeners[i](&snap);
}

static void open_incident(const alarm_msg_t *m, int64_t now)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_info.state    = ALARM_ACTIVE;
    s_info.acked_by = ALARM_BY_NONE;
    s_info.id++;
    s_info.src_ip   = m->ip;
    memcpy(s_info.src_mac, m->mac, sizeof(s_info.src_mac));
    s_info.type     = m->type;
    s_info.first_ts = m->ts;
    s_info.last_ts  = m->ts;
    s_info.count    = 1;
    xSemaphoreGive(s_mutex);

    s_last_event_s  = now;
    s_last_remind_s = now;
    persist();
    ESP_LOGW(TAG, "Incident #%lu opened (type %u)",
             (unsigned long)s_info.id, (unsigned)m->type);
    notify();
    buzzer_alarm();
}

static void alarm_task(void *arg)
{
    (void)arg;
    bool    dirty       = false;   // count changed since the last notify
    int64_t last_notify = 0;

    if (s_info.state == ALARM_ACTIVE) {
        // Unacknowledged incident survived a reboot: say so, keep reminding.
        s_last_remind_s = mono_s();
        notify();
        buzzer_remind();
    }

    for (;;) {
        alarm_msg_t m;
        bool got = xQueueReceive(s_queue, &m, pdMS_TO_TICKS(1000)) == pdTRUE;
        int64_t now = mono_s();

        if (got && m.kind == MSG_ACK) {
            if (s_info.state == ALARM_ACTIVE) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_info.state = ALARM_ACKED;
                s_info.acked_by = m.by;
                xSemaphoreGive(s_mutex);
                persist();
                ESP_LOGI(TAG, "Incident #%lu acknowledged", (unsigned long)s_info.id);
                buzzer_stop();
                notify();
                dirty = false;
            }
        } else if (got && m.kind == MSG_CLEAR) {
            // Re-arm: end an acknowledged incident now rather than after
            // ALARM_QUIET_S, so the next event alerts again. The incident's
            // details stay in s_info (the panel's "last incident") and nothing
            // in the logs is touched. An unacknowledged incident is left alone.
            if (s_info.state == ALARM_ACKED) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_info.state = ALARM_IDLE;
                xSemaphoreGive(s_mutex);
                persist();
                ESP_LOGI(TAG, "Incident #%lu closed, re-armed", (unsigned long)s_info.id);
                s_rearmed = true;
                notify();
                dirty = false;
            }
        } else if (got) {
            bool same_src = (m.ip == s_info.src_ip);
            bool quiet    = (now - s_last_event_s) >= (int64_t)settings_get()->alarm_quiet_s;

            if (s_info.state == ALARM_IDLE ||
                (s_info.state == ALARM_ACKED && (!same_src || quiet))) {
                open_incident(&m, now);
                dirty = false;
                last_notify = now;
            } else {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_info.count++;
                s_info.last_ts = m.ts;
                xSemaphoreGive(s_mutex);
                s_last_event_s = now;
                dirty = true;
            }
        }

        // Count-only updates are rate-limited so a port scan can't flood the
        // panel and the WebSocket with one message per probe.
        if (dirty && now - last_notify >= 1) {
            notify();
            dirty = false;
            last_notify = now;
        }

        if (s_info.state == ALARM_ACTIVE && now - s_last_remind_s >= (int64_t)settings_get()->alarm_remind_s) {
            s_last_remind_s = now;
            ESP_LOGW(TAG, "Incident #%lu still unacknowledged", (unsigned long)s_info.id);
            buzzer_remind();
        }

        if (s_info.state == ALARM_ACKED && now - s_last_event_s >= (int64_t)settings_get()->alarm_quiet_s) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_info.state = ALARM_IDLE;
            xSemaphoreGive(s_mutex);
            persist();
            ESP_LOGI(TAG, "Incident #%lu closed after %lu s quiet",
                     (unsigned long)s_info.id, (unsigned long)settings_get()->alarm_quiet_s);
            s_rearmed = false;
            notify();
        }
    }
}

void alarm_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_queue = xQueueCreate(ALARM_QUEUE_DEPTH, sizeof(alarm_msg_t));
    buzzer_init();
    restore();
    log_store_add_listener(on_event);
    xTaskCreatePinnedToCore(alarm_task, "alarm", ALARM_TASK_STACK, NULL,
                            ALARM_TASK_PRIO, NULL, 1);
}
