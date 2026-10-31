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
#define ALARM_MAX_LISTENERS  4
#define NVS_NS               "alarm"
#define NVS_KEY              "incident"

typedef enum { MSG_EVENT, MSG_ACK, MSG_CLEAR } msg_kind_t;

typedef struct {
    msg_kind_t kind;
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

static void (*s_listeners[ALARM_MAX_LISTENERS])(const alarm_info_t *info);
static int s_listener_count = 0;

static int64_t mono_s(void) { return esp_timer_get_time() / 1000000LL; }

void alarm_add_listener(void (*cb)(const alarm_info_t *info))
{
    if (!cb || s_listener_count >= ALARM_MAX_LISTENERS) return;
    s_listeners[s_listener_count++] = cb;
}

void alarm_get(alarm_info_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_info;
    xSemaphoreGive(s_mutex);
}

void alarm_ack(void)
{
    if (!s_queue) return;
    alarm_msg_t m = { .kind = MSG_ACK };
    xQueueSend(s_queue, &m, 0);
}

void alarm_clear(void)
{
    if (!s_queue) return;
    alarm_msg_t m = { .kind = MSG_CLEAR };
    xQueueSend(s_queue, &m, 0);
}

bool alarm_should_alert(uint8_t type, uint32_t src_ip, const uint8_t src_mac[6])
{
    if (type < 32 && !(settings_get()->alert_mask & (1u << type))) return false;
    return !ignore_match(src_ip, src_mac);
}

// log_store listener: runs on the appending honeypot task (as small as 3 KB of
// stack), so it only copies five fields into the queue. Types switched off and
// ignored sources never reach the queue: logged, no incident.
static void on_event(const attack_log_t *e)
{
    if (!alarm_should_alert((uint8_t)e->type, e->src_ip, e->src_mac)) return;
    alarm_msg_t m = { .kind = MSG_EVENT, .ip = e->src_ip,
                      .type = (uint8_t)e->type, .ts = e->timestamp };
    memcpy(m.mac, e->src_mac, sizeof(m.mac));
    xQueueSend(s_queue, &m, 0);   // full queue = burst already raising the alarm
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
