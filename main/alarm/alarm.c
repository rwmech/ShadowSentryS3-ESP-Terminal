#include "settings.h"   // alarm_remind_s / alarm_quiet_s, read live
#include "alarm.h"
#include "buzzer.h"
#include "log_store.h"
#include "ignore.h"
#include "describe.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "ALARM";

#define ALARM_QUEUE_DEPTH    32
#define ALARM_TASK_STACK     4096
#define ALARM_TASK_PRIO      4
#define ALARM_MAX_LISTENERS  6     // UI, WebSocket, SD log, Discord, notify, plus 1 spare
#define NVS_NS               "alarm"
#define NVS_KEY              "incident"

typedef enum { MSG_EVENT, MSG_ACK, MSG_RESOLVE, MSG_IGNORED } msg_kind_t;

// The whole event rides along (PSRAM queue), so the code, tier and headline
// are worked out here on the alarm task, not on a 3 KB trap stack.
typedef struct {
    msg_kind_t   kind;
    uint8_t      by;        // alarm_by_t, for ACK, RESOLVE and IGNORED
    uint32_t     id;        // IGNORED: the incident the entry was added for
    attack_log_t e;         // EVENT
} alarm_msg_t;

// The incident as stored before codes and conditions (NVS blob, 32 B).
typedef struct {
    alarm_state_t state;
    uint32_t      id;
    uint32_t      src_ip;
    uint8_t       src_mac[6];
    uint8_t       type;
    uint32_t      first_ts;
    uint32_t      last_ts;
    uint32_t      count;
} old_info_t;

static QueueHandle_t     s_queue;
static SemaphoreHandle_t s_mutex;
static alarm_info_t      s_info;            // guarded by s_mutex; written on the alarm task only
static int64_t           s_last_event_s;    // monotonic, alarm task only
static int64_t           s_last_remind_s;   // monotonic, alarm task only
static bool              s_rearmed;         // alarm task only: the last close was a resolve

static void (*s_listeners[ALARM_MAX_LISTENERS])(const alarm_info_t *info);
static int s_listener_count = 0;

static int64_t mono_s(void) { return esp_timer_get_time() / 1000000LL; }

static alarm_cond_t cond_of(alarm_state_t st)
{
    return st == ALARM_ACTIVE ? ALARM_COND_RED : st == ALARM_ACKED ? ALARM_COND_YELLOW : ALARM_COND_GREEN;
}

// Bit of a code in alarm_info_t.codes: its row in the code table, -1 if none.
static int code_bit(const char *code)
{
    int n = describe_code_count();
    for (int i = 0; i < n && i < 32; i++)
        if (!strcmp(describe_code_at(i, NULL, NULL), code)) return i;
    return -1;
}

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

void alarm_get(alarm_info_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_info;
    xSemaphoreGive(s_mutex);
}

const char *alarm_cond_key(alarm_cond_t c)
{
    return c == ALARM_COND_RED ? "red" : c == ALARM_COND_YELLOW ? "yellow" : "green";
}

const char *alarm_by_key(uint8_t by)
{
    return by == ALARM_BY_PANEL ? "panel" : by == ALARM_BY_DASHBOARD ? "dashboard" : "";
}

static void post(msg_kind_t kind, alarm_by_t by, uint32_t id)
{
    if (!s_queue) return;
    alarm_msg_t m = { .kind = kind, .by = (uint8_t)by, .id = id };    // the event part unused
    xQueueSend(s_queue, &m, 0);
}

void alarm_ack(alarm_by_t by)     { post(MSG_ACK, by, 0); }
void alarm_resolve(alarm_by_t by) { post(MSG_RESOLVE, by, 0); }
void alarm_clear(void)            { alarm_resolve(ALARM_BY_PANEL); }

static esp_err_t ignore_incident(alarm_by_t by, bool whole_device)
{
    alarm_info_t a;
    alarm_get(&a);
    if (a.state == ALARM_IDLE || !a.id) return ESP_ERR_INVALID_STATE;
    static const uint8_t zero[6] = { 0 };
    bool has_mac = memcmp(a.src_mac, zero, 6) != 0;
    if (!a.src_ip && !has_mac) return ESP_ERR_INVALID_STATE;     // nothing to name the source by
    char note[IGNORE_NOTE_MAX];
    snprintf(note, sizeof(note), "%s, incident #%lu%s%s", by == ALARM_BY_PANEL ? "panel" : "dashboard",
             (unsigned long)a.id, whole_device ? "" : ", ", whole_device ? "" : a.code);
    esp_err_t r = ignore_add(a.src_ip, has_mac ? a.src_mac : NULL, whole_device ? "" : a.code, note);
    if (r == ESP_OK) {
        ESP_LOGW(TAG, "Incident #%lu: %s ignored (%s)", (unsigned long)a.id,
                 whole_device ? "source" : a.code, alarm_by_key(by));
        post(MSG_IGNORED, by, a.id);
    }
    return r;
}

esp_err_t alarm_ignore_error(alarm_by_t by)  { return ignore_incident(by, false); }
esp_err_t alarm_ignore_device(alarm_by_t by) { return ignore_incident(by, true); }

bool alarm_should_alert(const attack_log_t *e)
{
    if (!e) return false;
    if ((unsigned)e->type < 32 && !(settings_get()->alert_mask & (1u << e->type))) return false;
    return !ignore_match(e->src_ip, e->src_mac, describe_code(e));
}

// log_store listener: runs on the appending honeypot task (as small as 3 KB of
// stack), so it only gates and queues a copy (about 250 B on that stack, as
// the SD log's listener). Types switched off and ignored sources or codes
// never reach the queue: logged, no incident.
static void on_event(const attack_log_t *e)
{
    if (!alarm_should_alert(e)) return;
    alarm_msg_t m = { .kind = MSG_EVENT, .e = *e };
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

// Code and headline for an incident restored without them: the opening
// event's type is all that is left of it.
static void fill_from_type(alarm_info_t *a)
{
    attack_log_t ev = { .timestamp = a->first_ts, .src_ip = a->src_ip, .type = (attack_type_t)a->type };
    memcpy(ev.src_mac, a->src_mac, 6);
    strlcpy(a->code, describe_code(&ev), sizeof(a->code));
    describe_event(&ev, a->headline, sizeof(a->headline));
    int b = code_bit(a->code);
    a->codes = b >= 0 ? (1u << b) : 0;
}

static void restore(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    alarm_info_t *saved = heap_caps_calloc(1, sizeof(*saved), MALLOC_CAP_SPIRAM);
    size_t len = sizeof(*saved);
    if (saved && nvs_get_blob(h, NVS_KEY, saved, &len) == ESP_OK) {
        if (len == sizeof(*saved)) {
            saved->code[sizeof(saved->code) - 1] = '\0';
            saved->headline[sizeof(saved->headline) - 1] = '\0';
            s_info = *saved;
        } else if (len == sizeof(old_info_t)) {
            // Saved by a build before codes: an unacknowledged incident stays
            // RED, an acknowledged one becomes YELLOW.
            old_info_t o;
            memcpy(&o, saved, sizeof(o));
            memset(&s_info, 0, sizeof(s_info));
            s_info.state    = o.state <= ALARM_ACKED ? o.state : ALARM_IDLE;
            s_info.id       = o.id;
            s_info.src_ip   = o.src_ip;
            memcpy(s_info.src_mac, o.src_mac, 6);
            s_info.type     = o.type;
            s_info.first_ts = o.first_ts;
            s_info.last_ts  = o.last_ts;
            s_info.count    = o.count;
            fill_from_type(&s_info);
            ESP_LOGI(TAG, "Incident #%lu migrated (code %s)", (unsigned long)s_info.id, s_info.code);
        }
        if (s_info.state > ALARM_ACKED) s_info.state = ALARM_IDLE;
        s_info.cond = cond_of(s_info.state);
    }
    heap_caps_free(saved);
    nvs_close(h);
}

// ── Task ──────────────────────────────────────────────────────────────────────

static alarm_info_t *s_snap;        // alarm task only, PSRAM: off its stack
static alarm_msg_t  *s_msg;         // the same

static void notify(void)
{
    alarm_get(s_snap);
    for (int i = 0; i < s_listener_count; i++) s_listeners[i](s_snap);
}

// s_mutex held. The cond follows the state.
static void set_state(alarm_state_t st)
{
    s_info.state = st;
    s_info.cond  = cond_of(st);
}

// s_mutex held. The incident's headline event: type, code, headline.
static void set_headline(const attack_log_t *e)
{
    s_info.type = (uint8_t)e->type;
    strlcpy(s_info.code, describe_code(e), sizeof(s_info.code));
    describe_event(e, s_info.headline, sizeof(s_info.headline));
}

static void log_stack_once(void)
{
    static bool done;
    if (done) return;
    done = true;
    ESP_LOGI(TAG, "First incident, stack high-water %u B of %d",
             (unsigned)uxTaskGetStackHighWaterMark(NULL), ALARM_TASK_STACK);
}

static void open_incident(const attack_log_t *e, bool red, int64_t now)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    set_state(red ? ALARM_ACTIVE : ALARM_ACKED);
    s_info.acked_by    = ALARM_BY_NONE;
    s_info.resolved_by = ALARM_BY_NONE;
    s_info.id++;
    s_info.src_ip   = e->src_ip;
    memcpy(s_info.src_mac, e->src_mac, sizeof(s_info.src_mac));
    s_info.first_ts = e->timestamp;
    s_info.last_ts  = e->timestamp;
    s_info.count    = 1;
    set_headline(e);
    int b = code_bit(s_info.code);
    s_info.codes = b >= 0 ? (1u << b) : 0;
    xSemaphoreGive(s_mutex);

    s_last_event_s  = now;
    s_last_remind_s = now;
    persist();
    ESP_LOGW(TAG, "Incident #%lu opened %s: %s", (unsigned long)s_info.id,
             red ? "RED" : "YELLOW", s_info.headline);
    notify();
    if (red) buzzer_alarm();
    else     buzzer_yellow();
    log_stack_once();
}

// A SEV1 event in a YELLOW incident nobody acknowledged: RED in place, same
// number, the SEV1 event becomes the headline.
static void escalate(const attack_log_t *e, int64_t now)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    set_state(ALARM_ACTIVE);
    s_info.count++;
    s_info.last_ts = e->timestamp;
    set_headline(e);
    int b = code_bit(s_info.code);
    if (b >= 0) s_info.codes |= 1u << b;
    xSemaphoreGive(s_mutex);
    s_last_event_s  = now;
    s_last_remind_s = now;
    persist();
    ESP_LOGW(TAG, "Incident #%lu escalated to RED: %s", (unsigned long)s_info.id, s_info.headline);
    notify();
    buzzer_alarm();
}

static void close_incident(alarm_by_t by)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    set_state(ALARM_IDLE);
    s_info.resolved_by = (uint8_t)by;
    xSemaphoreGive(s_mutex);
    persist();
    s_rearmed = by != ALARM_BY_NONE;
    notify();
}

// Same source: the IP, or for events without one (radio, ARP by MAC) the MAC.
static bool same_source(const attack_log_t *e)
{
    if (e->src_ip || s_info.src_ip) return e->src_ip == s_info.src_ip;
    return !memcmp(e->src_mac, s_info.src_mac, 6);
}

// True when the event opened or changed the incident's state (listeners told).
static bool handle_event(const attack_log_t *e, int64_t now)
{
    bool sev1 = describe_tier(e) == TIER_SEV1;
    if (s_info.state == ALARM_IDLE) { open_incident(e, sev1, now); return true; }

    bool same  = same_source(e);
    bool quiet = (now - s_last_event_s) >= (int64_t)settings_get()->alarm_quiet_s;
    if (s_info.state == ALARM_ACKED) {
        if (!same || quiet) { open_incident(e, sev1, now); return true; }
        if (sev1 && s_info.acked_by == ALARM_BY_NONE) { escalate(e, now); return true; }
    }
    int b = code_bit(describe_code(e));
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_info.count++;
    s_info.last_ts = e->timestamp;
    if (b >= 0 && same) s_info.codes |= 1u << b;
    xSemaphoreGive(s_mutex);
    s_last_event_s = now;
    return false;
}

// After an ignore entry was added for incident id: resolve it, whatever
// other codes it saw (Rob, 2026-11-01: an explicit ignore means "dealt
// with"). Its events stay in the logs; a later event whose code is not
// ignored opens a new incident as usual.
static void handle_ignored(uint32_t id, alarm_by_t by)
{
    if (s_info.state == ALARM_IDLE || s_info.id != id) return;
    if (s_info.state == ALARM_ACTIVE) buzzer_stop();
    ESP_LOGI(TAG, "Incident #%lu resolved by an ignore (%s)", (unsigned long)id, alarm_by_key(by));
    close_incident(by);
}

static void alarm_task(void *arg)
{
    (void)arg;
    bool    dirty       = false;   // count changed since the last notify
    int64_t last_notify = 0;
    alarm_msg_t *m = s_msg;         // PSRAM: a whole event, off the stack

    s_last_event_s = mono_s();     // a YELLOW incident restored at boot: the quiet time starts now
    if (s_info.state == ALARM_ACTIVE) {
        // Unacknowledged incident survived a reboot: say so, keep reminding.
        s_last_remind_s = mono_s();
        notify();
        buzzer_remind();
    } else if (s_info.state == ALARM_ACKED) {
        notify();
    }

    for (;;) {
        bool got = xQueueReceive(s_queue, m, pdMS_TO_TICKS(1000)) == pdTRUE;
        int64_t now = mono_s();

        if (got && m->kind == MSG_ACK) {
            if (s_info.state == ALARM_ACTIVE) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                set_state(ALARM_ACKED);
                s_info.acked_by = m->by ? m->by : ALARM_BY_PANEL;
                xSemaphoreGive(s_mutex);
                persist();
                ESP_LOGI(TAG, "Incident #%lu acknowledged (%s), YELLOW",
                         (unsigned long)s_info.id, alarm_by_key(m->by));
                buzzer_stop();
                notify();
                dirty = false;
            }
        } else if (got && m->kind == MSG_RESOLVE) {
            // RED or YELLOW to GREEN now, so the next event alerts again. The
            // incident's details stay in s_info (the panel's "last incident")
            // and nothing in the logs is touched.
            if (s_info.state != ALARM_IDLE) {
                if (s_info.state == ALARM_ACTIVE) buzzer_stop();
                ESP_LOGI(TAG, "Incident #%lu resolved (%s), GREEN",
                         (unsigned long)s_info.id, alarm_by_key(m->by));
                close_incident(m->by ? (alarm_by_t)m->by : ALARM_BY_DASHBOARD);
                dirty = false;
            }
        } else if (got && m->kind == MSG_IGNORED) {
            handle_ignored(m->id, m->by ? (alarm_by_t)m->by : ALARM_BY_DASHBOARD);
            dirty = false;
        } else if (got) {
            if (handle_event(&m->e, now)) {
                dirty = false;
                last_notify = now;
            } else {
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
            ESP_LOGI(TAG, "Incident #%lu closed after %lu s quiet, GREEN",
                     (unsigned long)s_info.id, (unsigned long)settings_get()->alarm_quiet_s);
            close_incident(ALARM_BY_NONE);
        }
    }
}

void alarm_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    // PSRAM: each message carries a whole attack_log_t (about 250 B).
    s_queue = xQueueCreateWithCaps(ALARM_QUEUE_DEPTH, sizeof(alarm_msg_t), MALLOC_CAP_SPIRAM);
    s_snap  = heap_caps_calloc(1, sizeof(*s_snap), MALLOC_CAP_SPIRAM);
    s_msg   = heap_caps_calloc(1, sizeof(*s_msg), MALLOC_CAP_SPIRAM);
    configASSERT(s_mutex && s_queue && s_snap && s_msg);
    buzzer_init();
    restore();
    log_store_add_listener(on_event);
    xTaskCreatePinnedToCore(alarm_task, "alarm", ALARM_TASK_STACK, NULL,
                            ALARM_TASK_PRIO, NULL, 1);
}
