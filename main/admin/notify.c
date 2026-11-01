// Notification layer: fan-out to the alert backends, the boot "online"
// message with the reset reason, and incident transitions for the backends
// that take them. See notify.h. Fork addition, Robert Mech.
//
// Threading: notify_send() runs on the caller (the alarm task for incidents,
// app_main for the boot message) and only hands a copy to each backend's own
// queue. The backend table is filled at boot, before the first send.

#include "notify.h"
#include "alarm.h"
#include "log_store.h"
#include "settings.h"
#include "config.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "NOTIFY";

#define NOTIFY_NVS_NS       "notify"
#define NOTIFY_NVS_KEY      "restart"

static const notify_backend_t *s_backends[NOTIFY_MAX_BACKENDS];
static int                     s_backend_count;
static esp_reset_reason_t      s_reset;
static notify_restart_t        s_intent;
static char                    s_reason[80];
static alarm_info_t            s_prev;          // alarm listener only

// ── Reset reason ──────────────────────────────────────────────────────────────

const char *notify_reset_reason_str(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:   return "power-on";
    case ESP_RST_SW:        return "software restart";
    case ESP_RST_PANIC:     return "panic/crash";
    case ESP_RST_INT_WDT:   return "interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "task watchdog";
    case ESP_RST_WDT:       return "other watchdog";
    case ESP_RST_BROWNOUT:  return "brown-out";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    case ESP_RST_EXT:       return "external pin";
    default:                return "unknown";
    }
}

static notify_severity_t reset_severity(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_PANIC:
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:       return NOTIFY_ALERT;
    case ESP_RST_BROWNOUT:  return NOTIFY_WARN;
    default:                return NOTIFY_INFO;
    }
}

static const char *intent_str(notify_restart_t why)
{
    switch (why) {
    case NOTIFY_RESTART_OTA:           return "OTA update";
    case NOTIFY_RESTART_DASHBOARD:     return "reboot from the dashboard";
    case NOTIFY_RESTART_WIFI_FALLBACK: return "saved Wi-Fi got no IP, back to the config.h network";
    default:                           return NULL;
    }
}

const char *notify_boot_reason(void) { return s_reason; }

static uint32_t s_boot_internal;
void notify_note_boot_heap(uint32_t internal_free) { s_boot_internal = internal_free; }
uint32_t notify_boot_heap(void) { return s_boot_internal; }

void notify_restart_intent(notify_restart_t why)
{
    nvs_handle_t h;
    if (nvs_open(NOTIFY_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_set_u8(h, NOTIFY_NVS_KEY, (uint8_t)why) == ESP_OK) nvs_commit(h);
    nvs_close(h);
}

// Read the intent the previous run stored, then clear it so a later crash or
// power cut is never reported as a deliberate restart.
static notify_restart_t take_intent(void)
{
    nvs_handle_t h;
    uint8_t v = NOTIFY_RESTART_NONE;
    if (nvs_open(NOTIFY_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return NOTIFY_RESTART_NONE;
    if (nvs_get_u8(h, NOTIFY_NVS_KEY, &v) == ESP_OK) {
        nvs_erase_key(h, NOTIFY_NVS_KEY);
        nvs_commit(h);
    }
    nvs_close(h);
    return (notify_restart_t)v;
}

// ── Fan-out ───────────────────────────────────────────────────────────────────

void notify_register(const notify_backend_t *backend)
{
    if (!backend || !backend->send) return;
    if (s_backend_count >= NOTIFY_MAX_BACKENDS) {
        ESP_LOGE(TAG, "Backend table full (%d), %s dropped", NOTIFY_MAX_BACKENDS, backend->name);
        return;
    }
    s_backends[s_backend_count++] = backend;
}

void notify_send(notify_kind_t kind, const char *title, const char *text,
                 notify_severity_t severity)
{
    if (kind >= NOTIFY_KIND_COUNT) return;
    notify_msg_t m = { .kind = kind, .severity = severity };
    strlcpy(m.title, title ? title : "", sizeof(m.title));
    strlcpy(m.text, text ? text : "", sizeof(m.text));
    for (int i = 0; i < s_backend_count; i++) {
        const notify_backend_t *b = s_backends[i];
        if (!(b->kinds & NOTIFY_BIT(kind))) continue;
        if (b->enabled && !b->enabled()) continue;
        if (!b->send(&m)) ESP_LOGW(TAG, "%s: queue full, message dropped", b->name);
    }
}

// ── Boot message ──────────────────────────────────────────────────────────────

void notify_boot(const char *ip_str)
{
    const char *ip = (ip_str && ip_str[0]) ? ip_str : "no IP";
    const esp_app_desc_t *app = esp_app_get_description();
    notify_severity_t sev = reset_severity(s_reset);

    char title[NOTIFY_TITLE_MAX];
    if (sev == NOTIFY_INFO)
        snprintf(title, sizeof(title), "ShadowSentry S3 online");
    else
        snprintf(title, sizeof(title), "ShadowSentry S3 online, reset: %s",
                 notify_reset_reason_str(s_reset));

    char text[NOTIFY_TEXT_MAX];
    snprintf(text, sizeof(text),
             "Device: %s (%s)\n"
             "Firmware: %s (build %.32s)\n"
             "Reset: %s\n"
             "Dashboard: http://%s:%d",
             ip,
#if defined(MDNS_ENABLE) && MDNS_ENABLE
             MDNS_HOSTNAME ".local",
#else
             DEVICE_HOSTNAME,
#endif
             SHADOWSENTRY_VERSION, app->version,
             s_reason,
             ip, ADMIN_PORT);
    notify_send(NOTIFY_BOOT, title, text, sev);
}

// ── Incident transitions (alarm listener, alarm task) ─────────────────────────

static const char *type_name(uint8_t t)
{
    static const char *const NAMES[] = {"RTSP login", "HTTP request", "Telnet login", "SSH login",
                                        "FTP login", "ARP spoofing / MITM", "Wi-Fi deauth flood",
                                        "Interactive shell", "Port scan", "Probe", "ARP sweep",
                                        "ADB (Android Debug Bridge)",
                                        "Tripwire port", "LAN discovery (device seen)"};
    _Static_assert(sizeof(NAMES) / sizeof(NAMES[0]) == ATTACK_TYPE_COUNT, "NAMES: one per attack_type_t");
    return t < ATTACK_TYPE_COUNT ? NAMES[t] : "other attack";
}

// "Code 17-01 ARP sweep: incident #N <what>", the code first so a cut keeps it
static void inc_title(char *out, size_t len, const alarm_info_t *a, const char *what)
{
    const char *name = describe_code_name(a->code);
    snprintf(out, len, "Code %s%s%s: incident #%lu %s",
             a->code[0] ? a->code : "?", name ? " " : "", name ? name : "", (unsigned long)a->id, what);
}

static void post_closed(const alarm_info_t *a, const char *what, const char *why)
{
    char title[NOTIFY_TITLE_MAX], text[160], ip[16];
    ip4_addr_t addr = { .addr = a->src_ip };
    ip4addr_ntoa_r(&addr, ip, sizeof(ip));
    inc_title(title, sizeof(title), a, what);
    snprintf(text, sizeof(text), "%s\nSource: %s\nEvents: %lu",
             why, ip, (unsigned long)a->count);
    notify_send(NOTIFY_INCIDENT_CLOSED, title, text, NOTIFY_INFO);
}

static void on_alarm(const alarm_info_t *a)
{
    // Transitions only: count-only updates arrive every second.
    if (a->state == s_prev.state && a->id == s_prev.id) { s_prev = *a; return; }

    static char *text;                  // alarm task only, PSRAM: off its stack
    if (!text) text = heap_caps_malloc(NOTIFY_TEXT_MAX, MALLOC_CAP_SPIRAM);
    if (!text) { s_prev = *a; return; }
    char title[NOTIFY_TITLE_MAX], ip[16];
    ip4_addr_t addr = { .addr = a->src_ip };
    ip4addr_ntoa_r(&addr, ip, sizeof(ip));

    if (a->state != ALARM_IDLE && a->id != s_prev.id) {
        // A YELLOW incident is closed implicitly when a new one opens.
        if (s_prev.state != ALARM_IDLE && s_prev.id) {
            char why[64];
            snprintf(why, sizeof(why), "New incident #%lu.", (unsigned long)a->id);
            post_closed(&s_prev, "closed, GREEN", why);
        }
        bool red = a->state == ALARM_ACTIVE;
        inc_title(title, sizeof(title), a, red ? "opened, RED" : "opened, YELLOW");
        snprintf(text, NOTIFY_TEXT_MAX, "%s\nAttack: %s\nSource: %s", a->headline, type_name(a->type), ip);
        notify_send(NOTIFY_INCIDENT_OPENED, title, text, red ? NOTIFY_ALERT : NOTIFY_WARN);
    } else if (a->state == ALARM_ACTIVE && s_prev.state == ALARM_ACKED) {
        inc_title(title, sizeof(title), a, "escalated to RED");
        snprintf(text, NOTIFY_TEXT_MAX, "%s\nSource: %s\nEvents so far: %lu", a->headline, ip, (unsigned long)a->count);
        notify_send(NOTIFY_INCIDENT_OPENED, title, text, NOTIFY_ALERT);
    } else if (a->state == ALARM_ACKED && s_prev.state == ALARM_ACTIVE) {
        inc_title(title, sizeof(title), a, "acknowledged, YELLOW");
        snprintf(text, NOTIFY_TEXT_MAX, "Acknowledged %s.\nSource: %s\nEvents so far: %lu",
                 a->acked_by == ALARM_BY_DASHBOARD ? "from the dashboard" : "on the front panel",
                 ip, (unsigned long)a->count);
        notify_send(NOTIFY_INCIDENT_ACKED, title, text, NOTIFY_WARN);
    } else if (a->state == ALARM_IDLE && s_prev.state != ALARM_IDLE) {
        char why[64];
        if (a->resolved_by)
            snprintf(why, sizeof(why), "Resolved %s.",
                     a->resolved_by == ALARM_BY_DASHBOARD ? "from the dashboard" : "on the front panel");
        else
            snprintf(why, sizeof(why), "Quiet for %lu s.", (unsigned long)settings_get()->alarm_quiet_s);
        post_closed(a, a->resolved_by ? "resolved, GREEN" : "closed, GREEN", why);
    }
    s_prev = *a;
}

// ── Init ──────────────────────────────────────────────────────────────────────

void notify_init(void)
{
    s_reset  = esp_reset_reason();
    s_intent = take_intent();
    const char *why = (s_reset == ESP_RST_SW) ? intent_str(s_intent) : NULL;
    if (why)
        snprintf(s_reason, sizeof(s_reason), "%s (%s)", notify_reset_reason_str(s_reset), why);
    else
        snprintf(s_reason, sizeof(s_reason), "%s", notify_reset_reason_str(s_reset));
    ESP_LOGI(TAG, "Reset reason: %s (code %d)", s_reason, (int)s_reset);

    alarm_get(&s_prev);                 // an incident carried over a reboot is not "new"
    alarm_add_listener(on_alarm);
}
