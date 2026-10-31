#include "settings.h"
#include "config.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char *TAG = "SETTINGS";
#define NS "settings"

#ifndef ALARM_REMIND_S
#define ALARM_REMIND_S 60
#endif
#ifndef ALARM_QUIET_S
#define ALARM_QUIET_S 600
#endif
#ifndef DISPLAY_TZ
#define DISPLAY_TZ "UTC0"
#endif
#ifndef DISCORD_WEBHOOK_URL
#define DISCORD_WEBHOOK_URL ""
#endif

static settings_t        s_live;     // what is running now
static settings_t        s_saved;    // what NVS holds: the next boot runs this
static SemaphoreHandle_t s_mutex;
static bool              s_wifi_overridden = false;
static void            (*s_on_change[3])(void);
static int               s_on_change_count = 0;

static void defaults(settings_t *s)
{
    memset(s, 0, sizeof(*s));
    strlcpy(s->admin_password, ADMIN_PASSWORD, sizeof(s->admin_password));
    strlcpy(s->wifi_ssid, WIFI_SSID, sizeof(s->wifi_ssid));
    strlcpy(s->wifi_password, WIFI_PASSWORD, sizeof(s->wifi_password));
    strlcpy(s->tg_token, TELEGRAM_BOT_TOKEN, sizeof(s->tg_token));
    strlcpy(s->tg_chat_id, TELEGRAM_CHAT_ID, sizeof(s->tg_chat_id));
    strlcpy(s->tz, DISPLAY_TZ, sizeof(s->tz));
    s->alarm_remind_s = ALARM_REMIND_S;
    s->alarm_quiet_s  = ALARM_QUIET_S;
    s->brightness     = 100;
    s->alarm_sound    = true;
    s->boot_chirp     = true;
    s->touch_click    = true;
    strlcpy(s->discord_webhook, DISCORD_WEBHOOK_URL, sizeof(s->discord_webhook));
    s->discord_log_events = true;
}

static void get_str(nvs_handle_t h, const char *key, char *dst, size_t len)
{
    size_t n = len;
    char tmp[168];                  // longest field: discord_webhook[160]
    if (n > sizeof(tmp)) n = sizeof(tmp);
    if (nvs_get_str(h, key, tmp, &n) == ESP_OK) strlcpy(dst, tmp, len);
}

static void get_u32(nvs_handle_t h, const char *key, uint32_t *dst)
{
    uint32_t v;
    if (nvs_get_u32(h, key, &v) == ESP_OK) *dst = v;
}

static void get_u8(nvs_handle_t h, const char *key, uint8_t *dst)
{
    uint8_t v;
    if (nvs_get_u8(h, key, &v) == ESP_OK) *dst = v;
}

static void get_bool(nvs_handle_t h, const char *key, bool *dst)
{
    uint8_t v;
    if (nvs_get_u8(h, key, &v) == ESP_OK) *dst = v != 0;
}

void settings_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    defaults(&s_live);

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        get_str(h, "admin_pw", s_live.admin_password, sizeof(s_live.admin_password));
        size_t n = 0;
        s_wifi_overridden = nvs_get_str(h, "wifi_ssid", NULL, &n) == ESP_OK;
        get_str(h, "wifi_ssid", s_live.wifi_ssid, sizeof(s_live.wifi_ssid));
        get_str(h, "wifi_pw", s_live.wifi_password, sizeof(s_live.wifi_password));
        get_str(h, "tg_token", s_live.tg_token, sizeof(s_live.tg_token));
        get_str(h, "tg_chat", s_live.tg_chat_id, sizeof(s_live.tg_chat_id));
        get_str(h, "tz", s_live.tz, sizeof(s_live.tz));
        get_u32(h, "remind_s", &s_live.alarm_remind_s);
        get_u32(h, "quiet_s", &s_live.alarm_quiet_s);
        get_u8(h, "bright", &s_live.brightness);
        get_bool(h, "alarm_snd", &s_live.alarm_sound);
        get_bool(h, "boot_chirp", &s_live.boot_chirp);
        get_bool(h, "click", &s_live.touch_click);
        get_str(h, "dc_hook", s_live.discord_webhook, sizeof(s_live.discord_webhook));
        get_bool(h, "dc_log", &s_live.discord_log_events);
        nvs_close(h);
    }
    s_saved = s_live;
    setenv("TZ", s_live.tz, 1);
    tzset();
    ESP_LOGI(TAG, "Loaded (Wi-Fi %s, Telegram %s)",
             s_wifi_overridden ? "from settings" : "from config.h",
             settings_telegram_enabled() ? "on" : "off");
}

const settings_t *settings_get(void) { return &s_live; }

void settings_copy(settings_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_live;
    xSemaphoreGive(s_mutex);
}

void settings_copy_saved(settings_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_saved;
    xSemaphoreGive(s_mutex);
}

bool settings_reboot_pending(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool p = strcmp(s_saved.wifi_ssid, s_live.wifi_ssid) ||
             strcmp(s_saved.wifi_password, s_live.wifi_password) ||
             strcmp(s_saved.tg_token, s_live.tg_token) ||
             strcmp(s_saved.tg_chat_id, s_live.tg_chat_id);
    xSemaphoreGive(s_mutex);
    return p;
}

void settings_on_change(void (*cb)(void))
{
    if (cb && s_on_change_count < 3) s_on_change[s_on_change_count++] = cb;
}

bool settings_wifi_overridden(void) { return s_wifi_overridden; }

bool settings_telegram_enabled(void)
{
    return s_live.tg_token[0] && s_live.tg_token[0] != 'Y' &&
           s_live.tg_chat_id[0] && s_live.tg_chat_id[0] != 'Y';
}

void settings_forget_wifi(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_key(h, "wifi_ssid");
    nvs_erase_key(h, "wifi_pw");
    nvs_commit(h);
    nvs_close(h);
}

// Every byte in [lo, hi].
static bool chars_ok(const char *s, unsigned char lo, unsigned char hi)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < lo || c > hi) return false;
    }
    return true;
}

// Letters, digits and the extra set only.
static bool alnum_ok(const char *s, const char *extra)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) continue;
        if (strchr(extra, c)) continue;
        return false;
    }
    return true;
}

// Empty, or https://discord.com/api/webhooks/... (or discordapp.com) followed
// by URL-safe characters only: the URL goes straight to esp_http_client.
static bool discord_url_ok(const char *u)
{
    static const char *const pfx[] = { "https://discord.com/api/webhooks/",
                                       "https://discordapp.com/api/webhooks/" };
    for (size_t i = 0; i < sizeof(pfx) / sizeof(pfx[0]); i++) {
        size_t n = strlen(pfx[i]);
        if (strncmp(u, pfx[i], n) == 0 && u[n] && alnum_ok(u + n, "-_/?=&.")) return true;
    }
    return false;
}

bool settings_discord_enabled(void) { return discord_url_ok(s_live.discord_webhook); }

static const char *validate(const settings_t *s)
{
    if (strlen(s->admin_password) < 8) return "admin password must be at least 8 characters";
    // Printable ASCII: browsers disagree on how Basic auth encodes anything else.
    if (!chars_ok(s->admin_password, 0x20, 0x7e))
                                       return "admin password must be printable ASCII";
    if (!s->wifi_ssid[0])              return "Wi-Fi SSID is empty";
    if (!chars_ok(s->wifi_ssid, 0x20, 0xff))
                                       return "Wi-Fi SSID has control characters";
    if (s->wifi_password[0] && strlen(s->wifi_password) < 8)
                                       return "Wi-Fi password must be 8+ characters";
    if (!chars_ok(s->wifi_password, 0x20, 0x7e))
                                       return "Wi-Fi password must be printable ASCII";
    // The token goes into a URL path and the chat id into a JSON string, unescaped.
    if (!alnum_ok(s->tg_token, ":_-")) return "Telegram token: letters, digits, : _ - only";
    if (!alnum_ok(s->tg_chat_id, "@_-"))
                                       return "Telegram chat id: letters, digits, @ _ - only";
    if (!s->tz[0])                     return "timezone is empty";
    if (!chars_ok(s->tz, 0x21, 0x7e))  return "timezone must be printable ASCII, no spaces";
    if (s->alarm_remind_s < 60 || s->alarm_remind_s > 3600)
                                       return "reminder interval must be 60-3600 s";
    if (s->alarm_quiet_s < 60 || s->alarm_quiet_s > 86400)
                                       return "quiet time must be 60-86400 s";
    if (s->brightness < 5 || s->brightness > 100)
                                       return "brightness must be 5-100 %";
    if (s->discord_webhook[0] && !discord_url_ok(s->discord_webhook))
        return "Discord webhook must be https://discord.com/api/webhooks/..., no spaces";
    return NULL;
}

esp_err_t settings_save(const settings_t *s, const char **err, bool *reboot_needed)
{
    const char *why = validate(s);
    if (why) { if (err) *err = why; return ESP_ERR_INVALID_ARG; }

    nvs_handle_t h;
    esp_err_t r = nvs_open(NS, NVS_READWRITE, &h);
    if (r != ESP_OK) { if (err) *err = "NVS open failed"; return r; }
    esp_err_t w = ESP_OK;
#define SET(call) do { esp_err_t e_ = (call); if (e_ != ESP_OK) w = e_; } while (0)
    SET(nvs_set_str(h, "admin_pw",   s->admin_password));
    SET(nvs_set_str(h, "tg_token",   s->tg_token));
    SET(nvs_set_str(h, "tg_chat",    s->tg_chat_id));
    SET(nvs_set_str(h, "tz",         s->tz));
    SET(nvs_set_u32(h, "remind_s",   s->alarm_remind_s));
    SET(nvs_set_u32(h, "quiet_s",    s->alarm_quiet_s));
    SET(nvs_set_u8(h,  "bright",     s->brightness));
    SET(nvs_set_u8(h,  "alarm_snd",  s->alarm_sound));
    SET(nvs_set_u8(h,  "boot_chirp", s->boot_chirp));
    SET(nvs_set_u8(h,  "click",      s->touch_click));
    SET(nvs_set_str(h, "dc_hook",    s->discord_webhook));
    SET(nvs_set_u8(h,  "dc_log",     s->discord_log_events));
    // Wi-Fi keys are written only when the Wi-Fi changes, so an untouched
    // config.h network stays "not overridden" (no boot fallback timer). Going
    // back to the config.h network erases them.
    if (strcmp(s->wifi_ssid, s_saved.wifi_ssid) || strcmp(s->wifi_password, s_saved.wifi_password)) {
        if (!strcmp(s->wifi_ssid, WIFI_SSID) && !strcmp(s->wifi_password, WIFI_PASSWORD)) {
            nvs_erase_key(h, "wifi_ssid");
            nvs_erase_key(h, "wifi_pw");
        } else {
            SET(nvs_set_str(h, "wifi_ssid", s->wifi_ssid));
            SET(nvs_set_str(h, "wifi_pw",   s->wifi_password));
        }
    }
#undef SET
    r = (w != ESP_OK) ? w : nvs_commit(h);
    nvs_close(h);
    if (r != ESP_OK) { if (err) *err = "NVS write failed"; return r; }

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_saved = *s;
    bool reboot = strcmp(s->wifi_ssid, s_live.wifi_ssid) ||
                  strcmp(s->wifi_password, s_live.wifi_password) ||
                  strcmp(s->tg_token, s_live.tg_token) ||
                  strcmp(s->tg_chat_id, s_live.tg_chat_id);
    // Wi-Fi and Telegram keep their running values until the reboot.
    settings_t next = *s;
    strlcpy(next.wifi_ssid, s_live.wifi_ssid, sizeof(next.wifi_ssid));
    strlcpy(next.wifi_password, s_live.wifi_password, sizeof(next.wifi_password));
    strlcpy(next.tg_token, s_live.tg_token, sizeof(next.tg_token));
    strlcpy(next.tg_chat_id, s_live.tg_chat_id, sizeof(next.tg_chat_id));
    s_live = next;
    memset(&next, 0, sizeof(next));
    xSemaphoreGive(s_mutex);
    if (reboot_needed) *reboot_needed = reboot;

    setenv("TZ", s->tz, 1);
    tzset();
    for (int i = 0; i < s_on_change_count; i++) s_on_change[i]();
    ESP_LOGI(TAG, "Saved%s", reboot ? " (reboot to apply Wi-Fi/Telegram)" : "");
    return ESP_OK;
}
