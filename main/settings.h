#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runtime settings, editable from the dashboard's Settings page.
 *
 * config.h supplies the first-boot defaults; anything saved from the web lives
 * in NVS (namespace "settings", one key per field so adding a field never wipes
 * the others) and survives OTA updates.
 *
 * Applied immediately: admin password, timezone, alarm timings, sounds,
 * brightness, Discord. Applied after a reboot: Wi-Fi, Telegram.
 *
 * Wi-Fi safety net: if saved Wi-Fi credentials don't get an IP within
 * SETTINGS_WIFI_FALLBACK_S at boot, the saved Wi-Fi keys are erased and the
 * board reboots onto the config.h network, so a typo can't strand it.
 */

#define SETTINGS_WIFI_FALLBACK_S   90

typedef struct {
    char     admin_password[64];
    char     wifi_ssid[33];
    char     wifi_password[65];
    char     tg_token[64];
    char     tg_chat_id[24];
    char     tz[48];                // POSIX TZ string
    uint32_t alarm_remind_s;        // reminder beep interval, 60..3600
    uint32_t alarm_quiet_s;         // quiet time that closes an acked incident, 60..86400
    uint8_t  brightness;            // backlight %, 5..100
    bool     alarm_sound;           // incident alarm + reminders on the buzzer
    bool     boot_chirp;            // chirp at power-up / reboot
    bool     touch_click;           // click on every screen press
    char     discord_webhook[160];  // secret: "" = off, else https://discord.com/api/webhooks/...
    bool     discord_log_events;    // deduplicated event log to Discord (incidents post regardless)
} settings_t;

// Load defaults, then NVS overrides. Call once, after nvs_flash_init().
void settings_init(void);

// Live settings. Scalars may be read directly from any task; take a copy with
// settings_copy() before using the strings, which can change under a save.
const settings_t *settings_get(void);
void settings_copy(settings_t *out);

// What NVS holds, i.e. what the next boot runs. Differs from the live copy only
// in Wi-Fi and Telegram, after a save that needs a reboot. Start an edit from
// this copy, so a second save before the reboot keeps the first one's changes.
void settings_copy_saved(settings_t *out);

// A saved Wi-Fi or Telegram change is waiting for a reboot.
bool settings_reboot_pending(void);

// Validate, persist and apply. On a validation failure nothing is changed and
// err (if non-NULL) names the problem. Sets *reboot_needed when the saved Wi-Fi
// or Telegram differs from the running one, so a reboot is needed to apply it.
esp_err_t settings_save(const settings_t *s, const char **err, bool *reboot_needed);

// True when saved (NVS) Wi-Fi credentials override config.h.
bool settings_wifi_overridden(void);

// Drop saved Wi-Fi credentials (back to config.h). Used by the boot fallback.
void settings_forget_wifi(void);

// Telegram is configured (non-empty, non-placeholder token and chat id).
bool settings_telegram_enabled(void);

// Discord is configured (a well-formed webhook URL).
bool settings_discord_enabled(void);

// Register a callback run after every successful save (e.g. apply brightness).
void settings_on_change(void (*cb)(void));

#ifdef __cplusplus
}
#endif
