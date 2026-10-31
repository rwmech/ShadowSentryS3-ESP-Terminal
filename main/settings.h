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
 * brightness. Applied after a reboot: Wi-Fi, Telegram.
 *
 * Wi-Fi safety net: if saved Wi-Fi credentials don't get an IP within
 * SETTINGS_WIFI_FALLBACK_S at boot, the saved Wi-Fi keys are erased and the
 * board reboots onto the config.h network, so a typo can't strand it.
 */

#define SETTINGS_WIFI_FALLBACK_S   90
#define SETTINGS_ADMIN_ALLOW_MAX   8

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
    // Detection and alerting (applied immediately)
    uint32_t alert_mask;            // bit n set: attack_type_t n opens an incident; logging is always on
    uint32_t scan_ports;            // distinct ports from one source that make a port scan, 3..32
    uint32_t scan_window_s;         // ... within this many seconds, 2..300
    uint32_t arp_targets;           // distinct who-has targets from one MAC that make an ARP sweep, 3..32
    uint32_t arp_window_s;          // ... within this many seconds, 2..300
    uint32_t admin_allow[SETTINGS_ADMIN_ALLOW_MAX];  // IPv4, network order; SYNs to the admin
    uint8_t  admin_allow_n;         // ports from anyone else are dropped. 0 = open to all
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

// Register a callback run after every successful save (e.g. apply brightness).
void settings_on_change(void (*cb)(void));

// Empty the admin allowlist (admin ports open to all again), saved and live.
// The USB serial console's recovery command; see detect/detect.h.
esp_err_t settings_clear_admin_allow(void);

#ifdef __cplusplus
}
#endif
