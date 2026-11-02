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
 * Applied immediately: admin password, timezone, panel clock format, alarm
 * timings, sounds, brightness, Discord, WhatsApp, Pi-hole, MikroTik. Applied after a reboot: Wi-Fi,
 * Telegram.
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
    uint8_t  ui_volume;             // chirps and boot beeps: 0 off, 1 low, 2 medium, 3 high
    uint8_t  alarm_volume;          // klaxon and yellow call: 1 low, 2 medium, 3 high (never off)
    bool     clock_24h;             // panel times: 24-hour "15:39:12", else 12-hour "3:39 PM"
    uint8_t  panel_style;           // front panel: 0 dashboard, 1 LCARS (live, no reboot)
    char     discord_webhook[160];  // secret: "" = off, else https://discord.com/api/webhooks/...
    bool     discord_log_events;    // deduplicated event log to Discord (incidents post regardless)
    uint8_t  discord_min_tier;      // Discord posts SEV1..this: 1 SEV1, 2 SEV1 and SEV2, 3 every tier
    // Detection and alerting (applied immediately)
    uint32_t alert_mask;            // bit n set: attack_type_t n opens an incident; logging is always on.
                                    // Default all on except ATTACK_DISCOVERY (settings.c)
    uint32_t scan_ports;            // distinct ports from one source that make a port scan, 3..32
    uint32_t scan_window_s;         // ... within this many seconds, 2..300
    uint32_t arp_targets;           // distinct who-has targets from one MAC that make an ARP sweep, 3..32
    uint32_t arp_window_s;          // ... within this many seconds, 2..300
    uint32_t admin_allow[SETTINGS_ADMIN_ALLOW_MAX];  // IPv4, network order; SYNs to the admin
    uint8_t  admin_allow_n;         // ports from anyone else are dropped. 0 = open to all
    char     whatsapp_phone[20];    // CallMeBot: "" = off, else +<country code><number>
    char     whatsapp_apikey[33];   // secret: CallMeBot apikey, letters and digits
    // Pi-hole v6, read only (main/admin/pihole.h). Applied immediately.
    char     pihole_url[96];        // "" or http(s)://host[:port], no path ("/admin" is stripped)
    char     pihole_password[129];  // secret: an app password, printable ASCII, no spaces
    char     pihole_tls_sha256[65]; // https only: the certificate's SHA-256, 64 lowercase hex digits
    bool     pihole_enabled;        // needs a URL and a password
    // MikroTik router, read only (admin/mikrotik.c)
    char     mikrotik_url[96];      // "" = off, else http://host[:port] or https://host[:port], no path
    char     mikrotik_user[33];     // REST user, printable ASCII, no ':'
    char     mikrotik_password[65]; // secret
    char     mikrotik_cert_sha256[65]; // "" or 64 lowercase hex: the pinned certificate (https only)
    bool     mikrotik_enabled;      // the switch; on only when URL, user and password are set too
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

// WhatsApp (CallMeBot) is configured: a phone number and an apikey.
bool settings_whatsapp_enabled(void);

// Pi-hole is switched on, with a well-formed URL and a password.
bool settings_pihole_enabled(void);

// Split a Pi-hole URL: http:// or https://, a host (letters, digits, '.' and
// '-', at most 63), an optional :port (1-65535), an optional trailing '/' and
// nothing else. False if it is not of that form. host may be NULL.
bool settings_pihole_url_parse(const char *u, bool *https, char *host, size_t host_cap, uint16_t *port);
// MikroTik is configured and switched on: a valid URL, a user, a password.
bool settings_mikrotik_enabled(void);

// A SHA-256 fingerprint as typed (any case; ':', '-' and spaces ignored) into
// out as 64 lowercase hex digits. "" stays "". False, and out "", otherwise.
bool settings_sha256_norm(const char *in, char out[65]);

// Register a callback run after every successful save (e.g. apply brightness).
void settings_on_change(void (*cb)(void));

// Empty the admin allowlist (admin ports open to all again), saved and live.
// The USB serial console's recovery command; see detect/detect.h.
esp_err_t settings_clear_admin_allow(void);

#ifdef __cplusplus
}
#endif
