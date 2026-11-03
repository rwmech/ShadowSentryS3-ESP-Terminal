#include "settings.h"
#include "esp_attr.h"
#include "config.h"
#include "log_store.h"        // ATTACK_DISCOVERY, ATTACK_TYPE_COUNT
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <ctype.h>
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
#ifndef DISPLAY_CLOCK_24H
#define DISPLAY_CLOCK_24H 0
#endif
#ifndef UI_VOLUME_DEFAULT
#define UI_VOLUME_DEFAULT 1
#endif
#ifndef ALARM_VOLUME_DEFAULT
#define ALARM_VOLUME_DEFAULT 3
#endif
#ifndef DISPLAY_PANEL_STYLE
#define DISPLAY_PANEL_STYLE 1
#endif
#ifndef DISPLAY_ROTATE_S
#define DISPLAY_ROTATE_S 30
#endif
#ifndef DISCORD_WEBHOOK_URL
#define DISCORD_WEBHOOK_URL ""
#endif
#ifndef DISCORD_MIN_TIER
#define DISCORD_MIN_TIER 2
#endif
// Detection defaults (main\detect\detect.c reads them live).
#define DET_SCAN_PORTS     5
#define DET_SCAN_WINDOW_S  10
#define DET_ARP_TARGETS    10
#define DET_ARP_WINDOW_S   10
// Alert switches. Every type opens an incident by default, except LAN
// discovery, which is background noise (logged, no incident), and a new
// device on the network (SEV3, logged, no incident; on Discord only when
// discord_min_tier is 3). Bits past the
// known types stay set, so a type added later alerts unless listed here.
#define ALERT_DEFAULT_OFF   ((1u << ATTACK_DISCOVERY) | (1u << ATTACK_NEW_DEVICE))
#define ALERT_MASK_DEFAULT  (0xFFFFFFFFu & ~ALERT_DEFAULT_OFF)
// A saved mask records how many types its firmware knew (NVS "alert_known").
// Bits from there up were set by the rule above, not by a choice, so on load
// they take this firmware's default. A mask saved before the key existed
// knew the 13 types before ATTACK_DISCOVERY.
#define ALERT_KNOWN_LEGACY  ATTACK_DISCOVERY
_Static_assert(ATTACK_TYPE_COUNT <= 32, "alert_mask has a bit per type");
#ifndef WHATSAPP_PHONE
#define WHATSAPP_PHONE ""
#endif
#ifndef WHATSAPP_APIKEY
#define WHATSAPP_APIKEY ""
#endif
// Pi-hole (main/admin/pihole.h): off unless an app password is configured.
#ifndef PIHOLE_URL
#define PIHOLE_URL "http://ph.local"
#endif
#ifndef PIHOLE_APP_PASSWORD
#define PIHOLE_APP_PASSWORD ""
#endif
#ifndef PIHOLE_ENABLE
#define PIHOLE_ENABLE (sizeof(PIHOLE_APP_PASSWORD) > 1 && sizeof(PIHOLE_URL) > 1)
#endif
_Static_assert(sizeof(PIHOLE_URL) <= 96, "PIHOLE_URL must be at most 95 characters");
_Static_assert(sizeof(PIHOLE_APP_PASSWORD) <= 129, "PIHOLE_APP_PASSWORD must be at most 128 characters");
_Static_assert((PIHOLE_ENABLE) == 0 || (PIHOLE_ENABLE) == 1, "PIHOLE_ENABLE must be 0 or 1");
#ifndef MIKROTIK_URL
#define MIKROTIK_URL ""
#endif
#ifndef MIKROTIK_USER
#define MIKROTIK_USER ""
#endif
#ifndef MIKROTIK_PASSWORD
#define MIKROTIK_PASSWORD ""
#endif
#ifndef MIKROTIK_CERT_SHA256
#define MIKROTIK_CERT_SHA256 ""
#endif
#ifndef ROUTER_DNS_REDIRECT
#define ROUTER_DNS_REDIRECT 1
#endif
_Static_assert((ROUTER_DNS_REDIRECT) == 0 || (ROUTER_DNS_REDIRECT) == 1, "ROUTER_DNS_REDIRECT must be 0 or 1");

// Both copies in PSRAM (EXT_RAM_BSS_ATTR, a no-op without
// CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY): 1.1 KB each, read by tasks only.
EXT_RAM_BSS_ATTR static settings_t s_live;     // what is running now
EXT_RAM_BSS_ATTR static settings_t s_saved;    // what NVS holds: the next boot runs this
static SemaphoreHandle_t s_mutex;
static bool              s_wifi_overridden = false;
static bool              s_wa_at_boot;   // WhatsApp configured at boot: its task runs only then
static void            (*s_on_change[4])(void);
static bool wa_ok(const settings_t *s);
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
    s->ui_volume      = UI_VOLUME_DEFAULT;
    s->alarm_volume   = ALARM_VOLUME_DEFAULT;
    s->clock_24h      = DISPLAY_CLOCK_24H != 0;
    s->panel_style    = DISPLAY_PANEL_STYLE;
    s->panel_rotate_s = DISPLAY_ROTATE_S;
    strlcpy(s->discord_webhook, DISCORD_WEBHOOK_URL, sizeof(s->discord_webhook));
    s->discord_log_events = true;
    s->discord_min_tier   = DISCORD_MIN_TIER;
    // Detection: every type alerts except discovery (ALERT_MASK_DEFAULT),
    // thresholds, admin ports open.
    s->alert_mask     = ALERT_MASK_DEFAULT;
    s->scan_ports     = DET_SCAN_PORTS;
    s->scan_window_s  = DET_SCAN_WINDOW_S;
    s->arp_targets    = DET_ARP_TARGETS;
    s->arp_window_s   = DET_ARP_WINDOW_S;
    s->admin_allow_n  = 0;
    strlcpy(s->whatsapp_phone, WHATSAPP_PHONE, sizeof(s->whatsapp_phone));
    strlcpy(s->whatsapp_apikey, WHATSAPP_APIKEY, sizeof(s->whatsapp_apikey));
    strlcpy(s->pihole_url, PIHOLE_URL, sizeof(s->pihole_url));
    strlcpy(s->pihole_password, PIHOLE_APP_PASSWORD, sizeof(s->pihole_password));
    s->pihole_enabled = (PIHOLE_ENABLE) != 0;
    strlcpy(s->mikrotik_url, MIKROTIK_URL, sizeof(s->mikrotik_url));
    strlcpy(s->mikrotik_user, MIKROTIK_USER, sizeof(s->mikrotik_user));
    strlcpy(s->mikrotik_password, MIKROTIK_PASSWORD, sizeof(s->mikrotik_password));
    if (!settings_sha256_norm(MIKROTIK_CERT_SHA256, s->mikrotik_cert_sha256)) s->mikrotik_cert_sha256[0] = 0;
    s->mikrotik_enabled = true;
    s->router_dns_redirect = (ROUTER_DNS_REDIRECT) != 0;
}

static void get_str(nvs_handle_t h, const char *key, char *dst, size_t len)
{
    size_t n = len;
    char tmp[168];                  // longest field: discord_webhook[160] (pihole_password 129)
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

static void get_u16(nvs_handle_t h, const char *key, uint16_t *dst)
{
    uint16_t v;
    if (nvs_get_u16(h, key, &v) == ESP_OK) *dst = v;
}

static void get_bool(nvs_handle_t h, const char *key, bool *dst)
{
    uint8_t v;
    if (nvs_get_u8(h, key, &v) == ESP_OK) *dst = v != 0;
}

// The admin allowlist: a blob of 0..SETTINGS_ADMIN_ALLOW_MAX IPv4s. Anything
// else in NVS (wrong size, a zero address) is ignored: admin ports stay open.
static void get_allow(nvs_handle_t h, settings_t *s)
{
    uint32_t ips[SETTINGS_ADMIN_ALLOW_MAX];
    size_t n = sizeof(ips);
    if (nvs_get_blob(h, "admin_allow", ips, &n) != ESP_OK || n % 4) return;
    for (size_t i = 0; i < n / 4; i++) if (!ips[i]) return;
    memcpy(s->admin_allow, ips, n);
    s->admin_allow_n = (uint8_t)(n / 4);
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
        get_u8(h, "ui_vol", &s_live.ui_volume);
        get_u8(h, "al_vol", &s_live.alarm_volume);
        get_bool(h, "clock24", &s_live.clock_24h);
        get_u8(h, "panel", &s_live.panel_style);
        get_u16(h, "rot_s", &s_live.panel_rotate_s);
        if (s_live.panel_rotate_s < 10 || s_live.panel_rotate_s > 600) s_live.panel_rotate_s = DISPLAY_ROTATE_S;
        get_str(h, "dc_hook", s_live.discord_webhook, sizeof(s_live.discord_webhook));
        get_bool(h, "dc_log", &s_live.discord_log_events);
        get_u8(h, "dc_tier", &s_live.discord_min_tier);
        if (s_live.discord_min_tier < 1 || s_live.discord_min_tier > 3) s_live.discord_min_tier = DISCORD_MIN_TIER;
        get_u32(h, "alert_mask", &s_live.alert_mask);
        uint8_t known = ALERT_KNOWN_LEGACY;
        get_u8(h, "alert_known", &known);
        if (known < 32) {               // types newer than the saved mask: default
            uint32_t newer = ~((1u << known) - 1u);
            s_live.alert_mask = (s_live.alert_mask & ~newer) | (ALERT_MASK_DEFAULT & newer);
        }
        get_u32(h, "scan_ports", &s_live.scan_ports);
        get_u32(h, "scan_win_s", &s_live.scan_window_s);
        get_u32(h, "arp_targets", &s_live.arp_targets);
        get_u32(h, "arp_win_s", &s_live.arp_window_s);
        get_allow(h, &s_live);
        get_str(h, "wa_phone", s_live.whatsapp_phone, sizeof(s_live.whatsapp_phone));
        get_str(h, "wa_key", s_live.whatsapp_apikey, sizeof(s_live.whatsapp_apikey));
        get_str(h, "ph_url", s_live.pihole_url, sizeof(s_live.pihole_url));
        get_str(h, "ph_pw", s_live.pihole_password, sizeof(s_live.pihole_password));
        get_str(h, "ph_pin", s_live.pihole_tls_sha256, sizeof(s_live.pihole_tls_sha256));
        get_bool(h, "ph_on", &s_live.pihole_enabled);
        get_str(h, "mt_url", s_live.mikrotik_url, sizeof(s_live.mikrotik_url));
        get_str(h, "mt_user", s_live.mikrotik_user, sizeof(s_live.mikrotik_user));
        get_str(h, "mt_pw", s_live.mikrotik_password, sizeof(s_live.mikrotik_password));
        get_str(h, "mt_pin", s_live.mikrotik_cert_sha256, sizeof(s_live.mikrotik_cert_sha256));
        get_bool(h, "mt_on", &s_live.mikrotik_enabled);
        get_bool(h, "rt_dnsred", &s_live.router_dns_redirect);
        nvs_close(h);
    }
    s_saved = s_live;
    s_wa_at_boot = wa_ok(&s_live);
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
             strcmp(s_saved.tg_chat_id, s_live.tg_chat_id) ||
             (wa_ok(&s_saved) && !s_wa_at_boot);     // WhatsApp's task starts only at boot
    xSemaphoreGive(s_mutex);
    return p;
}

void settings_on_change(void (*cb)(void))
{
    if (cb && s_on_change_count < 4) s_on_change[s_on_change_count++] = cb;
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

// +<country code><number>: an optional '+', then 7 to 15 digits (E.164).
static bool whatsapp_phone_ok(const char *p)
{
    if (*p == '+') p++;
    size_t n = strlen(p);
    return n >= 7 && n <= 15 && strspn(p, "0123456789") == n;
}

static bool wa_ok(const settings_t *s)
{
    return whatsapp_phone_ok(s->whatsapp_phone) && s->whatsapp_apikey[0] &&
           alnum_ok(s->whatsapp_apikey, "");
}

bool settings_whatsapp_enabled(void)
{
    return wa_ok(&s_live);
}

bool settings_pihole_url_parse(const char *u, bool *https, char *host, size_t host_cap, uint16_t *port)
{
    bool tls;
    if (!strncmp(u, "http://", 7))       { tls = false; u += 7; }
    else if (!strncmp(u, "https://", 8)) { tls = true;  u += 8; }
    else return false;
    size_t n = strspn(u, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-");
    if (n == 0 || n > 63 || u[0] == '.' || u[0] == '-' || u[n - 1] == '.' || u[n - 1] == '-') return false;
    for (size_t i = 1; i < n; i++) if (u[i] == '.' && u[i - 1] == '.') return false;
    const char *h = u;
    u += n;
    unsigned long p = tls ? 443 : 80;
    if (*u == ':') {
        u++;
        size_t d = strspn(u, "0123456789");
        if (d == 0 || d > 5) return false;
        p = strtoul(u, NULL, 10);
        if (p == 0 || p > 65535) return false;
        u += d;
    }
    if (*u == '/') u++;
    if (*u) return false;                       // a path, query or anything else
    if (https) *https = tls;
    if (port) *port = (uint16_t)p;
    if (host) {
        if (host_cap <= n) return false;
        memcpy(host, h, n);
        host[n] = '\0';
    }
    return true;
}

static bool pihole_ok(const settings_t *s)
{
    return s->pihole_enabled && s->pihole_password[0] &&
           settings_pihole_url_parse(s->pihole_url, NULL, NULL, 0, NULL);
}

bool settings_pihole_enabled(void) { return pihole_ok(&s_live); }
// "" or http(s)://host[:port] with an optional trailing '/': no path, no
// user info. Host: letters, digits, '.', '-', or an [IPv6] literal. The
// client appends /rest/..., so nothing else may follow.
static bool mikrotik_url_ok(const char *u)
{
    if (!u[0]) return true;
    const char *h;
    if (!strncmp(u, "http://", 7)) h = u + 7;
    else if (!strncmp(u, "https://", 8)) h = u + 8;
    else return false;
    size_t n = 0;
    if (h[0] == '[') {
        n = 1;
        while (h[n] && (isxdigit((unsigned char)h[n]) || h[n] == ':' || h[n] == '.')) n++;
        if (h[n] != ']' || n < 3) return false;
        n++;
    } else {
        while (h[n] && (isalnum((unsigned char)h[n]) || h[n] == '.' || h[n] == '-')) n++;
        if (!n) return false;
    }
    const char *p = h + n;
    if (*p == ':') {
        p++;
        size_t d = strspn(p, "0123456789");
        if (d < 1 || d > 5 || atoi(p) < 1 || atoi(p) > 65535) return false;
        p += d;
    }
    if (*p == '/') p++;
    return *p == '\0';
}

// "" or exactly 64 lowercase hex digits (api_ext.c normalises the input).
static bool sha256_hex_ok(const char *s)
{
    if (!s[0]) return true;
    if (strlen(s) != 64) return false;
    for (; *s; s++) if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f'))) return false;
    return true;
}

bool settings_sha256_norm(const char *in, char out[65])
{
    size_t n = 0;
    for (; *in; in++) {
        char c = *in;
        if (c == ':' || c == ' ' || c == '-') continue;
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) || n >= 64) { out[0] = 0; return false; }
        out[n++] = c;
    }
    out[n] = 0;
    if (n && n != 64) { out[0] = 0; return false; }
    return true;
}

bool settings_mikrotik_enabled(void)
{
    return s_live.mikrotik_enabled && s_live.mikrotik_url[0] && mikrotik_url_ok(s_live.mikrotik_url) &&
           s_live.mikrotik_user[0] && s_live.mikrotik_password[0];
}

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
    if (s->ui_volume > 3)              return "UI sound volume must be 0-3 (off, low, medium, high)";
    if (s->alarm_volume < 1 || s->alarm_volume > 3)
                                       return "alarm volume must be 1-3 (low, medium, high)";
    if (s->panel_style > 1)            return "panel_style must be 0 (dashboard) or 1 (LCARS)";
    if (s->panel_rotate_s < 10 || s->panel_rotate_s > 600)
                                       return "page rotation must be 10-600 s";
    if (s->discord_webhook[0] && !discord_url_ok(s->discord_webhook))
        return "Discord webhook must be https://discord.com/api/webhooks/..., no spaces";
    if (s->discord_min_tier < 1 || s->discord_min_tier > 3)
                                       return "Discord tiers must be 1 (SEV1), 2 (SEV1 and SEV2) or 3 (all)";
    if (s->scan_ports < 3 || s->scan_ports > 32)
                                       return "port scan threshold must be 3-32 ports";
    if (s->scan_window_s < 2 || s->scan_window_s > 300)
                                       return "port scan window must be 2-300 s";
    if (s->arp_targets < 3 || s->arp_targets > 32)
                                       return "ARP sweep threshold must be 3-32 hosts";
    if (s->arp_window_s < 2 || s->arp_window_s > 300)
                                       return "ARP sweep window must be 2-300 s";
    if (s->admin_allow_n > SETTINGS_ADMIN_ALLOW_MAX)
                                       return "admin allowlist holds at most 8 addresses";
    for (int i = 0; i < s->admin_allow_n; i++) {
        uint8_t b0 = (uint8_t)(s->admin_allow[i] & 0xff);            // network order
        if (!s->admin_allow[i] || s->admin_allow[i] == 0xFFFFFFFFu || b0 == 127 || b0 >= 224)
                                       return "admin allowlist: unicast IPv4 addresses only";
    }
    if (s->whatsapp_phone[0] && !whatsapp_phone_ok(s->whatsapp_phone))
        return "WhatsApp phone: + and 7-15 digits, country code first, no spaces";
    if (!alnum_ok(s->whatsapp_apikey, ""))
                                       return "WhatsApp apikey: letters and digits only";
    if (s->pihole_url[0] && !settings_pihole_url_parse(s->pihole_url, NULL, NULL, 0, NULL))
        return "Pi-hole URL must be http://host or https://host, optionally :port, no path";
    // Printable ASCII without spaces: v6 app passwords are base64 (+ / =).
    if (!chars_ok(s->pihole_password, 0x21, 0x7e))
                                       return "Pi-hole password must be printable ASCII, no spaces";
    if (s->pihole_tls_sha256[0] &&
        (strlen(s->pihole_tls_sha256) != 64 || strspn(s->pihole_tls_sha256, "0123456789abcdef") != 64))
        return "Pi-hole certificate SHA-256 must be 64 hex digits";
    if (s->pihole_enabled && (!s->pihole_url[0] || !s->pihole_password[0]))
        return "Pi-hole needs a URL and an app password before it can be turned on";
    if (!mikrotik_url_ok(s->mikrotik_url))
        return "MikroTik URL: http://host[:port] or https://host[:port], no path";
    // Basic auth: the user can't hold ':', and both go into a header.
    if (!chars_ok(s->mikrotik_user, 0x20, 0x7e) || strchr(s->mikrotik_user, ':'))
        return "MikroTik user: printable ASCII, no ':'";
    if (!chars_ok(s->mikrotik_password, 0x20, 0x7e))
        return "MikroTik password must be printable ASCII";
    if (!sha256_hex_ok(s->mikrotik_cert_sha256))
        return "MikroTik certificate pin: 64 hex digits (SHA-256), or empty";
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
    SET(nvs_set_u8(h,  "ui_vol",     s->ui_volume));
    SET(nvs_set_u8(h,  "al_vol",     s->alarm_volume));
    SET(nvs_set_u8(h,  "clock24",    s->clock_24h));
    SET(nvs_set_u8(h,  "panel",      s->panel_style));
    SET(nvs_set_u16(h, "rot_s",      s->panel_rotate_s));
    SET(nvs_set_str(h, "dc_hook",    s->discord_webhook));
    SET(nvs_set_u8(h,  "dc_log",     s->discord_log_events));
    SET(nvs_set_u8(h,  "dc_tier",    s->discord_min_tier));
    SET(nvs_set_u32(h, "alert_mask", s->alert_mask));
    SET(nvs_set_u8(h,  "alert_known", ATTACK_TYPE_COUNT));
    SET(nvs_set_u32(h, "scan_ports", s->scan_ports));
    SET(nvs_set_u32(h, "scan_win_s", s->scan_window_s));
    SET(nvs_set_u32(h, "arp_targets", s->arp_targets));
    SET(nvs_set_u32(h, "arp_win_s",  s->arp_window_s));
    if (s->admin_allow_n) SET(nvs_set_blob(h, "admin_allow", s->admin_allow, s->admin_allow_n * 4u));
    else nvs_erase_key(h, "admin_allow");
    SET(nvs_set_str(h, "wa_phone",   s->whatsapp_phone));
    SET(nvs_set_str(h, "wa_key",     s->whatsapp_apikey));
    SET(nvs_set_str(h, "ph_url",     s->pihole_url));
    SET(nvs_set_str(h, "ph_pw",      s->pihole_password));
    SET(nvs_set_str(h, "ph_pin",     s->pihole_tls_sha256));
    SET(nvs_set_u8(h,  "ph_on",      s->pihole_enabled));
    SET(nvs_set_str(h, "mt_url",     s->mikrotik_url));
    SET(nvs_set_str(h, "mt_user",    s->mikrotik_user));
    SET(nvs_set_str(h, "mt_pw",      s->mikrotik_password));
    SET(nvs_set_str(h, "mt_pin",     s->mikrotik_cert_sha256));
    SET(nvs_set_u8(h,  "mt_on",      s->mikrotik_enabled));
    SET(nvs_set_u8(h,  "rt_dnsred",  s->router_dns_redirect));
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
                  strcmp(s->tg_chat_id, s_live.tg_chat_id) ||
                  (wa_ok(s) && !s_wa_at_boot);       // WhatsApp's task starts only at boot
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

esp_err_t settings_clear_admin_allow(void)
{
    nvs_handle_t h;
    esp_err_t r = nvs_open(NS, NVS_READWRITE, &h);
    if (r != ESP_OK) return r;
    r = nvs_erase_key(h, "admin_allow");
    if (r == ESP_ERR_NVS_NOT_FOUND) r = ESP_OK;
    if (r == ESP_OK) r = nvs_commit(h);
    nvs_close(h);
    if (r != ESP_OK) return r;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_live.admin_allow_n  = 0;
    s_saved.admin_allow_n = 0;
    memset(s_live.admin_allow, 0, sizeof(s_live.admin_allow));
    memset(s_saved.admin_allow, 0, sizeof(s_saved.admin_allow));
    xSemaphoreGive(s_mutex);
    for (int i = 0; i < s_on_change_count; i++) s_on_change[i]();
    ESP_LOGW(TAG, "Admin allowlist cleared: admin ports open to all");
    return ESP_OK;
}
