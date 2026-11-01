// Wi-Fi re-roam on a weak link, and the link state for /api/status. See
// wifi_roam.h. Fork addition, Robert Mech.

#include "wifi_roam.h"
#include "wifi_manager.h"
#include "json_esc.h"
#include "sd_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "WIFI-ROAM";

#define POLL_MS         5000
#define SCAN_MAX        16              // AP records read back from a scan

static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;
static int64_t           s_self_until;  // esp_timer: disconnects before this are ours
static bool              s_self_first;  // the roam's own disconnect is still to come
static bool              s_pinned;      // the STA config holds a BSSID and channel
static uint8_t           s_target[6];   // BSSID we roamed to, for the log
static volatile uint32_t s_roams;

// ── Config pin ────────────────────────────────────────────────────────────────

static esp_err_t set_pin(const uint8_t *bssid, uint8_t channel)
{
    wifi_config_t cfg;
    esp_err_t err = esp_wifi_get_config(WIFI_IF_STA, &cfg);
    if (err != ESP_OK) return err;
    cfg.sta.bssid_set = bssid != NULL;
    if (bssid) memcpy(cfg.sta.bssid, bssid, 6);
    else memset(cfg.sta.bssid, 0, 6);
    cfg.sta.channel = bssid ? channel : 0;
    return esp_wifi_set_config(WIFI_IF_STA, &cfg);
}

bool wifi_roam_note_disconnect(void)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_mux);
    bool self  = s_self_until && now < s_self_until;
    bool first = s_self_first;
    s_self_first = false;
    bool unpin = s_pinned && !first;
    if (unpin) s_pinned = false;
    portEXIT_CRITICAL(&s_mux);
    // Event loop task. The config storage is RAM, so no NVS write here.
    if (unpin) {
        esp_err_t err = set_pin(NULL, 0);
        ESP_LOGI(TAG, "BSSID pin dropped (%s): reconnecting to the strongest AP", esp_err_to_name(err));
    }
    return self;
}

void wifi_roam_link(wifi_link_t *out)
{
    memset(out, 0, sizeof(*out));
    out->roams = s_roams;
    wifi_ap_record_t ap;
    if (!wifi_manager_is_connected() || esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return;
    out->up = true;
    memcpy(out->ssid, ap.ssid, sizeof(out->ssid) - 1);
    out->ssid[sizeof(out->ssid) - 1] = '\0';
    memcpy(out->bssid, ap.bssid, 6);
    out->channel = ap.primary;
    out->rssi = ap.rssi;
}

// ── Logging ───────────────────────────────────────────────────────────────────

static void mac_str(const uint8_t m[6], char *out, size_t n)
{
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// A BSSID change: console and {"kind":"wifi","event":"roam",...} on the card.
static void log_roam(const char *ssid, const uint8_t from[6], int from_rssi,
                     const uint8_t to[6], int to_rssi, int channel, const char *by)
{
    char f[18], t[18], esc[100];
    mac_str(from, f, sizeof(f));
    mac_str(to, t, sizeof(t));
    ESP_LOGW(TAG, "Roam %lu (%s): %s %d dBm -> %s %d dBm, channel %d",
             (unsigned long)s_roams, by, f, from_rssi, t, to_rssi, channel);
    json_esc(ssid, 32, esc, sizeof(esc));
    char *line = heap_caps_malloc(320, MALLOC_CAP_SPIRAM);
    if (!line) return;
    int n = snprintf(line, 320,
        "{\"kind\":\"wifi\",\"ts\":%lu,\"event\":\"roam\",\"by\":\"%s\",\"ssid\":\"%s\","
        "\"from\":\"%s\",\"from_rssi\":%d,\"to\":\"%s\",\"rssi\":%d,\"channel\":%d,\"roams\":%lu}\n",
        (unsigned long)time(NULL), by, esc, f, from_rssi, t, to_rssi, channel, (unsigned long)s_roams);
    if (n > 0 && n < 320) sd_log_line(line, (size_t)n);     // frees it
    else free(line);
}

// ── Scan and roam ─────────────────────────────────────────────────────────────

static void try_roam(const wifi_ap_record_t *cur)
{
    wifi_scan_config_t sc = {
        .ssid        = (uint8_t *)cur->ssid,
        .show_hidden = false,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = { .min = 0, .max = 120 },
    };
    // Promiscuous mode (the Wi-Fi threat monitor) is paused for the scan's
    // couple of seconds, so the two never share the radio.
    bool prom = false;
    esp_wifi_get_promiscuous(&prom);
    if (prom) esp_wifi_set_promiscuous(false);
    esp_err_t err = esp_wifi_scan_start(&sc, true);
    if (prom) esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        esp_wifi_clear_ap_list();
        ESP_LOGW(TAG, "Scan failed: %s", esp_err_to_name(err));
        return;
    }

    wifi_ap_record_t *recs = heap_caps_malloc(SCAN_MAX * sizeof(*recs), MALLOC_CAP_SPIRAM);
    uint16_t n = recs ? SCAN_MAX : 0;
    if (!recs || esp_wifi_scan_get_ap_records(&n, recs) != ESP_OK) {
        esp_wifi_clear_ap_list();
        free(recs);
        return;
    }
    const wifi_ap_record_t *best = NULL;
    for (int i = 0; i < n; i++) {
        if (strncmp((const char *)recs[i].ssid, (const char *)cur->ssid, sizeof(cur->ssid))) continue;
        if (!memcmp(recs[i].bssid, cur->bssid, 6)) continue;
        if (!best || recs[i].rssi > best->rssi) best = &recs[i];
    }
    char b[18];
    if (!best || best->rssi < cur->rssi + WIFI_ROAM_GAIN_DB) {
        if (best) mac_str(best->bssid, b, sizeof(b));
        ESP_LOGI(TAG, "Weak link (%d dBm), %d APs seen; best other %s %d dBm, not %d dB better: staying",
                 cur->rssi, n, best ? b : "none", best ? best->rssi : 0, WIFI_ROAM_GAIN_DB);
        free(recs);
        return;
    }

    mac_str(best->bssid, b, sizeof(b));
    ESP_LOGW(TAG, "Roaming: %d dBm here, %s %d dBm on channel %d", cur->rssi, b, best->rssi, best->primary);
    portENTER_CRITICAL(&s_mux);
    s_self_until = esp_timer_get_time() + WIFI_ROAM_SELF_S * 1000000LL;
    s_self_first = true;
    s_pinned     = true;
    memcpy(s_target, best->bssid, 6);
    portEXIT_CRITICAL(&s_mux);
    err = set_pin(best->bssid, best->primary);
    if (err == ESP_OK) err = esp_wifi_disconnect();   // wifi_manager reconnects, to the pin
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Roam not started: %s", esp_err_to_name(err));
        portENTER_CRITICAL(&s_mux);
        s_self_first = false;
        s_pinned     = false;
        portEXIT_CRITICAL(&s_mux);
        set_pin(NULL, 0);
    }
    free(recs);
}

void wifi_roam_task(void *arg)
{
    (void)arg;
#if !WIFI_ROAM_ENABLE
    ESP_LOGI(TAG, "Re-roam disabled (WIFI_ROAM_ENABLE 0)");
    vTaskDelete(NULL);
#else
    ESP_LOGI(TAG, "Re-roam on: below %d dBm for %d s, a BSSID %d dB stronger, at most every %d s",
             WIFI_ROAM_RSSI_DBM, WIFI_ROAM_LOW_S, WIFI_ROAM_GAIN_DB, WIFI_ROAM_INTERVAL_S);
    uint8_t last[6] = {0};
    int     last_rssi = 0;
    int64_t low_since = 0, last_try = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        wifi_ap_record_t ap;
        if (!wifi_manager_is_connected() || esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
            low_since = 0;
            continue;
        }
        static const uint8_t zero[6] = {0};
        if (memcmp(last, zero, 6) && memcmp(last, ap.bssid, 6)) {
            portENTER_CRITICAL(&s_mux);
            bool ours = !memcmp(s_target, ap.bssid, 6);
            memset(s_target, 0, 6);
            portEXIT_CRITICAL(&s_mux);
            s_roams++;
            log_roam((const char *)ap.ssid, last, last_rssi, ap.bssid, ap.rssi, ap.primary,
                     ours ? "rssi" : "other");
        }
        memcpy(last, ap.bssid, 6);
        last_rssi = ap.rssi;

        int64_t now = esp_timer_get_time();
        if (ap.rssi >= WIFI_ROAM_RSSI_DBM) { low_since = 0; continue; }
        if (!low_since) low_since = now;
        if (now - low_since < WIFI_ROAM_LOW_S * 1000000LL) continue;
        if (last_try && now - last_try < WIFI_ROAM_INTERVAL_S * 1000000LL) continue;
        last_try = now;
        try_roam(&ap);
    }
#endif
}
