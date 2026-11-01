#pragma once
#include <stdbool.h>
#include <stdint.h>

/*
 * Wi-Fi roaming (fork, 2026-11-01)
 *
 * wifi_manager.c joins the strongest AP for the SSID (all-channel scan,
 * sorted by signal) and, with CONFIG_ESP_WIFI_11KV_SUPPORT, lets the AP
 * steer it (802.11k radio measurement and 802.11v BSS transition). This
 * module adds a re-roam for a station that stays on a weak AP: when the
 * RSSI stays below WIFI_ROAM_RSSI_DBM for WIFI_ROAM_LOW_S, it scans for the
 * SSID, and if another BSSID is at least WIFI_ROAM_GAIN_DB stronger it pins
 * that BSSID and channel in the STA config and disconnects; wifi_manager's
 * handler reconnects as usual. At most one scan and roam every
 * WIFI_ROAM_INTERVAL_S. The pin is dropped at the next disconnect after the
 * roam's own, so a failed roam or a later drop goes back to "strongest AP".
 *
 * The Wi-Fi threat monitor counts a disconnect as a deauth attack by its
 * reason code. A roam's own disconnect (reason 8, ASSOC_LEAVE, excluded
 * anyway) and any failed reconnect within WIFI_ROAM_SELF_S after it (reason
 * 2 or 15 would count) are marked as ours through
 * wifi_roam_note_disconnect() and not counted.
 *
 * Every BSSID change (a roam of ours, an AP steer, or a reconnect that lands
 * on another AP) is logged, counted ("roams" in /api/status "wifi") and
 * written to the SD log as {"kind":"wifi","event":"roam",...}.
 *
 * The task's stack is in PSRAM: it never touches flash, as wifi_manager sets
 * the driver's config storage to RAM (esp_wifi_set_storage), so
 * esp_wifi_set_config() writes no NVS.
 */

#include "config.h"

#ifndef WIFI_ROAM_ENABLE
#define WIFI_ROAM_ENABLE        1       // 0 = no re-roam task (the strongest-AP join stays)
#endif
#ifndef WIFI_ROAM_RSSI_DBM
#define WIFI_ROAM_RSSI_DBM      (-75)   // below this the link counts as weak
#endif
#ifndef WIFI_ROAM_LOW_S
#define WIFI_ROAM_LOW_S         60      // weak for this long before a scan
#endif
#ifndef WIFI_ROAM_GAIN_DB
#define WIFI_ROAM_GAIN_DB       8       // a candidate must be this much stronger
#endif
#ifndef WIFI_ROAM_INTERVAL_S
#define WIFI_ROAM_INTERVAL_S    300     // at most one scan and roam per this
#endif

#define WIFI_ROAM_SELF_S        20      // disconnects this soon after our roam are ours
#define WIFI_ROAM_TASK_STACK    3072    // PSRAM
#define WIFI_ROAM_TASK_PRIO     2

typedef struct {
    bool     up;            // associated, the fields below are valid
    char     ssid[33];
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint32_t roams;         // BSSID changes since boot
} wifi_link_t;

// Current association, read from the driver, and the roam count. Any task.
void wifi_roam_link(wifi_link_t *out);

// From wifi_manager's WIFI_EVENT_STA_DISCONNECTED handler, before it counts
// the disconnect: true if it is ours (a roam, or its failed reconnect), so it
// must not count as a deauth. Drops the BSSID pin when due.
bool wifi_roam_note_disconnect(void);

// Task entry point (spawned in main.c with SPAWN_PSRAM).
void wifi_roam_task(void *arg);
