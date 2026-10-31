#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_system.h"

/*
 * Notification layer, Core 1 (fork addition, Robert Mech)
 *
 * One call, notify_send(), fans a short message out to every registered and
 * enabled backend (Discord, Telegram, WhatsApp). Each backend keeps its own
 * queue and task: its send() only copies the message into that queue, so
 * notify_send() never blocks and is safe from any task.
 *
 * What goes through here:
 *   - NOTIFY_BOOT: one "online" message per boot, after Wi-Fi is up, with the
 *     device address, the firmware version and the reset reason in words
 *     (see notify_reset_reason_str()). Crashes, watchdogs and brown-outs are
 *     raised in severity.
 *   - NOTIFY_INCIDENT_*: incident opened, acknowledged and closed, from an
 *     alarm listener in notify.c (transitions only). Backends that build their
 *     own richer incident posts (Discord) leave these kinds out of their mask.
 *
 * Messages are plain text, ASCII, built from device data only (no attacker
 * text). Each backend escapes for its own format (JSON, HTML, URL).
 *
 * Adding a backend (ntfy, Slack, a generic webhook): one new file with a queue,
 * a task and a notify_backend_t, registered from its init function.
 */

#define NOTIFY_MAX_BACKENDS     6       // Discord, Telegram and WhatsApp use three
#define NOTIFY_TITLE_MAX        64
#define NOTIFY_TEXT_MAX         320

typedef enum {
    NOTIFY_BOOT = 0,
    NOTIFY_INCIDENT_OPENED,
    NOTIFY_INCIDENT_ACKED,
    NOTIFY_INCIDENT_CLOSED,
    NOTIFY_KIND_COUNT
} notify_kind_t;

#define NOTIFY_BIT(kind)        (1u << (kind))
#define NOTIFY_ALL_INCIDENTS    (NOTIFY_BIT(NOTIFY_INCIDENT_OPENED) | \
                                 NOTIFY_BIT(NOTIFY_INCIDENT_ACKED)  | \
                                 NOTIFY_BIT(NOTIFY_INCIDENT_CLOSED))

typedef enum {
    NOTIFY_INFO = 0,            // normal (Discord green)
    NOTIFY_WARN,                // needs a look (Discord amber)
    NOTIFY_ALERT,               // something went wrong (Discord red)
} notify_severity_t;

typedef struct {
    notify_kind_t     kind;
    notify_severity_t severity;
    char              title[NOTIFY_TITLE_MAX];
    char              text[NOTIFY_TEXT_MAX];    // plain text, '\n' between lines
} notify_msg_t;

typedef struct {
    const char *name;                           // for the log: "Discord", "WhatsApp"
    uint32_t    kinds;                          // NOTIFY_BIT() mask of the kinds it takes
    bool      (*enabled)(void);                 // configured right now
    bool      (*send)(const notify_msg_t *msg); // copy and enqueue; false if dropped
} notify_backend_t;

// Why the app is about to restart, stored in NVS just before esp_restart() and
// read (and cleared) at the next boot, so the online message can say "OTA
// update" rather than only "software restart".
typedef enum {
    NOTIFY_RESTART_NONE = 0,
    NOTIFY_RESTART_OTA,
    NOTIFY_RESTART_DASHBOARD,
    NOTIFY_RESTART_WIFI_FALLBACK,
} notify_restart_t;

// Read and clear the stored restart intent and register the alarm listener.
// Call once at boot, after nvs_flash_init() and alarm_init(), before the
// backends' init functions.
void notify_init(void);

// Register a backend (the pointer is kept). Call from the backend's init.
void notify_register(const notify_backend_t *backend);

// Fan a message out to every enabled backend that takes this kind. Never
// blocks. title and text are cut to NOTIFY_TITLE_MAX / NOTIFY_TEXT_MAX.
void notify_send(notify_kind_t kind, const char *title, const char *text,
                 notify_severity_t severity);

// Send the boot "online" message. Call once, after Wi-Fi has an IP and the
// backend tasks are spawned.
void notify_boot(const char *ip_str);

// Store the restart intent. Call just before esp_restart().
void notify_restart_intent(notify_restart_t why);

// The reset reason in words: "power-on", "software restart", "panic/crash",
// "interrupt watchdog", "task watchdog", "other watchdog", "brown-out",
// "deep sleep", "external pin", "unknown".
const char *notify_reset_reason_str(esp_reset_reason_t reason);

// This boot's reset reason with the stored intent, e.g. "software restart (OTA
// update)". Valid after notify_init().
const char *notify_boot_reason(void);

// Internal heap free once every task is up (app_main records it), for
// GET /api/status now that the board has no serial console. 0 until then.
void     notify_note_boot_heap(uint32_t internal_free);
uint32_t notify_boot_heap(void);
