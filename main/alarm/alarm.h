#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "log_store.h"
#include "describe.h"

/*
 * Incident alarm, Core 1
 *
 * Every event appended to the log store is an attack on the internal network
 * (nothing legitimate touches a honeypot), so any event can open an incident,
 * unless its type is switched off in the alert mask or its source (or its
 * code from that source) is on the ignore list (alarm_should_alert): those
 * are logged and nothing more. What an event does depends on its code's tier
 * (describe.h): SEV1 opens RED, SEV2 and SEV3 open YELLOW.
 *
 * Conditions (cond), one per state, 1:1:
 *   GREEN   ALARM_IDLE    no open incident
 *   RED     ALARM_ACTIVE  an open incident with a SEV1 event, unacknowledged:
 *                         the siren, and again every ALARM_REMIND_S
 *   YELLOW  ALARM_ACKED   a RED incident that was acknowledged, or one opened
 *                         by SEV2/SEV3 events only (one soft tone when it
 *                         opens, never the siren, no reminders)
 *
 *   GREEN  -> RED     a SEV1 event: buzzer_alarm() (the siren)
 *   GREEN  -> YELLOW  a SEV2 or SEV3 event: buzzer_yellow() (one soft tone)
 *   RED    -> RED     more events: count/last-seen updated, no extra sirens
 *   RED    -> YELLOW  alarm_ack() (panel, POST /api/alarm/ack); a siren still
 *                     playing is cut short
 *   YELLOW -> YELLOW  same source keeps going: silent. A SEV1 event from the
 *                     same source in a YELLOW incident nobody acknowledged
 *                     (opened by SEV2 events) escalates it to RED in place.
 *   YELLOW -> new     a different source, or the same source after
 *                     ALARM_QUIET_S without events: a new incident, RED for a
 *                     SEV1 event, YELLOW otherwise
 *   YELLOW -> GREEN   ALARM_QUIET_S without events (YELLOW only)
 *   RED or YELLOW -> GREEN  alarm_resolve() (panel, POST /api/alarm/resolve):
 *                     the next event opens a new incident at once
 * Nothing here ever deletes a log: the flash ring, SD log and metrics stay.
 *
 * The incident is persisted to NVS, so a reboot does not clear it: a RED
 * incident sounds one reminder siren at boot and the reminders carry on; a
 * YELLOW one stays YELLOW and its quiet timer starts again at boot.
 */

#ifndef ALARM_REMIND_S
#define ALARM_REMIND_S   60      // reminder siren interval while unacknowledged
#endif
#ifndef ALARM_QUIET_S
#define ALARM_QUIET_S    600     // silence that closes a YELLOW incident
#endif

typedef enum {
    ALARM_IDLE   = 0,   // GREEN
    ALARM_ACTIVE = 1,   // RED: unacknowledged SEV1
    ALARM_ACKED  = 2,   // YELLOW: acknowledged, or SEV2 only
} alarm_state_t;

typedef enum {
    ALARM_COND_GREEN  = 0,
    ALARM_COND_YELLOW = 1,
    ALARM_COND_RED    = 2,
} alarm_cond_t;

// Who acknowledged or resolved.
typedef enum {
    ALARM_BY_NONE      = 0,
    ALARM_BY_PANEL     = 1,
    ALARM_BY_DASHBOARD = 2,     // the dashboard or anything else on the API
} alarm_by_t;

typedef struct {
    alarm_state_t state;
    alarm_cond_t  cond;        // follows state, see above
    uint32_t      id;          // incident number, increments per incident
    uint32_t      src_ip;      // first source (network order, as attack_log_t)
    uint8_t       src_mac[6];
    uint8_t       type;        // attack_type_t of the headline event
    uint8_t       acked_by;    // alarm_by_t; ALARM_BY_NONE if never acknowledged
    uint32_t      first_ts;    // unix time of the opening event
    uint32_t      last_ts;     // unix time of the latest event
    uint32_t      count;       // events in this incident
    char          code[DESCRIBE_CODE_LEN];   // "17-01": the headline event's code
    uint8_t       resolved_by; // alarm_by_t of the last resolve; NONE for a quiet close
    uint8_t       _pad;
    uint32_t      codes;       // bit i: describe_code_at(i) seen from the source
    char          headline[DESCRIBE_MAX];    // describe_event() of that event
} alarm_info_t;

// Call once at boot, before the honeypot tasks start. Spawns the alarm task.
void alarm_init(void);

// Acknowledge: RED -> YELLOW, the siren cut short, by is kept in acked_by.
// Nothing in other states. Safe from any task; non-blocking.
void alarm_ack(alarm_by_t by);

// Resolve: RED or YELLOW -> GREEN, so the next event alarms again. Logs are
// never touched. Nothing when GREEN. Safe from any task; non-blocking.
void alarm_resolve(alarm_by_t by);

// The old name of alarm_resolve(ALARM_BY_PANEL).
void alarm_clear(void);

// Ignore and close. alarm_ignore_error() adds the incident's source (IP and
// MAC) with the incident's code to the ignore list; alarm_ignore_device()
// adds the source with an empty code (every code). Either then resolves the
// incident (resolved_by = by), whatever other codes it saw: the events stay
// in the logs, and a later event whose code is not ignored opens a new
// incident.
// ESP_ERR_INVALID_STATE when there is no open incident, else ignore_add()'s
// result. Writes NVS: call from a task with a few KB of stack (UI, admin).
esp_err_t alarm_ignore_error(alarm_by_t by);
esp_err_t alarm_ignore_device(alarm_by_t by);

// true if the last close to GREEN was alarm_resolve() (or alarm_clear()),
// false if it was the quiet timer. Meaningful only inside a listener, on the
// alarm task, when a listener sees the state go to IDLE.
bool alarm_closed_by_rearm(void);

// Snapshot of the current incident. Safe from any task.
void alarm_get(alarm_info_t *out);

// "green", "yellow", "red".
const char *alarm_cond_key(alarm_cond_t c);

// "", "panel", "dashboard".
const char *alarm_by_key(uint8_t by);

// Should this event alert (open or extend an incident, Telegram, Discord)?
// False when its type's bit is clear in the settings' alert_mask or its
// source, or its code from that source, is on the ignore list. Logging never
// depends on it. Cheap and safe from any task.
bool alarm_should_alert(const attack_log_t *e);

// Feed an event to the incident logic without the log store (LAN discovery
// keeps its events out of the flash ring). Gated by alarm_should_alert() like
// every other event; copies and queues, never blocks, safe from any task.
void alarm_note_event(const attack_log_t *e);

// Called from the alarm task on every state or count change. Must be
// non-blocking (copy and queue). Up to 6 listeners (ALARM_MAX_LISTENERS in
// alarm.c), registered at boot; five are used (UI, WebSocket, SD log, Discord,
// notify).
void alarm_add_listener(void (*cb)(const alarm_info_t *info));
