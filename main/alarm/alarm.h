#pragma once
#include <stdint.h>
#include <stdbool.h>

/*
 * Incident alarm, Core 1
 *
 * Every event appended to the log store is an attack on the internal network
 * (nothing legitimate touches a honeypot), so any event can open an incident,
 * unless its type is switched off in the alert mask or its source is on the
 * ignore list (alarm_should_alert): those are logged and nothing more.
 *
 *   IDLE   → ACTIVE  first event: buzzer_alarm() (the siren), panel + web
 *                    show the incident
 *   ACTIVE → ACTIVE  more events: count/last-seen updated, no extra sirens;
 *                    buzzer_remind() (the siren again) every ALARM_REMIND_S
 *                    until acknowledged, even after the attack has stopped
 *   ACTIVE → ACKED   alarm_ack() from the front panel or POST /api/ack;
 *                    a siren still playing is cut short
 *   ACKED  → ACKED   same source keeps going: silent
 *   ACKED  → ACTIVE  a different source, or the same source after
 *                    ALARM_QUIET_S without events: new incident, new alarm
 *   ACKED  → IDLE    ALARM_QUIET_S without events, or alarm_clear() (re-arm,
 *                    from the panel or POST /api/alarm/clear): the next event
 *                    opens a new incident at once. The logs are not touched.
 *
 * An unacknowledged incident is persisted to NVS, so a reboot does not clear
 * it: the board sounds one reminder siren at boot and the reminders carry on.
 */

#ifndef ALARM_REMIND_S
#define ALARM_REMIND_S   60      // reminder siren interval while unacknowledged
#endif
#ifndef ALARM_QUIET_S
#define ALARM_QUIET_S    600     // silence that closes an acknowledged incident
#endif

typedef enum {
    ALARM_IDLE   = 0,
    ALARM_ACTIVE = 1,   // unacknowledged
    ALARM_ACKED  = 2,
} alarm_state_t;

typedef struct {
    alarm_state_t state;
    uint32_t      id;          // incident number, increments per incident
    uint32_t      src_ip;      // first source (network order, as attack_log_t)
    uint8_t       src_mac[6];
    uint8_t       type;        // attack_type_t of the opening event
    uint32_t      first_ts;    // unix time of the opening event
    uint32_t      last_ts;     // unix time of the latest event
    uint32_t      count;       // events in this incident
} alarm_info_t;

// Call once at boot, before the honeypot tasks start. Spawns the alarm task.
void alarm_init(void);

// Acknowledge the current incident. Safe from any task; non-blocking.
void alarm_ack(void);

// Re-arm: end an acknowledged incident (ACKED → IDLE) so the next event
// alarms again. Ignored unless the incident is acknowledged. Safe from any
// task; non-blocking.
void alarm_clear(void);

// true if the last ACKED -> IDLE close was a re-arm (alarm_clear()), false if
// it was the quiet timer. Meaningful only inside a listener, on the alarm
// task, when a listener sees the state go to IDLE.
bool alarm_closed_by_rearm(void);

// Snapshot of the current incident. Safe from any task.
void alarm_get(alarm_info_t *out);

// Should an event of this type from this source alert (open or extend an
// incident, Telegram, Discord)? False when the type's bit is clear in the
// settings' alert_mask or the source is on the ignore list. Logging never
// depends on it. Cheap and safe from any task.
bool alarm_should_alert(uint8_t type, uint32_t src_ip, const uint8_t src_mac[6]);

// Called from the alarm task on every state or count change. Must be
// non-blocking (copy and queue). Up to 6 listeners (ALARM_MAX_LISTENERS in
// alarm.c), registered at boot; five are used (UI, WebSocket, SD log, Discord,
// notify).
void alarm_add_listener(void (*cb)(const alarm_info_t *info));
