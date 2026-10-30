#pragma once
#include <stdint.h>
#include <stdbool.h>

/*
 * Incident alarm — Core 1
 *
 * Every event appended to the log store is an attack on the internal network
 * (nothing legitimate touches a honeypot), so any event can open an incident.
 *
 *   IDLE   → ACTIVE  first event: buzzer_alarm(), panel + web show the incident
 *   ACTIVE → ACTIVE  more events: count/last-seen updated, no extra beeps;
 *                    buzzer_remind() every ALARM_REMIND_S until acknowledged,
 *                    even after the attack itself has stopped
 *   ACTIVE → ACKED   alarm_ack() from the front panel or POST /api/ack
 *   ACKED  → ACKED   same source keeps going: silent
 *   ACKED  → ACTIVE  a different source, or the same source after
 *                    ALARM_QUIET_S without events: new incident, new alarm
 *   ACKED  → IDLE    ALARM_QUIET_S without events
 *
 * An unacknowledged incident is persisted to NVS, so a reboot does not clear
 * it: the board chirps once at boot and the reminders carry on.
 */

#ifndef ALARM_REMIND_S
#define ALARM_REMIND_S   300     // reminder beep interval while unacknowledged
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

// Snapshot of the current incident. Safe from any task.
void alarm_get(alarm_info_t *out);

// Called from the alarm task on every state or count change. Must be
// non-blocking (copy and queue). Up to 3 listeners, registered at boot.
void alarm_add_listener(void (*cb)(const alarm_info_t *info));
