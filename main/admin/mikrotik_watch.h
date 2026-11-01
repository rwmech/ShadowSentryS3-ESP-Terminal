#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Router integrity: the MikroTik router as a sensor (fork addition, Robert
 * Mech)
 *
 * Snapshot and diff over the read-only REST client (mikrotik.h). For each
 * watched menu the stable fields are fetched, each record keyed by its .id
 * and hashed without its counters (run-count, last-started, bytes, ...). Rob
 * arms a baseline from the Settings page and re-arms it after a planned
 * change; from then on an added, removed or changed record raises an
 * ATTACK_ROUTER event with a 55-xx code ("Router integrity"), once per change.
 *
 *   55-01 /system/scheduler, /system/script             SEV1
 *   55-02 /user, /user/group, /user/ssh-keys             SEV1
 *   55-03 /ip/socks, /ip/proxy                           SEV1
 *   55-04 /ip/firewall/nat                               SEV1
 *   55-05 /ip/service (port, available-from, disabled)   SEV1
 *   55-06 /ip/firewall/filter, chain input               SEV1
 *   55-07 /ip/dns, /ip/dns/static                        SEV1
 *   55-08 /interface, tunnel types only                  SEV1
 *   55-09 /system/logging, /system/logging/action        SEV1 (blinding the sensor)
 *   55-10 /log logins and failures, /user/active         SEV2 (no baseline: always on)
 *   55-11 /system/package, /system/resource version,
 *         /system/routerboard firmware                   SEV2
 * (critical and high in the research table map to SEV1, medium to SEV2.)
 *
 * The static checks of microsoft/routeros-scanner (MIT, the .py files in commands) run on
 * every record and are named in the event and the status: a scheduler entry
 * named u<digits> or fetching from the web, the default admin in group full,
 * a user with no allowed address, dst-nat between two public addresses, a
 * service off its default port, SOCKS or the web proxy enabled, DNS answering
 * remote requests.
 *
 * Polled every MIKROTIK_POLL_S, one menu at a time, staggered (RouterOS runs
 * one user's requests one at a time). A menu the router does not have (no
 * /ip/socks on some builds, no packages menu) is marked missing, not an error.
 * Script source is diffed only if this user can read it (no "sensitive"
 * policy may hide it); otherwise name, owner and policy, and the status says so.
 *
 * Storage: the per-record hashes are in PSRAM; NVS keeps only a compact
 * digest per menu (and the arm time), so after a reboot each menu is compared
 * with its armed digest and a mismatch is reported once, without record detail.
 *
 * Events go through log_store_append() from a short-lived internal-stack
 * helper task (the mikrotik task's stack is in PSRAM and must not write
 * SPIFFS), so they reach the ring, the dashboard, the panel, the SD log,
 * Discord, Telegram and the alarm like any trap event. The event's source is
 * the router's address (from the MikroTik URL) and MAC (from the ARP table).
 */

#define MIKROTIK_WATCH_RECS   64      // records per menu
#define MIKROTIK_WATCH_EVENTS 4       // events per menu per check, then one "(+N more)"

// At boot, from mikrotik_start() (internal stack): read the armed digests.
void mikrotik_watch_load(void);

// From the mikrotik task's loop, about once a second while the router answers:
// runs at most one request when a menu is due (or an arm is in progress).
void mikrotik_watch_tick(void);

// Ask the task to arm the baseline from the router's current state (takes
// one pass over the menus, about 30 s). False when MikroTik is not running.
bool mikrotik_watch_arm(void);

// The status as JSON into buf (cap bytes): {"armed","armed_at","arming",
// "last_check","checks":[{"key","title","code","state","records","armed_records",
// "changes","last","note","findings"}]}. Every router string escaped.
// Returns the length, 0 if it did not fit. Any task.
unsigned mikrotik_watch_json(char *buf, unsigned cap);

// The router's IPv4 (network order) from the MikroTik URL, 0 if it is a name.
uint32_t mikrotik_watch_router_ip(void);

#ifdef __cplusplus
}
#endif
