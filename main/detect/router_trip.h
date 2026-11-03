#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Router tripwires: the MikroTik router's own log as a sensor (fork
 * addition, Robert Mech)
 *
 * Rob's choice, 2026-11-01, "Syslog + list check". The router sends chosen
 * log topics to this board over UDP syslog (tools/routeros/tripwires.rsc),
 * and a few firewall rules on the router log offenders with an "SS-TRIP-"
 * prefix and add them to the address-list shadowsentry-trip. The rules only
 * log and add to a list: they never drop, reject or touch admin access.
 *
 * No socket and no file descriptor (53 of 53 are taken). The station netif
 * input wrapper in detect.c hands every frame to router_frame_tap(), which
 * copies an IPv4 UDP datagram to ROUTER_SYSLOG_PORT on our address into a
 * PSRAM slot ring (single producer: the Wi-Fi RX task; single consumer: the
 * router task; lock-free, a full ring drops and counts), but only when its
 * source IP is the router (ROUTER_SYSLOG_SRC, else the host of the MikroTik
 * URL) and its source MAC is the gateway's. That frame is then consumed (not
 * passed to lwIP), so the router gets no ICMP port-unreachable back. Anything
 * else to that port goes on to lwIP as before (a closed port).
 *
 * The router task (PSRAM stack: RAM, queues and logging only, never flash)
 * parses each line with bounded readers (the line carries attacker text: a
 * user name in a failed login, a DHCP host name), as RouterOS writes it in
 * "default" or "syslog" (RFC 3164) format, with or without the topics:
 *   55-21 Router login failed  SEV1  "login failure for user U from A via S":
 *                                     any from an address that is not an
 *                                     admin; 3 or more in 300 s from an admin
 *   55-22 Router login         SEV1  "user U logged in from A via S" from an
 *                                     address that is not an admin
 *   55-23 Router config change SEV1  "<item> changed|added|removed|moved by
 *                                     <actor>", the actor's address not an
 *                                     admin, or a scheduler or script actor
 *   55-24 Router port scan     SEV1  prefix SS-TRIP-PSD (the router's psd matcher)
 *   55-25 Router management    SEV2  prefix SS-TRIP-MGMT (a non-admin host on
 *                                     the router's management ports)
 *   55-26 DNS bypass           SEV2  prefix SS-TRIP-DNS (DNS or DoT to anything
 *                                     but the Pi-hole)
 *   55-27 Router tripwire list SEV2  a new shadowsentry-trip entry that no
 *                                     syslog line explained (list check below)
 *   55-28 DNS bypass, redirected SEV3 SS-TRIP-DNS on UDP or TCP 53 while the
 *                                     router_dns_redirect setting is on (the
 *                                     router NATs 53 to the Pi-hole): logged,
 *                                     no incident; DoT 853 stays 55-26
 *   DHCP "<server> assigned <ip> for <MAC> <host>" goes to the MikroTik
 *   client's known-device set: a MAC never seen raises Code 60-02 once,
 *   whichever of syslog and the lease poll sees it first.
 * Admins: ROUTER_ADMIN_IPS plus the dashboard's admin allowlist. This board's
 * own address (its read-only REST login) is never an offender for logins.
 * One event per code and source per hold time (300 s, DNS bypass 3600 s),
 * repeats counted into the next one. Events go through mikrotik_watch_post()
 * (log_store_append() on its internal-stack helper), source the offender.
 *
 * While syslog is live (a line from the router in the last 900 s), the
 * integrity watcher's 55-10 login events from /log polling and /user/active
 * are not raised (they would repeat 55-21 and 55-22).
 *
 * List check: every ROUTER_LIST_CHECK_S, on the mikrotik task, GET
 * /rest/ip/firewall/address-list?list=shadowsentry-trip (GET only, the
 * existing read-only client). The first read learns; a new entry whose
 * address raised no syslog tripwire in the last 24 h raises 55-27.
 */

// ── Configuration (config.h; defaults for a config.h without them) ────────────

#ifndef ROUTER_SYSLOG_ENABLE
#define ROUTER_SYSLOG_ENABLE    1
#endif
#ifndef ROUTER_SYSLOG_PORT
#define ROUTER_SYSLOG_PORT      514     // UDP, copied from the Wi-Fi input, no socket
#endif
#ifndef ROUTER_SYSLOG_SRC
#define ROUTER_SYSLOG_SRC       ""      // the router's IPv4; "" = the host of the MikroTik URL
#endif
#ifndef ROUTER_ADMIN_IPS
#define ROUTER_ADMIN_IPS        ""      // "192.168.0.10,192.168.0.11", up to 8, plus the admin allowlist
#endif
#ifndef ROUTER_PIHOLE_IP
#define ROUTER_PIHOLE_IP        ""      // for the never-block list; "" = the Pi-hole client's resolved address
#endif
#ifndef ROUTER_LIST_CHECK_S
#define ROUTER_LIST_CHECK_S     15
#endif
#ifndef ROUTER_IPFIX_ENABLE
#define ROUTER_IPFIX_ENABLE     1
#endif
#ifndef ROUTER_IPFIX_PORT
#define ROUTER_IPFIX_PORT       4739    // UDP, IPFIX (or NetFlow v9), copied like syslog
#endif

_Static_assert(ROUTER_SYSLOG_PORT > 0 && ROUTER_SYSLOG_PORT <= 65535, "ROUTER_SYSLOG_PORT must be 1-65535");
_Static_assert(ROUTER_IPFIX_PORT > 0 && ROUTER_IPFIX_PORT <= 65535, "ROUTER_IPFIX_PORT must be 1-65535");
_Static_assert(ROUTER_SYSLOG_PORT != ROUTER_IPFIX_PORT, "ROUTER_SYSLOG_PORT and ROUTER_IPFIX_PORT must differ");
_Static_assert(ROUTER_LIST_CHECK_S >= 5 && ROUTER_LIST_CHECK_S <= 3600, "ROUTER_LIST_CHECK_S must be 5-3600");
_Static_assert(sizeof(ROUTER_SYSLOG_SRC) <= 16, "ROUTER_SYSLOG_SRC must be a dotted quad or empty");
_Static_assert(sizeof(ROUTER_ADMIN_IPS) <= 136, "ROUTER_ADMIN_IPS must be at most 135 characters");
_Static_assert(sizeof(ROUTER_PIHOLE_IP) <= 16, "ROUTER_PIHOLE_IP must be a dotted quad or empty");

#define ROUTER_TASK_STACK       4096    // PSRAM: RAM, queues and logging only
#define ROUTER_TASK_PRIO        2
#define ROUTER_SYSLOG_SLOTS     16
#define ROUTER_SYSLOG_SLOT      640     // bytes of a datagram kept; longer ones are cut
#define ROUTER_TRIP_LIST        "shadowsentry-trip"
#define ROUTER_ADMIN_MAX        8

// ── Wi-Fi RX task ─────────────────────────────────────────────────────────────

// Every frame on the station interface (detect.c). Constant time, never
// blocks, allocates or logs. True when the frame was a datagram from the
// router to one of our collector ports and was copied: the caller frees it
// and does not pass it on.
bool router_frame_tap(const uint8_t *frame, size_t len, uint32_t our_ip);

// ── Router task ───────────────────────────────────────────────────────────────

// The task (SPAWN_PSRAM in main.c): the syslog ring, the IPFIX ring
// (router_flow.c), the router's address and the gateway's MAC.
void router_trip_task(void *arg);

// ── Any task ──────────────────────────────────────────────────────────────────

// The router's IPv4 the taps accept (network order), 0 = not known yet.
uint32_t router_trip_router_ip(void);

// The gateway's MAC as the taps use it. False while unknown.
bool router_trip_gateway_mac(uint8_t mac[6]);

// An admin address: ROUTER_ADMIN_IPS or the admin allowlist.
bool router_trip_is_admin(uint32_t ip);

// The comma-separated IPv4 list in s into out (network order), up to max.
// Entries that are not dotted quads are skipped. Returns the count.
int router_trip_parse_ips(const char *s, uint32_t *out, int max);

// A syslog line from the router came in the last 900 s.
bool router_trip_syslog_live(void);

// The mikrotik task's loop: the address-list check when due. True when it
// sent a request (the caller then skips its own work for this tick).
bool router_trip_list_tick(void);

typedef struct {
    bool     enabled, live, list_learned;
    uint32_t router_ip;
    bool     gw_known;
    uint32_t received, foreign, dropped, cut, parsed, events, held, sd_lines, sd_dropped;
    uint32_t c_login_fail, c_login, c_change, c_psd, c_mgmt, c_dns, c_dhcp, c_other;
    uint32_t last_ts;               // unix time of the last line
    uint32_t list_checks, list_errors, list_entries, list_events, list_last;
    int      list_status;           // HTTP status of the last list read, 0 none
} router_trip_status_t;

void router_trip_get_status(router_trip_status_t *out);

// The status as a JSON object into buf: {"enabled","live",...}. Returns the
// length, 0 if it did not fit.
size_t router_trip_status_json(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
