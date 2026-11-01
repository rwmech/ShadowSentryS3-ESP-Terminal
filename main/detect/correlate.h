#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "mikrotik.h"
#include "router_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Device intelligence: one device seen from several places (fork addition,
 * Robert Mech)
 *
 * Merges, for one MAC and/or IP:
 *   - the honeypot's own events from it (the flash ring, counted by code, and
 *     the open incident's codes);
 *   - the router's view (admin/mikrotik.c): lease hostname, switch port or
 *     AP and signal, and its tracked connections summarised by destination;
 *   - the router's IPFIX flows (detect/router_flow.c), merged into the same
 *     destination list: conntrack rows first, then destinations only IPFIX
 *     saw, busiest first, each row marked conntrack, ipfix or both;
 *   - Pi-hole's view, when a Pi-hole client is built in (optional, below).
 * and raises flags, each with a short plain-English reason:
 *   dns_bypass      DNS sent to an outside server, or outside connections with
 *                   no lookups through Pi-hole (Pi-hole on only)
 *   blocked_contact a connection to an address Pi-hole blocked a name for, or
 *                   blocked lookups plus DNS bypass (Pi-hole on only)
 *   beaconing       new connections to one destination at a near-regular
 *                   interval, little data each time (from repeated fetches)
 *   unusual_port    outbound to an external port malware favours (Telnet, IRC,
 *                   ADB, SMB, Metasploit's 4444, ...)
 *   fanout          many distinct external hosts at once
 *   doh             DNS over HTTPS or TLS to a known public resolver (443 or
 *                   853): lookups Pi-hole never sees
 *   upload          an external destination that got at least 1 MB and four
 *                   times what came back
 *   direct_ip       external destinations with no DNS name behind them, when
 *                   a name source covers the device (Pi-hole answers, or the
 *                   router's DNS cache naming its other destinations)
 * Each destination carries the bits of the flags it raised (CORRELATE_F_*),
 * its name (Pi-hole answer, else the router's DNS cache) and its GeoIP
 * country and AS (looked up only for a device someone opened, top 8).
 *
 * Pure RAM work over copies; no network, no flash. Any task.
 */

#define CORRELATE_FLAGS_MAX   10
#define CORRELATE_REASON_LEN  112
#define CORRELATE_CODES_MAX   12
#define CORRELATE_SUMMARY_LEN 72
#define CORRELATE_FANOUT      25        // distinct external hosts in one snapshot
#define CORRELATE_UPLOAD_MIN  (1024u * 1024u)
#define CORRELATE_GEO_LOOKUPS 8         // GeoIP requests per intel call

// Per-destination flag bits (correlate_t.dflags), and their keys.
#define CORRELATE_F_DNS      0x01       // dns_bypass
#define CORRELATE_F_DOH      0x02
#define CORRELATE_F_PORT     0x04       // unusual_port
#define CORRELATE_F_BEACON   0x08       // beaconing
#define CORRELATE_F_UPLOAD   0x10
#define CORRELATE_F_DIRECT   0x20       // direct_ip
#define CORRELATE_F_BLOCKED  0x40       // blocked_contact
const char *correlate_flag_key(int bit);    // "dns_bypass", ...; bit 0..6

// Where a conn.dst[] row came from (correlate_t.dsrc).
#define CORRELATE_SRC_CONNTRACK 1
#define CORRELATE_SRC_IPFIX     2
#define CORRELATE_SRC_BOTH      3
const char *correlate_src_key(uint8_t src);  // "conntrack", "ipfix", "both"

// ── Optional Pi-hole input ────────────────────────────────────────────────────
//
// A Pi-hole client fills this for one device when it is built in and on.
// correlate.c holds only a weak reference to correlate_pihole_device(), so
// this module builds and runs without it. Pi-hole v6's GET /api/queries
// carries no answer addresses, so ip[] is normally 0; a client that knows
// them (another resolver, a cache) may fill them and the IP checks use them.

#define CORRELATE_DNS_MAX  16
typedef struct {
    char     domain[64];
    bool     blocked;
    uint32_t ts;
    uint32_t ip[2];                 // answers, network order, 0 = unknown
} correlate_dns_q_t;

typedef struct {
    uint32_t as_of;                 // unix time of the Pi-hole data
    uint32_t window_s;              // the queries cover this many seconds back
    uint32_t server_ip;             // the Pi-hole's own address, 0 = unknown
    uint16_t total, blocked;        // queries from the device in the window
    uint8_t  n;
    correlate_dns_q_t q[CORRELATE_DNS_MAX];     // newest distinct first
} correlate_dns_t;

// Provided by the Pi-hole client, if built in: fill out for the device with
// this IP (and MAC, may be NULL). False when Pi-hole is off or has nothing.
// Must not block for long (RAM lookups only); called from the admin, Discord
// and WebSocket tasks.
bool correlate_pihole_device(uint32_t ip, const uint8_t *mac, correlate_dns_t *out);

// ── Result ────────────────────────────────────────────────────────────────────

typedef struct {
    char key[16];                   // dns_bypass, blocked_contact, beaconing, unusual_port, fanout
    char reason[CORRELATE_REASON_LEN];
} correlate_flag_t;

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    bool     mac_known;

    // The honeypot's own events from this device
    uint32_t hp_events, hp_last;
    uint8_t  hp_n;
    struct { char code[6]; uint16_t n; } hp[CORRELATE_CODES_MAX];
    char     label[40];             // discovery's best label, "" none

    // MikroTik
    mikrotik_state_t mt_state;
    bool     host_found;
    uint32_t host_as_of;
    mikrotik_host_t host;
    bool     conn_found;
    mikrotik_conn_t conn;
    uint8_t  dflags[MIKROTIK_DST_MAX];      // CORRELATE_F_* per conn.dst[]
    // The router's IPFIX flows (detect/router_flow.c), merged into conn.dst[]:
    // dsrc says where a row came from, fidx its entry in flow.d[] (-1 none).
    // An IPFIX-only row carries the flow totals in bytes_* and pkts_*.
    bool     flow_found;
    router_flow_dev_t flow;
    uint8_t  dsrc[MIKROTIK_DST_MAX];        // CORRELATE_SRC_*
    int8_t   fidx[MIKROTIK_DST_MAX];
    bool     flow_cut;                      // IPFIX destinations left out (conn.dst full)
    struct { char cc[4]; char asn[16]; char org[40]; } geo[MIKROTIK_DST_MAX];   // "" unknown

    // Pi-hole
    bool     dns_on;
    correlate_dns_t dns;

    uint8_t  n_flags;
    correlate_flag_t flags[CORRELATE_FLAGS_MAX];
    char     summary[CORRELATE_SUMMARY_LEN];    // "on ether4, 3 external connections, 1 flagged"
} correlate_t;

// Build the picture for a device. mac may be NULL (looked up by IP), ip may
// be 0 (looked up by MAC). With fetch true, the router is asked for the
// device's connections (rate-limited; the answer comes on a later call).
// with_events scans the flash ring (about 47 KB of PSRAM for a moment).
// out is big (about 5 KB): allocate it, don't put it on a stack.
void correlate_build(uint32_t ip, const uint8_t *mac, bool fetch, bool with_events, correlate_t *out);

// The short summary for a device into buf, "" (and 0) when nothing is known.
// Cheap: no fetch, no ring scan. For the alarm JSON.
size_t correlate_summary(uint32_t ip, const uint8_t *mac, char *buf, size_t len);

// For an incident's opening post: ask the router for the source's
// connections and wait up to wait_ms for them (returns at once when the
// router is off or the device is not on the LAN), then the summary as above.
size_t correlate_incident_summary(uint32_t ip, const uint8_t *mac, char *buf, size_t len, int wait_ms);

#ifdef __cplusplus
}
#endif
