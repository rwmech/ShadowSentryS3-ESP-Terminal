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
 *                   the router's DNS cache names the device's other
 *                   destinations (not raised while Pi-hole's log is read:
 *                   no_lookup is the better test then)
 *   no_lookup       external destinations nobody looked up through Pi-hole
 *                   while its DNS log covered (see the DNS log input below)
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
#define CORRELATE_F_NOLOOKUP 0x80       // no_lookup
#define CORRELATE_F_BITS     8
const char *correlate_flag_key(int bit);    // "dns_bypass", ...; bit 0..7

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

// ── Optional Pi-hole DNS log input (answers) ─────────────────────────────────
//
// The Pi-hole client reads the resolver's log and keeps, per IPv4 address,
// the name it was the answer for and who asked. Weak like the hook above.
// Each external destination of the device then gets a lookup verdict:
//   self    this device looked the address up (the name it asked for)
//   other   another device did (that device), or the log did not name the
//           asker (an IPv6 client, or its query line was missed)
//   unseen  no lookup of it in the log: called out (flag no_lookup), and only
//           when the log is usable (read for PIHOLE_LOG_COVER_S without a gap)
//   before  no lookup, but the router saw the connection before the log's
//           cover began, so the lookup may have come first
//   wait    no lookup yet, but the log has not covered long enough to say
// and "" when not checked (local, DNS itself, a known resolver, no log).

enum { CORRELATE_LK_NA = 0, CORRELATE_LK_SELF, CORRELATE_LK_OTHER, CORRELATE_LK_UNSEEN,
       CORRELATE_LK_BEFORE, CORRELATE_LK_WAIT };
const char *correlate_lookup_key(uint8_t lk);   // "", "self", "other", "unseen", "before", "wait"

typedef struct {
    bool     on;                    // a log client is built in and Pi-hole is on
    bool     readable;              // the log is being read (answers can be matched)
    bool     usable;                // readable, and covers long enough to call out "unseen"
    char     state[16];             // pihole_status_t.log_state
    char     why[160];              // plain words: why not usable ("" when usable)
    uint32_t cover_from;            // epoch the answers cover back to, 0 none
    uint32_t geo_blocked_ts;        // Pi-hole refused ip-api.com to this board (GeoIP owners), 0 never
} correlate_dnslog_t;

typedef struct {
    bool     found;
    bool     self;                  // this device asked
    char     name[64];              // the name it asked (self), else the newest name
    uint32_t last;                  // epoch of the newest answer
    uint32_t by;                    // the other asker shown, network order; 0 not named
} correlate_answer_t;

// State of the log, into out. False when no log client is built in.
bool correlate_pihole_dnslog(correlate_dnslog_t *out);
// For n destination addresses: what the log knows, asked from client (this
// device). dns (may be NULL): the device's top domains, for its own name when
// the address was also the answer to another device's newer question. RAM
// only, one lock. Returns how many were found.
int correlate_pihole_answers(uint32_t client, const correlate_dns_t *dns, const uint32_t *ips, int n,
                             correlate_answer_t *out);

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
    // Pi-hole's DNS log: the lookup verdict per conn.dst[] (CORRELATE_LK_*),
    // the name the answer was for, when, and the other asker with its label.
    correlate_dnslog_t dnslog;
    struct { uint8_t lk; uint32_t when, by; char name[64]; char by_label[32]; } lk[MIKROTIK_DST_MAX];

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
