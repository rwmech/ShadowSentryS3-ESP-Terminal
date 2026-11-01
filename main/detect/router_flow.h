#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "router_trip.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Router flows: an IPFIX (or NetFlow v9) collector for the MikroTik's
 * traffic-flow on its WAN port (fork addition, Robert Mech)
 *
 * Rob's choice, 2026-11-01, "Router IPFIX": conntrack is a snapshot, so a
 * connection that opens and closes between two fetches is missed; the
 * router's flow export sees every one. tools/routeros/flow.rsc sets it up.
 *
 * No socket: router_frame_tap() (router_trip.c) copies UDP to
 * ROUTER_IPFIX_PORT on our address, from the router's address and the
 * gateway's MAC only, into ROUTER_FLOW_SLOTS PSRAM slots of a full datagram
 * (lock-free, one producer, one consumer, a full ring drops and counts), and
 * consumes the frame. The router task drains it (router_flow_service()).
 *
 * Parsing: version 10 (IPFIX, RFC 7011) and 9 (NetFlow v9, RFC 3954), with
 * templates in a fixed table (ROUTER_FLOW_TEMPLATES, keyed by version,
 * observation domain or source id, and template id; the oldest replaced).
 * Every set, template, field and record length is checked against what is
 * left of the datagram; enterprise fields and variable-length fields (IPFIX
 * length 65535) are skipped by their encoded length. Options templates and
 * data for an unknown template are skipped and counted.
 * Fields used: octetDeltaCount 1 (or octetTotalCount 85), packetDeltaCount 2
 * (or 86), protocolIdentifier 4, ports 7 and 11, IPv4 addresses 8 and 12,
 * postNAT addresses 225 and 226. Templates are parsed, never assumed.
 *
 * Direction: a record with a private (RFC 1918) source and a public
 * destination is outbound, the device is the source; public to private is
 * inbound, the device is the destination; when both are public the post-NAT
 * addresses decide (an inbound reply to the WAN address names the device in
 * 226). LAN to LAN records are not kept.
 *
 * Rate cap: ROUTER_IPFIX_RATE records a second; the rest of a datagram over
 * the budget is dropped and counted.
 *
 * Table (PSRAM): ROUTER_FLOW_DEVICES devices by IPv4, each with
 * ROUTER_FLOW_DST destinations by (remote IPv4, remote port, protocol):
 * bytes and packets each way, flows, first and last seen (the datagram's
 * export time). The least recently seen device, or destination within a
 * device, is evicted when full; a destination idle ROUTER_FLOW_KEEP_S is
 * dropped. Read by /api/device/intel through correlate.c.
 */

#ifndef ROUTER_IPFIX_RATE
#define ROUTER_IPFIX_RATE       200     // records a second
#endif
_Static_assert(ROUTER_IPFIX_RATE >= 10 && ROUTER_IPFIX_RATE <= 5000, "ROUTER_IPFIX_RATE must be 10-5000");

#define ROUTER_FLOW_SLOTS       16
#define ROUTER_FLOW_SLOT        1500    // a full datagram on a 1500 B MTU
#define ROUTER_FLOW_TEMPLATES   16
#define ROUTER_FLOW_FIELDS      48      // fields per template; a longer template is unusable
#define ROUTER_FLOW_DEVICES     32
#define ROUTER_FLOW_DST         64
#define ROUTER_FLOW_KEEP_S      86400

typedef struct {
    uint32_t ip;                // remote, network order
    uint16_t port;              // remote port (outbound: the destination port)
    uint8_t  proto;
    uint8_t  external;
    uint64_t bytes_out, bytes_in;
    uint32_t pkts_out, pkts_in;
    uint32_t flows;             // records merged
    uint32_t first, last;       // unix time
} router_flow_dst_t;

typedef struct {
    uint8_t  state;             // ROUTER_FLOW_ST_*
    uint32_t ip;
    uint32_t as_of;             // unix time of the last record for this device
    uint32_t first;             // the oldest first-seen kept
    uint16_t n;
    bool     truncated;         // destinations were evicted for room
    router_flow_dst_t d[ROUTER_FLOW_DST];   // busiest (bytes both ways) first
} router_flow_dev_t;

enum { ROUTER_FLOW_ST_OFF = 0, ROUTER_FLOW_ST_WAITING, ROUTER_FLOW_ST_OK };
const char *router_flow_state_key(uint8_t st);   // "off", "waiting", "ok"

// Wi-Fi RX task, from router_frame_tap(): copy one UDP payload. Constant
// time, never blocks, allocates or logs.
void router_flow_push(const uint8_t *data, size_t len);

// Router task: allocate the ring and table (true when on), then drain.
bool router_flow_init(void);
void router_flow_service(void);

// One device's destinations into out (any task; a short lock). out->state
// says off (collector off), waiting (no record yet from the router) or ok;
// false when the device has no records.
bool router_flow_device(uint32_t ip, router_flow_dev_t *out);

// How many external destinations the device has (for the router DNS read).
int router_flow_ext_count(uint32_t ip);

// Collector-wide counters: records parsed, records dropped by the rate cap.
void router_flow_counters(uint32_t *records, uint32_t *dropped);

// The status as a JSON object into buf. Returns the length, 0 if it did not fit.
size_t router_flow_status_json(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
