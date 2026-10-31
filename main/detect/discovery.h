#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LAN discovery listeners and the "seen devices" table (fork addition, Robert Mech)
 *
 * Log-only: these sockets never send. Nothing on the LAN can tell they exist,
 * and nothing in the house changes behaviour because of them. The point is to
 * see who scans or discovers the LAN (an LG TV opening Photo & Video or Home
 * Dashboard, a phone app, Home Assistant, Windows), and with what.
 *
 * One task select()s over the UDP sockets:
 *   SSDP          1900   joins 239.255.255.250: M-SEARCH (ST, MAN, MX,
 *                        USER-AGENT) and NOTIFY (NT, NTS, SERVER, LOCATION)
 *   WS-Discovery  3702   joins 239.255.255.250: Probe / Hello / Resolve, the
 *                        Types and Scopes from the SOAP body (bounded scans,
 *                        no XML parser)
 *   LLMNR         5355   joins 224.0.0.252: the queried names (QR=0 only)
 *   NBNS           137   broadcast: queried names; a registration's name is
 *                        the sender's own NetBIOS name, used as a label
 *   Kasa      9999 20002 vendor broadcasts: size and first bytes as hex; the
 *                        9999 XOR-autokey JSON is decoded for the log
 *   LIFX         56700   size, message type, first bytes as hex
 *   PlayStation 987 9302 size, first line if printable, first bytes as hex
 *   DHCP            67   client broadcasts (receive only; the board's own
 *                        DHCP client is on 68): hostname (12), vendor class
 *                        (60), parameter request list (55) as a fingerprint
 * mDNS (5353) is not bound: the espressif/mdns component owns 5353 through a
 * raw lwIP pcb without SOF_REUSEADDR, so a second bind fails, and a bind that
 * won the race would take .local away from the board. See the README.
 *
 * Source MACs: a UDP socket only gives the source IP, so the station netif
 * input wrapper in detect.c (Wi-Fi RX task) hands every frame to
 * discovery_frame_tap(), which queues (IP, MAC) for UDP to these ports. DHCP
 * uses the packet's chaddr. Otherwise the ARP cache is asked.
 *
 * Seen devices (PSRAM): up to DISCOVERY_DEV_MAX keyed by MAC (by IP while the
 * MAC is unknown), least recently seen evicted. Each has the IP, first and
 * last seen, the protocols and a count per protocol, the best label so far,
 * the DHCP or NetBIOS hostname, and the last DISCOVERY_QUERY_KEEP distinct
 * query strings. Labels, best first: a known vendor string in an SSDP
 * USER-AGENT or SERVER, a DHCP hostname or a DHCP vendor class (LG webOS,
 * Samsung, Roku, Sonos, Hue, Fire TV, Windows, ...); a raw hostname; a raw
 * vendor class or SERVER string; the MAC vendor. A locally administered MAC
 * (phones randomise theirs) is flagged.
 *
 * Output:
 *   - an SD line {"kind":"discovery",...} per new device, new protocol, new
 *     label or new query string for a device (DISCOVERY_SD_BURST, then one per
 *     DISCOVERY_SD_REFILL_MS)
 *   - an ATTACK_DISCOVERY event (flash ring, dashboard, panel, Discord event
 *     log) only for a new device, protocol or label, DISCOVERY_EV_BURST then
 *     one per DISCOVERY_EV_REFILL_S; the rest are counted into the next one as
 *     "(+N held)". Discovery is background noise: its alert bit is off by
 *     default (settings.c), so it opens no incident unless switched on.
 *   - GET /api/devices (main/admin/api_devices.c) and the dashboard's Devices tab
 *
 * Memory: receive buffer (1500 B), device table, MAC map and the queue in
 * PSRAM; the task stack is internal because log_store_append() writes SPIFFS.
 *
 * The defaults below let a config.h written before these options still build.
 */

#ifndef DISCOVERY_ENABLE
#define DISCOVERY_ENABLE        1
#endif
#ifndef DISCOVERY_DHCP
#define DISCOVERY_DHCP          1       // 0: do not bind UDP 67
#endif

#define DISCOVERY_DEV_MAX       64
#define DISCOVERY_QUERY_KEEP    4       // distinct query strings kept per device
#define DISCOVERY_QUERY_LEN     72
#define DISCOVERY_LABEL_LEN     40
#define DISCOVERY_HOST_LEN      33
#define DISCOVERY_RX_MAX        1500
#define DISCOVERY_EV_BURST      8       // events at once ...
#define DISCOVERY_EV_REFILL_S   30      // ... then one per this many seconds
#define DISCOVERY_SD_BURST      20      // SD lines at once ...
#define DISCOVERY_SD_REFILL_MS  3000    // ... then one per this many ms
#define DISCOVERY_TASK_STACK    3584    // internal; high-water logged on each new low
#define DISCOVERY_TASK_PRIO     2

_Static_assert(DISCOVERY_ENABLE == 0 || DISCOVERY_ENABLE == 1, "DISCOVERY_ENABLE must be 0 or 1");
_Static_assert(DISCOVERY_DHCP == 0 || DISCOVERY_DHCP == 1, "DISCOVERY_DHCP must be 0 or 1");

// Before the network is up, after log_store_init(): creates the MAC queue and
// the state, so the frame tap can run. The task opens the sockets once the
// station has an IP.
void discovery_init(void);

// FreeRTOS task entry point. Pass NULL. Core 1, internal stack.
void discovery_task(void *arg);

// Station netif input wrapper (detect.c), Wi-Fi RX task, every frame: queues
// (source IP, source MAC) for IPv4 UDP to a discovery port. Constant time,
// never blocks or logs.
void discovery_frame_tap(const uint8_t *frame, size_t len);

// The seen-devices table and listener status as one JSON object, newest
// first, into buf (cap bytes, NUL-terminated). Every string is escaped; the
// object is always complete ("truncated":true when devices were left out).
// Returns the length. For GET /api/devices.
size_t discovery_devices_json(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
