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
 *   mDNS          5353   no socket: the espressif/mdns component owns 5353
 *                        through a raw lwIP pcb without SOF_REUSEADDR, so a
 *                        second bind fails, and one that won the race would
 *                        take .local away from the board. Instead the frame
 *                        tap copies queries (QR=0, standard opcode) to
 *                        224.0.0.251 or to us, up to DISCOVERY_MDNS_COPY bytes,
 *                        into a DISCOVERY_MDNS_SLOTS ring in PSRAM (dropped
 *                        and counted when full); the task reads the questions
 *                        with the same bounded DNS name reader as LLMNR. The
 *                        mdns component is untouched and still answers. IPv4
 *                        only.
 *
 * Source MACs: a UDP socket only gives the source IP, so the station netif
 * input wrapper in detect.c (Wi-Fi RX task) hands every frame to
 * discovery_frame_tap(), which queues (IP, MAC) for UDP to these ports (mDNS
 * slots carry their own). DHCP uses the packet's chaddr. Otherwise the ARP
 * cache is asked.
 *
 * Vendors: oui_lookup() (main/storage/oui.h: the microSD database, else the
 * compact table) on this task, cached; a device with nothing better is
 * labelled "<vendor> device".
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
 *     label or hostname, or a query string that device never sent before
 *     (a per-device LRU set of DISCOVERY_QHASH_N hashes), DISCOVERY_SD_BURST
 *     then one per DISCOVERY_SD_REFILL_MS; and once an hour one
 *     {"kind":"discovery_summary"} line per device that sent anything, with
 *     its packets per protocol. Nothing is written per packet.
 *   - a Discord digest every DISCOVERY_DIGEST_S, only when something new was
 *     seen: "LAN devices seen (last 30 min)", one line per device with news
 *     (label, IP or MAC, what it did in plain words from a table in flash:
 *     "looking for media servers (DLNA)", "asked for WPAD (proxy
 *     auto-discovery)", "DHCP request, hostname LGwebOSTV"), at most
 *     DISCOVERY_DIGEST_LINES, cut at word boundaries, then "+N more on the
 *     Devices tab". Discovery events no longer post line by line.
 *   - an ATTACK_DISCOVERY event only for a new device, protocol or label,
 *     DISCOVERY_EV_BURST then one per DISCOVERY_EV_REFILL_S; the rest are
 *     counted into the next one as "(+N held)". It never goes through
 *     log_store_append(), so it is not in the 200-entry flash ring, the
 *     dashboard's attack list and feed, the panel's events or stats.bin (not
 *     counted there at all; the device table has its own counts). It goes to
 *     Discord's event log (discord_log_event), the incident logic
 *     (alarm_note_event) and Telegram, and the last two apply the alert mask:
 *     discovery is background noise, its bit is off by default (settings.c),
 *     so it opens no incident unless switched on.
 *   - GET /api/devices (main/admin/api_devices.c) and the dashboard's Devices tab
 *
 * Memory: receive buffer (1500 B), device table, MAC map, the MAC queue and
 * the mDNS ring in PSRAM. Nothing on the task touches flash (no SPIFFS, no
 * NVS: only queues, sockets and RAM lookups), so its stack is in PSRAM too.
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
#define DISCOVERY_MDNS_SLOTS    8       // mDNS queries waiting for the task
#define DISCOVERY_MDNS_COPY     512     // bytes of each query kept (the questions come first)
#define DISCOVERY_ACT_KEEP      3       // plain-words activities per device per digest
#define DISCOVERY_ACT_LEN       64
#define DISCOVERY_DIGEST_S      1800    // Discord digest period
#define DISCOVERY_DIGEST_LINES  20      // devices per digest, the rest "+N more"
#define DISCOVERY_DIGEST_LINE   90      // characters per line, cut at a word
#define DISCOVERY_DIGEST_MAX    1800    // characters in all (Discord allows 2000)
#define DISCOVERY_QHASH_N       32      // distinct query strings remembered per device (LRU)
#define DISCOVERY_SUMMARY_S     3600    // discovery_summary period
#define DISCOVERY_TASK_STACK    4096    // PSRAM; high-water logged on each new low
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
// (source IP, source MAC) for IPv4 UDP to a discovery port, and copies mDNS
// queries to 224.0.0.251 or our_ip (network order) into the ring. Constant
// time (one bounded copy), never allocates, blocks or logs; a single producer.
void discovery_frame_tap(const uint8_t *frame, size_t len, uint32_t our_ip);

// The seen-devices table and listener status as one JSON object, newest
// first, into buf (cap bytes, NUL-terminated). Every string is escaped; the
// object is always complete ("truncated":true when devices were left out).
// Returns the length. For GET /api/devices.
size_t discovery_devices_json(char *buf, size_t cap);

// For the front panel: the number of devices seen (in the table), and the
// newest one's label (or IP) into label and its first-seen uptime (s) into
// *first_up_s. Either pointer may be NULL. Any task; takes the table lock.
int discovery_summary(char *label, size_t len, uint32_t *first_up_s);

// For the front panel's LAN talkers: up to max devices with the most packets
// an hour (all protocols, over first to last seen, at least
// DISCOVERY_RATE_MIN_S), busiest first, into out. Returns how many. label is
// the device's best label and vendor its MAC vendor, "" if none. Any task;
// takes the table lock.
#define DISCOVERY_VENDOR_LEN    41      // OUI_NAME_MAX
#define DISCOVERY_RATE_MIN_S    600
typedef struct {
    uint32_t ip;                        // network order, 0 = unknown
    uint8_t  mac[6];
    uint32_t per_hour;
    char     label[DISCOVERY_LABEL_LEN];
    char     vendor[DISCOVERY_VENDOR_LEN];
} discovery_talker_t;
int discovery_top_talkers(discovery_talker_t *out, int max);

// The best label of the device with this MAC (if not NULL and known) or IP,
// into buf. False, and buf "", if there is none. Any task; takes the lock.
bool discovery_label_for(uint32_t ip, const uint8_t mac[6], char *buf, size_t len);

#ifdef __cplusplus
}
#endif
