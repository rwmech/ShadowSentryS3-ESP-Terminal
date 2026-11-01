#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MikroTik router, read only, Core 1 (fork addition, Robert Mech)
 *
 * A RouterOS v7 REST client (https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API):
 * GET http(s)://<router>/rest/<menu path> with HTTP Basic auth. Every value in
 * a reply is a JSON string. Only GET is ever sent: nothing is written to the
 * router, ever.
 *
 * Polled every MIKROTIK_POLL_S, one request at a time (RouterOS runs one
 * user's requests one at a time anyway), into a host cache keyed by MAC:
 *   /rest/ip/dhcp-server/lease                 mac-address, address, active-address,
 *                                              host-name, client-id, status, last-seen
 *   /rest/ip/arp                               address, mac-address, interface
 *   /rest/interface/bridge/host                mac-address, on-interface, bridge, local
 *   /rest/interface/wifi/registration-table    mac-address, interface, ssid, signal
 *   /rest/interface/wireless/registration-table  mac-address, interface, signal-strength
 *   /rest/caps-man/registration-table          mac-address, interface, ssid, rx-signal
 * (field names from the RouterOS 7.24 CLI reference; a menu the router does not
 * have, such as the Wi-Fi tables on a CCR, is skipped and probed again hourly).
 * Before the first poll and then every MIKROTIK_OWN_EVERY_S: /rest/interface,
 * mac-address (read-only in the 7.24 reference), the router's own MACs, for
 * the MNDP and MAC-Telnet decoys' whitelist (RouterOS announces from each
 * interface's own MAC, not only the one ARP gives for the gateway).
 *
 * On demand, at most once per MIKROTIK_CONN_MIN_S per device: one device's
 * connection tracking, /rest/ip/firewall/connection?src-address=<ip>, the
 * router filtering (protocol, src-address, src-port, dst-address, dst-port,
 * tcp-state, timeout, orig-/repl-bytes and -packets), at most
 * MIKROTIK_CONN_MAX connections, summarised by destination. A device asked
 * about is watched for MIKROTIK_WATCH_S (and the open incident's source while
 * it is open): its connections are fetched again every MIKROTIK_WATCH_POLL_S,
 * and a destination that gets new connections at a near-regular interval is
 * marked as a possible beacon. Destination names come from the router's DNS
 * cache, /rest/ip/dns/cache (name, type, data: the fields routeros-scanner's
 * dns.py reads on 7.x; A records only), read at most every
 * MIKROTIK_DNS_EVERY_S and only when an external destination has no name.
 *
 * A bound DHCP lease from a MAC never seen before raises an ATTACK_NEW_DEVICE
 * event (Code 60-02, SEV3: logged and posted, no incident unless its alert
 * switch is on). The known MACs live in NVS; the first poll on a new board
 * learns the current leases without events.
 *
 * Transport: http:// is plain (Basic credentials in the clear on the LAN).
 * https:// is verified by the SHA-256 fingerprint of the router's (normally
 * self-signed) certificate: the pin from settings, else the one recorded on
 * first use (NVS), else the first one seen is recorded. A different
 * certificate is refused until it is pinned or the record is forgotten.
 * Verification is never switched off.
 *
 * Off (no URL, user or password, or switched off) means no task and no RAM.
 * Unreachable means a quiet exponential backoff (30 s to 30 min) and the last
 * good cache, served with its "as of" time.
 *
 * Threading: one task (stack in PSRAM: HTTP(S), RAM and queues only; the rare
 * NVS write goes to a short-lived internal-stack helper task). The getters
 * below are safe from any task; they copy under a mutex with a short timeout.
 */

#define MIKROTIK_TASK_STACK     6144    // PSRAM; the high-water mark is logged after the first poll
#define MIKROTIK_TASK_PRIO      2
#define MIKROTIK_POLL_S         300
#define MIKROTIK_CONN_MIN_S     20      // on-demand connection fetches, per device
#define MIKROTIK_CONN_MAX       200     // connections read per device
#define MIKROTIK_WATCH_S        900     // a device asked about is watched this long
#define MIKROTIK_WATCH_POLL_S   60      // a watched device's connections are fetched this often
#define MIKROTIK_HOSTS_MAX      128
#define MIKROTIK_DST_MAX        48      // destinations kept per device
#define MIKROTIK_DNS_NAMES      128     // router DNS cache names kept (address to name)
#define MIKROTIK_DNS_EVERY_S    120
#define MIKROTIK_KNOWN_MAX      160     // MACs remembered for new-device detection (960 B of NVS, a 16 KB partition)
#define MIKROTIK_OWN_MAX        32      // the router's own interface MACs kept (distinct)
#define MIKROTIK_OWN_EVERY_S    3600    // and read again this often

#define MIKROTIK_NAME_LEN       48
#define MIKROTIK_IF_LEN         24

// ── Settings side ─────────────────────────────────────────────────────────────

// Start the task if MikroTik is configured and on and the task is not running.
// Reads NVS (recorded fingerprint, known MACs), so call it from a task with an
// internal stack: app_main at boot, the admin task after a settings save.
void mikrotik_start(void);

// Tell the task the settings changed (new URL, credentials or pin): it drops
// the backoff and polls again soon. Safe from any task.
void mikrotik_settings_changed(void);

bool mikrotik_running(void);

// Forget the fingerprint recorded on first use, so the next https connection
// records the certificate it sees. Writes NVS: admin task.
void mikrotik_cert_forget(void);

// ── The router's own MACs ─────────────────────────────────────────────────────

// True if mac is one of the router's interface MACs as last read. Safe from
// any task (a copy under a spinlock).
bool mikrotik_own_mac(const uint8_t mac[6]);

// -1 the client is off (not configured or switched off), 0 the interfaces
// have not been read yet (also before the task has started), 1 read.
// *n (may be NULL): MACs held.
int mikrotik_own_macs_state(uint16_t *n);

// ── Host cache ────────────────────────────────────────────────────────────────

#define MIKROTIK_SRC_LEASE   0x01
#define MIKROTIK_SRC_ARP     0x02
#define MIKROTIK_SRC_BRIDGE  0x04
#define MIKROTIK_SRC_WIFI    0x08

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;                            // network order, 0 = unknown
    uint8_t  src;                           // MIKROTIK_SRC_* bits: where it was seen
    int8_t   signal;                        // dBm, 0 = unknown
    bool     new_device;                    // its lease raised a 60-02 event
    uint32_t first_seen;                    // unix time the cache first had it
    char     hostname[MIKROTIK_NAME_LEN];   // lease host-name (router text)
    char     client_id[MIKROTIK_NAME_LEN];
    char     lease_status[12];              // bound, waiting, offered, ...
    char     last_seen[20];                 // as RouterOS prints it ("2m10s")
    char     port[MIKROTIK_IF_LEN];         // bridge host on-interface: the switch port
    char     bridge[MIKROTIK_IF_LEN];
    char     arp_if[MIKROTIK_IF_LEN];       // ARP interface
    char     wifi_if[MIKROTIK_IF_LEN];      // registration-table interface: the AP or radio
    char     ssid[33];
} mikrotik_host_t;

// The host with this MAC (if mac is not NULL), else with this IP. *as_of is
// the time of the last good poll. False if not cached.
bool mikrotik_host(const uint8_t *mac, uint32_t ip, mikrotik_host_t *out, uint32_t *as_of);

// ── Connections ───────────────────────────────────────────────────────────────

enum { MIKROTIK_CONN_NONE = 0, MIKROTIK_CONN_OK, MIKROTIK_CONN_ERROR };

typedef struct {
    uint32_t ip;                // destination, network order
    uint16_t port;
    uint8_t  proto;             // 6 tcp, 17 udp, 1 icmp, else the number, 0 unknown
    uint8_t  external;          // not RFC 1918, loopback, link-local or multicast
    uint16_t conns;             // tracked connections to it now
    uint16_t beacon_n;          // > 0: new connections seen this many times at ~beacon_s
    uint32_t beacon_s;
    uint64_t bytes_out, bytes_in;
    uint32_t pkts_out, pkts_in;
    char     tcp_state[12];     // of the newest connection
    uint32_t first_seen;        // unix time a fetch first saw it (not the connection's start:
    uint32_t last_seen;         //   conntrack has no age); last_seen: the last fetch that saw it
    char     name[48];          // the name behind the address, "" none (see name_src)
    uint8_t  name_src;          // MIKROTIK_NAME_*
} mikrotik_dst_t;

enum { MIKROTIK_NAME_NONE = 0, MIKROTIK_NAME_ROUTER_DNS, MIKROTIK_NAME_PIHOLE };

typedef struct {
    uint8_t  state;             // MIKROTIK_CONN_*
    bool     pending;           // a fetch is queued or running
    bool     truncated;         // more than MIKROTIK_CONN_MAX connections, or more destinations
    uint32_t ip;
    uint32_t as_of;             // unix time of the snapshot, 0 = none yet
    uint16_t total;             // connections read
    uint16_t external;          // of them to external hosts
    uint16_t ext_hosts;         // distinct external destination IPs
    uint16_t n_dst;
    mikrotik_dst_t dst[MIKROTIK_DST_MAX];   // busiest (bytes) first
} mikrotik_conn_t;

// Ask for this device's connections and watch it for MIKROTIK_WATCH_S.
// Non-blocking. False when MikroTik is off, the IP is not private, or the
// device was fetched or queued in the last MIKROTIK_CONN_MIN_S (the snapshot
// stands). Safe from any task.
bool mikrotik_conn_request(uint32_t ip, const uint8_t *mac);

// The last snapshot for this IP. False if there is none (out->state NONE,
// out->pending still set if one is on its way).
bool mikrotik_conn_get(uint32_t ip, mikrotik_conn_t *out);

// ── Status and test ───────────────────────────────────────────────────────────

typedef enum {
    MIKROTIK_ST_OFF = 0,        // not configured, or switched off
    MIKROTIK_ST_STARTING,       // no poll finished yet
    MIKROTIK_ST_OK,
    MIKROTIK_ST_UNREACHABLE,    // no connection, timeout, TLS failure other than the pin
    MIKROTIK_ST_AUTH,           // 401/403: user, password, policy or allowed address
    MIKROTIK_ST_CERT,           // the certificate is not the pinned or recorded one
    MIKROTIK_ST_HTTP,           // another HTTP error, or a reply that is not REST JSON
} mikrotik_state_t;

typedef struct {
    mikrotik_state_t state;
    bool     running, https, pin_set;
    int      last_status;       // HTTP status of the last request, -1 transport, -2 certificate
    uint32_t last_ok, last_try; // unix time
    uint32_t next_s;            // seconds to the next poll
    uint32_t backoff_s;         // 0 when healthy
    uint32_t polls, failures;
    uint16_t hosts, leases, arp, bridge, wifi;
    uint8_t  wifi_tables;       // bit 0 wifi, 1 wireless, 2 caps-man: the menus that answered
    uint16_t known;             // MACs remembered
    bool     learned;           // the first lease poll has seeded the known set
    uint32_t new_devices;       // 60-02 events raised since boot
    uint16_t own_macs;          // the router's own interface MACs held
    bool     own_known;         // /rest/interface has been read
    uint32_t conn_fetches;
    char     tofu[65];          // fingerprint recorded on first use, "" none
    char     seen[65];          // last certificate presented, "" none
    char     detail[64];        // last error in words, "" none
    uint32_t test_req, test_done;
    int      test_status;       // as last_status
    bool     test_ok;
    char     test_text[64];     // "CCR1036-8G-2S+, RouterOS 7.24.5 (stable)"
} mikrotik_status_t;

void mikrotik_get_status(mikrotik_status_t *out);
const char *mikrotik_state_key(mikrotik_state_t s);   // "off", "starting", "ok", ...

// Queue a connection test (GET /rest/system/resource). Its request number,
// or 0 when the task is not running.
uint32_t mikrotik_request_test(void);

// ── REST reader (the mikrotik task only) ──────────────────────────────────────

// One record of a reply: up to MIKROTIK_ROW_KV keys. Values longer than
// MIKROTIK_VAL_LEN - 1 are cut (cut set); hash is FNV-1a over the whole value,
// so a long value can still be compared.
#define MIKROTIK_ROW_KV   24
#define MIKROTIK_KEY_LEN  32
#define MIKROTIK_VAL_LEN  80
typedef struct {
    uint8_t n;
    struct {
        char     k[MIKROTIK_KEY_LEN];
        char     v[MIKROTIK_VAL_LEN];
        uint32_t hash;
        bool     cut;
    } kv[MIKROTIK_ROW_KV];
} mikrotik_row_t;

// The value of key in row, "" if absent.
const char *mikrotik_row_get(const mikrotik_row_t *row, const char *key);

// Return false to stop reading.
typedef bool (*mikrotik_row_cb)(void *ctx, const mikrotik_row_t *row);

// GET <url>/rest<path> (path starts with '/', query string included), feeding
// each record to cb. A list or a single object both work. Reads at most
// max_bytes and 20 s. Returns the HTTP status (200 ok), -1 transport error,
// -2 certificate refused, -3 a reply that is not REST JSON, -4 the reply was
// cut at the byte or time cap (the records before the cut were delivered).
// *rows = records read. Only from the mikrotik task (one request at a time).
int mikrotik_rest_get(const char *path, mikrotik_row_cb cb, void *ctx, uint32_t max_bytes, uint32_t *rows);

// Save a blob in NVS namespace "mikrotik" from a short-lived helper task with
// an internal stack (the mikrotik task must not write flash). data is copied.
void mikrotik_nvs_save(const char *key, const void *data, size_t len);

#ifdef __cplusplus
}
#endif
