#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pi-hole v6 client, Core 1 (fork addition, Robert Mech)
 *
 * Optional. Reads, never writes: what Rob's Pi-hole knows about the devices the
 * board sees (names, query counts, blocked counts, top domains), to flesh out
 * the device reporting. Off unless a URL and an app password are configured
 * (settings pihole_url, pihole_password, pihole_enabled; config.h PIHOLE_URL
 * and PIHOLE_APP_PASSWORD). Off means no task, no buffers, no traffic.
 *
 * Pi-hole v6 REST API (https://docs.pi-hole.net/api/, the OpenAPI spec in
 * github.com/pi-hole/FTL src/api/docs/content/specs/), checked against FTL
 * v6.8 (master 29c8b13, 2026-10-17):
 *   POST   /api/auth {"password"}   session.valid, session.sid, session.validity
 *                                   (s; each request restarts it). 401 with
 *                                   session.valid false on a wrong password.
 *                                   An app password logs in the same way and
 *                                   never asks for 2FA; it cannot change the
 *                                   configuration (webserver.api.app_sudo off).
 *   DELETE /api/auth                logout, frees the seat (16 by default)
 *   GET    /api/info/version        version.{core,web,ftl}.local.version
 *   GET    /api/network/devices     devices[]: hwaddr, firstSeen, lastQuery,
 *                                   numQueries, macVendor, ips[]: ip, name
 *   GET    /api/stats/top_clients   clients[]: ip, name, count; with
 *                                   blocked=true count is the blocked count.
 *                                   In-memory data: the last 24 h by default.
 *   GET    /api/queries?client_ip=  queries[]: domain and status (newest first),
 *                                   for the top domains of a device's last
 *                                   PIHOLE_TOP_SAMPLE queries, each with its
 *                                   allowed and blocked counts and how it was
 *                                   blocked. status is FTL's
 *                                   get_query_status_str() (src/datastructure.c):
 *                                   allowed FORWARDED, CACHE, CACHE_STALE,
 *                                   RETRIED, RETRIED_DNSSEC; blocked as FTL's
 *                                   is_blocked(): GRAVITY, REGEX, DENYLIST and
 *                                   their _CNAME forms, EXTERNAL_BLOCKED_IP,
 *                                   _NULL, _NXRA, _EDE15, SPECIAL_DOMAIN,
 *                                   DBBUSY; UNKNOWN and IN_PROGRESS neither
 *   GET    /api/logs/dnsmasq?nextID= the DNS resolver's log (FTL src/api/logs.c,
 *                                   logs.yaml): log[]: timestamp, message, prio;
 *                                   nextID (the ID to ask for next), pid (FTL's;
 *                                   a change means FTL restarted). FTL keeps the
 *                                   last LOG_SIZE 512 lines of up to 259
 *                                   characters (src/log.h) and answers every
 *                                   line from max(nextID, newest - 512), so a
 *                                   nextID past the newest gives no lines and
 *                                   just the current nextID.
 *   GET    /api/config/dns/queryLogging   config.dns.queryLogging: false means
 *                                   dnsmasq logs no queries (FTL
 *                                   src/config/dnsmasq_config.c writes
 *                                   log-queries, or log-queries=proto with
 *                                   misc.extraLogging, only when it is true)
 * The SID goes in the X-FTL-SID header on every request. One session is kept
 * until it expires (re-auth on a 401), so the client never takes more than one
 * of Pi-hole's session seats.
 *
 * v5 (lighttpd, /admin/api.php) is detected and reported, not supported.
 *
 * Transport: one esp_http_client request at a time, on this task. http:// on
 * the LAN by default (the app password crosses the LAN in the clear, so use an
 * app password, not the admin one). https:// needs pihole_tls_sha256: the
 * SHA-256 of the server's certificate (or of a CA certificate the server
 * sends), checked on every handshake; verification is never turned off. A
 * .local host is resolved by mDNS (lwIP's one-shot query through getaddrinfo,
 * then the mdns component), cached, and resolved again after a connection
 * failure; requests go to the IP with the configured name in the Host header.
 *
 * Schedule: a sync every PIHOLE_SYNC_S, on demand (POST /api/pihole/refresh,
 * one per PIHOLE_REFRESH_MIN_S), and at once after a settings change. A failure
 * backs off from PIHOLE_BACKOFF_MIN_S doubling to PIHOLE_BACKOFF_MAX_S; the
 * last good cache stays, with its time. Errors go to the status (and the log
 * once per new error), never to alerts or Discord.
 *
 * Cache (PSRAM): up to PIHOLE_DEV_MAX devices keyed by MAC, by IP when Pi-hole
 * has no MAC. Responses are read into one PIHOLE_RESP_MAX buffer and parsed
 * with cJSON; a larger response is skipped and counted. Every string from
 * Pi-hole is untrusted and escaped by json_esc() on the way out.
 *
 * DNS answers: every PIHOLE_LOG_POLL_S the task reads the new lines of the
 * dnsmasq log (nextID paging, the 64 KB response cap: when the board fell
 * behind, it skips to the newest PIHOLE_LOG_BACK lines and counts the gap).
 * Lines parsed, each cut at PIHOLE_LOG_LINE bytes and at most 8 words:
 *   [<serial> <client>/<port> ]query[<type>] <name> from <client>
 *   [<serial> <client>/<port> ]reply|cached|cached-stale <name> is <answer>
 *   [...] <list> blocked <name> is <answer>    (only ip-api.com, see below)
 * (the optional prefix is log-queries=proto). <answer> "<CNAME>" starts or
 * continues a chain: the next reply line in a row belongs to the same
 * question, so an address is kept under the name the client asked for.
 * The asker is the prefix's client, else the newest "query" line for that
 * name in a PIHOLE_QRING ring. Kept in a PSRAM map: IPv4 address to name,
 * newest answer time and up to PIHOLE_MAP_ASKERS clients, PIHOLE_MAP_MAX
 * entries, the least recently answered evicted. A "blocked" line for
 * ip-api.com asked by this board is recorded too: it is why GeoIP owners
 * stay empty.
 *
 * Memory: the task stack (PSRAM: it only does sockets, HTTP and RAM lookups,
 * no flash, NVS or SPIFFS), the response buffer and two cache tables, all in
 * PSRAM and allocated when the task starts. pihole_init() points cJSON's
 * allocator at PSRAM first for every cJSON user: a parsed response is
 * thousands of small nodes, which would otherwise come from internal RAM.
 */

#define PIHOLE_TASK_STACK       6144    // PSRAM; high-water logged after the first sync
#define PIHOLE_TASK_PRIO        2
#define PIHOLE_SYNC_S           600     // between syncs
#define PIHOLE_REFRESH_MIN_S    30      // on-demand refresh at most this often
#define PIHOLE_BACKOFF_MIN_S    60      // after a failure, doubling ...
#define PIHOLE_BACKOFF_MAX_S    1800    // ... up to this
#define PIHOLE_TIMEOUT_MS       5000    // per request
#define PIHOLE_RESP_MAX         (64 * 1024)
#define PIHOLE_DEV_MAX          96      // cached devices (Pi-hole's devices plus clients)
#define PIHOLE_NET_DEVICES      64      // max_devices asked of /api/network/devices
#define PIHOLE_CLIENTS_MAX      128     // count asked of /api/stats/top_clients
#define PIHOLE_IPS              4       // addresses kept per device
#define PIHOLE_IP_LEN           46      // an IPv6 address as text
#define PIHOLE_NAMES            3       // distinct names kept per device
#define PIHOLE_NAME_LEN         64
#define PIHOLE_VENDOR_LEN       48
#define PIHOLE_TOP_N            10      // top domains kept per device
#define PIHOLE_DOMAIN_LEN       96      // longer domains are cut
#define PIHOLE_TOP_SAMPLE       100     // last queries counted for the top domains
#define PIHOLE_TOP_PER_SYNC     16      // devices whose queries are fetched per sync
#define PIHOLE_KNOWN_MAX        96      // discovery devices plus recent attackers
#define PIHOLE_RECENT           32      // recent attacks read for attacker IPs
#define PIHOLE_ERR_LEN          160
#define PIHOLE_LOG_POLL_S       10      // between dnsmasq log reads
#define PIHOLE_LOG_RETRY_S      60      // after a failed read
#define PIHOLE_LOG_RECHECK_S    600     // endpoint missing or logging off: ask again this often
#define PIHOLE_LOG_BACK         150     // lines read back at the start or after falling behind
#define PIHOLE_LOG_LINE         272     // a log line is cut here (FTL keeps 259)
#define PIHOLE_LOG_COVER_S      900     // the log must cover this long before "no lookup seen" is called
#define PIHOLE_MAP_MAX          4096    // addresses kept (PSRAM, about 116 B each)
#define PIHOLE_MAP_NAME         64      // a longer name is cut (matched by its full-name hash)
#define PIHOLE_MAP_ASKERS       3       // clients kept per address
#define PIHOLE_QRING            256     // recent "query" lines, for the asker of a reply

// Once at boot, after settings_init(): the table lock, the cJSON allocator
// (PSRAM first) and the settings listener. Never starts the task.
void pihole_init(void);

// Start the task if it is not running. Called at boot when Pi-hole is
// configured, and by the settings listener and the test route when it gets
// configured later (no reboot needed). Safe from any task; returns false if
// the task or its PSRAM could not be created.
bool pihole_start(void);

// Queue a connection test (auth plus GET /api/info/version) on the task,
// starting it if needed. Returns the request number (compare with test_done in
// pihole_status_t), or 0 if Pi-hole has no URL or password, or no task.
uint32_t pihole_request_test(void);

// Ask for a sync now. ip (network order, 0 for none) is fetched first for its
// top domains. Returns 0 when queued, else the seconds left before another
// refresh is allowed (rate limit), or -1 when Pi-hole is off.
int pihole_request_refresh(uint32_t ip);

typedef struct {
    bool     enabled;           // configured and switched on
    bool     running;           // the task exists
    bool     session;           // holds a session (the SID itself is never exposed)
    bool     syncing;
    char     state[12];         // "off", "starting", "ok", "error", "v5"
    char     error[PIHOLE_ERR_LEN];   // last error, "" after a good sync
    char     version[64];       // "core v6.1, web v6.1, FTL v6.1", "" unknown
    char     host[64];          // from the URL
    char     ip[16];            // resolved address, "" unknown
    char     tls_seen[65];      // https: SHA-256 hex of the last server certificate
    int      last_http;         // last HTTP status, -1 transport error, 0 none
    uint32_t last_ok_ts;        // epoch of the last good sync (0 never, or before SNTP)
    uint32_t last_ok_up;        // uptime (s) of the last good sync, 0 never
    uint32_t last_try_up;       // uptime (s) of the last attempt
    uint32_t next_in_s;         // seconds to the next sync
    uint32_t backoff_s;         // current back-off, 0 when healthy
    uint32_t devices;           // devices in the cache
    uint32_t with_top;          // of which have top domains
    uint32_t syncs, failures, requests, oversized;
    uint32_t test_req, test_done;
    bool     test_ok;
    int      test_status;       // HTTP status of the failing step, -1 transport, 0 config
    char     test_msg[PIHOLE_ERR_LEN];
    uint32_t stack_free;        // task stack high-water (B), 0 before the first sync
    // The dnsmasq log (answers). log_state: "off", "starting", "ok",
    // "no_endpoint" (404), "denied" (403), "logging_off" (dns.queryLogging
    // false), "no_queries" (lines but no query lines), "error"; log_why says
    // it in plain words when not "ok".
    char     log_state[16];
    char     log_why[PIHOLE_ERR_LEN];
    uint32_t log_since;         // epoch the log has been read without a gap since, 0 none
    uint32_t log_polls, log_lines, log_queries, log_answers, log_missed, log_gaps;
    uint32_t map_entries, map_evicted;
    uint32_t map_evict_newest;  // epoch: the newest answer evicted (coverage starts after it)
    uint32_t geo_blocked_ts;    // epoch Pi-hole last refused ip-api.com to this board, 0 never
    int8_t   query_logging;     // dns.queryLogging: 1 on, 0 off, -1 unknown
} pihole_status_t;

void pihole_get_status(pihole_status_t *out);

// For JSON routes: the cached Pi-hole data of the device with this MAC (NULL or
// all zero if unknown) or else this IPv4 (network order), as
// ,"pihole":{...} appended at buf (when lead is true; else just {...}).
// Returns the bytes written, 0 when Pi-hole is off or knows nothing of the
// device, or cap when it did not fit (buf then holds garbage up to cap).
// Every string is escaped. Any task; takes the table lock briefly. Lock order:
// callers may hold the discovery table lock; this module never takes it while
// holding its own. With answers true each top domain gains "ips": the
// addresses the DNS log saw it resolve to (one pass over the answer map, so
// for one device at a time, not for the device list).
size_t pihole_device_json(uint32_t ip, const uint8_t mac[6], char *buf, size_t cap, bool lead, bool answers);

#ifdef __cplusplus
}
#endif
