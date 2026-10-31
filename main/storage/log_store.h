#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    ATTACK_RTSP   = 0,
    ATTACK_HTTP   = 1,
    ATTACK_TELNET = 2,
    ATTACK_SSH    = 3,
    ATTACK_FTP    = 4,
    ATTACK_ARP    = 5,   // ARP-spoof / MITM detection (not a port honeypot)
    ATTACK_WIFI   = 6,   // 802.11 radio-layer attack (deauth/disassoc flood)
    ATTACK_SHELL  = 7,   // interactive fake-shell session (Telnet post-login)
    // Append only: the value is stored in the flash ring and on the microSD.
    ATTACK_SCAN      = 8,   // port scan: many distinct ports from one source (detect/detect.c)
    ATTACK_PROBE     = 9,   // SYN to a trap port with no login or request
    ATTACK_ARP_SWEEP = 10,  // one MAC asking who-has for many hosts
    ATTACK_ADB       = 11,  // Android Debug Bridge on 5555 (honeypot/adb_trap.c)
    ATTACK_TRIPWIRE  = 12,  // connection to a tripwire port (honeypot/tripwire.c)
    ATTACK_TYPE_COUNT       // number of types; size every per-type table with it
} attack_type_t;

typedef struct {
    uint32_t      timestamp;     // Unix epoch (seconds)
    uint32_t      src_ip;        // IPv4 in network byte order
    uint8_t       src_mac[6];    // attacker L2 MAC from ARP; all-zero if unresolved
    attack_type_t type;
    char          username[32];
    char          password[64];
    char          payload[128];
} attack_log_t;

// Must be called once before any other function (from Core 1 / admin world)
void log_store_init(void);

// Thread-safe: can be called from any core/task
void log_store_append(const attack_log_t *entry);

// Register a real-time listener invoked on every log_store_append(). Listeners
// (WebSocket push, alarm engine, front panel) run in the appending task's
// context, which can be a 3 KB honeypot stack, so each MUST be non-blocking and
// stack-light: copy what it needs into a queue and return. Up to
// LOG_STORE_MAX_LISTENERS; register at boot, before the traps start.
#define LOG_STORE_MAX_LISTENERS 6
void log_store_add_listener(void (*cb)(const attack_log_t *entry));

// Copy up to max_count most-recent entries into out[], newest first.
// Returns actual number of entries copied.
int  log_store_get_recent(attack_log_t *out, int max_count);

// All-time attack counter (persisted across reboots via SPIFFS).
uint32_t log_store_total_count(void);

// Wipe RAM ring buffer and SPIFFS files.
void log_store_clear(void);
