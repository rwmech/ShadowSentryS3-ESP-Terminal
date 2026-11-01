#pragma once

/*
 * Alert codes, plain-English headlines and severity tiers for attack events
 * (fork addition, Robert Mech). Pure functions over an attack_log_t: no
 * state, no locks, no allocation, safe from any task. Stack use is under
 * 400 B.
 *
 * Every event gets a two-part console code "CC-NN": the category, then the
 * item (the full table is in describe.c and the README).
 *   17  sensors and recon      ARP sweep, port scan, probe, scan ended
 *   20  access                 SSH, Telnet, FTP, RTSP logins, shell
 *   30  web                    one code per HTTP engine label
 *   40  services               ADB and one per tripwire service
 *   50  network attacks        ARP spoof, Wi-Fi deauth
 *   60  discovery and info     LAN discovery
 * HTTP and tripwire codes are picked per event from the label or service at
 * the start of the payload. Each code has one tier:
 *   SEV1  incident-worthy, opens a RED incident: credentials, shell and ADB
 *         activity, port scans, ARP spoof, Wi-Fi deauth, tripwire hits,
 *         HTTP login POSTs
 *   SEV2  opens a YELLOW incident at most, never the siren: ARP sweeps,
 *         probes, scan summaries, and HTTP requests that are scanners,
 *         scripts, dotfile or traversal paths, odd methods, oversize or
 *         non-HTTP
 *   SEV3  information: LAN discovery (opens nothing unless its alert bit is
 *         on in Settings, and then YELLOW)
 * The alert mask in Settings and the ignore list still decide whether an
 * event alerts at all.
 *
 * Headlines read "Code 17-01 ARP sweep | 192.168.0.75: 24 hosts in 10 s":
 * the code, its short name, the source (IP, else MAC, else "nearby"), then a
 * short sentence. They quote only short attacker tokens (a command's first
 * word, a path, a user name), as printable ASCII cut with "...": '`' and '"'
 * become '\'', and '#' (the panel's recolor marker) a space. Callers that
 * need more (JSON, Discord mentions) still escape the result.
 */

#include <stddef.h>
#include "log_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TIER_SEV1 = 1,
    TIER_SEV2 = 2,
    TIER_SEV3 = 3,
} describe_tier_t;

#define DESCRIBE_MAX       96   // a headline fits in this, NUL included
#define DESCRIBE_CODE_LEN   6   // "17-01" and its NUL
#define DESCRIBE_CODE_BITS 64   // rows the table may have: one bit each in alarm_info_t.codes

// The event's code, e.g. "17-01". "00-00" for an event no code covers (an
// attack type newer than the table). Never NULL; points at a constant.
const char *describe_code(const attack_log_t *e);

// Short name of a code, e.g. "ARP sweep" for "17-01". NULL if the code is
// not in the table (so it doubles as a validity check).
const char *describe_code_name(const char *code);

// Tier of a code (TIER_SEV1..3), 0 if the code is not in the table.
int describe_code_tier(const char *code);

// The event's tier: the tier of its code.
describe_tier_t describe_tier(const attack_log_t *e);

// "alert", "probe" or "info".
const char *describe_tier_key(describe_tier_t t);

// The code table, for dropdowns: describe_code_count() entries, in code
// order. describe_code_at(i, &name, &tier) returns the code and fills name
// and tier (either may be NULL); NULL when i is out of range.
int describe_code_count(void);
const char *describe_code_at(int i, const char **name, int *tier);

// One headline into out (len bytes, NUL-terminated, at most DESCRIBE_MAX - 1
// characters used), starting with "Code CC-NN <name> | ". Returns the length
// written.
size_t describe_event(const attack_log_t *e, char *out, size_t len);

#ifdef __cplusplus
}
#endif
