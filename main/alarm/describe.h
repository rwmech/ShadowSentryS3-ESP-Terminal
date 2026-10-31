#pragma once

/*
 * Plain-English headlines and severity tiers for attack events (fork
 * addition, Robert Mech). Pure functions over an attack_log_t: no state, no
 * locks, no allocation, safe from any task. Stack use is under 400 B.
 *
 * Tiers are for presentation and counting only. The alert mask in Settings
 * still decides what alarms.
 *   SEV1  incident-worthy: credentials, shell and ADB commands, port scans,
 *         ARP spoof and sweeps, Wi-Fi deauth, tripwire hits, HTTP login POSTs
 *   SEV2  counted and shown, no siren on their own: probes, and HTTP requests
 *         that are scanners, scripts, dotfile or traversal paths, odd methods,
 *         oversize or non-HTTP (decided per event, from the payload)
 *   SEV3  information: LAN discovery
 *
 * Headlines quote only short attacker tokens (a command's first word, a path,
 * a user name), as printable ASCII cut with "...": '`' and '"' become '\'',
 * and '#' (the panel's recolor marker) a space. Callers that need more (JSON,
 * Discord mentions) still escape the result.
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

#define DESCRIBE_MAX    96      // a headline fits in this, NUL included

// The event's tier.
describe_tier_t describe_tier(const attack_log_t *e);

// "alert", "probe" or "info".
const char *describe_tier_key(describe_tier_t t);

// One sentence into out (len bytes, NUL-terminated, at most DESCRIBE_MAX - 1
// characters used). Returns the length written.
size_t describe_event(const attack_log_t *e, char *out, size_t len);

#ifdef __cplusplus
}
#endif
