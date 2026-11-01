#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Block list for the router to pull (fork addition, Robert Mech)
 *
 * Rob's choice, 2026-11-01, "Router pulls list": the sentry keeps a list
 * and serves it; a scheduler on the router (tools/routeros/blocklist.rsc)
 * fetches it every minute, validates every line itself and syncs two
 * address lists that two forward-chain drop rules use. The sentry never
 * writes to the router, and its router login stays read-only.
 *
 *   dst <ip>  traffic from the LAN to that address is dropped (forward chain)
 *   src <ip>  the device itself: its forward traffic (the internet and other
 *             subnets) is dropped; it may still reach devices on its own
 *             LAN segment (bridged traffic does not pass the IP firewall)
 *
 * Damage limits, if the sentry were compromised: at most BLOCK_MAX entries;
 * an address on the never-block list is refused here and again on the router
 * (its own list); the router fetches data, never a script; the drop rules
 * are in the forward chain only, so the router's management and the admin
 * PCs' access to it are untouched.
 *
 * Never blocked (refused at add time, BLOCK_NEVER, with the reason):
 * 0.0.0.0/8, 127/8, multicast and above (224/4, 240/4, 255.255.255.255),
 * this board, its subnet's broadcast, the gateway and the router's address,
 * the Pi-hole (ROUTER_PIHOLE_IP, else the Pi-hole client's address), every
 * admin allowlist entry, ROUTER_ADMIN_IPS and ROUTER_NEVER_BLOCK.
 *
 * Stored in NVS (namespace "block", one blob of the entries in use, 52 B
 * each: at most 3.3 KB of the 16 KB partition). Add and remove run on the
 * admin task (NVS write) and log a {"kind":"block"} line on the card and a
 * Discord notice.
 */

#ifndef ROUTER_NEVER_BLOCK
#define ROUTER_NEVER_BLOCK      ""      // "192.168.0.10,192.168.0.11": Rob's PC and the like, up to 16
#endif
_Static_assert(sizeof(ROUTER_NEVER_BLOCK) <= 272, "ROUTER_NEVER_BLOCK must be at most 271 characters");

#define BLOCK_MAX           64
#define BLOCK_NOTE_MAX      41          // 40 printable ASCII characters and the NUL
#define BLOCK_NEVER_EXTRA   16

typedef enum { BLOCK_DST = 0, BLOCK_SRC = 1 } block_kind_t;

typedef struct {
    uint32_t ip;                        // network order
    uint32_t ts;                        // unix time added (or last updated)
    uint8_t  kind;                      // block_kind_t
    char     note[BLOCK_NOTE_MAX];
} block_entry_t;

typedef enum {
    BLOCK_OK = 0,                       // added
    BLOCK_UPDATED,                      // already there: note and time updated
    BLOCK_NEVER,                        // on the never-block list (why says which)
    BLOCK_FULL,
    BLOCK_BAD,                          // a note that is not printable ASCII, or too long
    BLOCK_SAVE,                         // NVS write failed (nothing changed)
    BLOCK_NOT_FOUND,
} block_result_t;

// Boot, after settings_init() (reads NVS on the caller's stack).
void blocklist_init(void);

// "dst" / "src", and back. False for anything else.
const char *blocklist_kind_key(uint8_t kind);
bool blocklist_kind_parse(const char *s, block_kind_t *out);

// True, and why ("the router", "this board", ...), if ip may never be blocked.
bool blocklist_never(uint32_t ip, char *why, size_t len);

// The never-block addresses known right now (fixed ranges left out).
int blocklist_never_list(uint32_t *ip, const char **why, int max);

// Admin task only (NVS write).
block_result_t blocklist_add(uint32_t ip, block_kind_t kind, const char *note, char *why, size_t len);
block_result_t blocklist_remove(uint32_t ip, block_kind_t kind);

// A copy of the list, oldest first. Returns the count.
int blocklist_get(block_entry_t *out, int max);

// The served list: "dst a.b.c.d\n" lines, nothing else. Returns the length
// (0 when empty), or (size_t)-1 when it did not fit: never serve a cut list,
// the router would unblock what was cut. BLOCK_MAX * 20 bytes always fit.
size_t blocklist_text(char *buf, size_t cap);

// Router fetches, for the status: count, last time, refused requests.
void blocklist_note_fetch(bool served);
void blocklist_fetch_stats(uint32_t *served, uint32_t *last, uint32_t *refused);

#ifdef __cplusplus
}
#endif
