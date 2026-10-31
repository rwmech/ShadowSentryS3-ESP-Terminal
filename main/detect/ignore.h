#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Ignore list: sources whose events are logged (flagged "ignored") but never
 * open an incident or send an alert.
 *
 * Up to IGNORE_MAX entries, each an IPv4 and/or a MAC, with a note and the time
 * it was added, kept in NVS (namespace "ignore", key "list"). An entry matches
 * an event when its IP equals the event's source IP or its MAC equals the
 * event's source MAC, so an entry holding both covers the device after DHCP
 * moves it.
 *
 * The panel only adds; removal is dashboard-only (POST /api/ignore), so the
 * backend can always undo what the panel did.
 */

#define IGNORE_MAX       32
#define IGNORE_NOTE_MAX  40     // bytes, NUL included

typedef struct {
    uint32_t ip;                // network order; 0 = no IP
    uint8_t  mac[6];            // all zero = no MAC
    uint8_t  _pad[2];
    uint32_t added_ts;          // unix time (0 before SNTP)
    char     note[IGNORE_NOTE_MAX];
} ignore_entry_t;

// Load from NVS. Call once at boot, before any event can be logged.
void ignore_init(void);

// Add an entry. ip 0 and mac NULL or all zero mean "none"; one of the two must
// be given. An entry with the same IP and MAC is not added twice (ESP_OK).
// The note is copied up to IGNORE_NOTE_MAX - 1 bytes, control characters
// replaced. ESP_ERR_NO_MEM when the list is full, ESP_ERR_INVALID_ARG when
// neither is given. Writes NVS: call from a task with a few KB of stack.
esp_err_t ignore_add(uint32_t ip, const uint8_t *mac, const char *note);

// Remove entry index (as returned by ignore_list). ESP_ERR_INVALID_ARG if out
// of range.
esp_err_t ignore_remove(int index);

// Copy up to max entries, in list order. Returns the number copied.
int ignore_list(ignore_entry_t *out, int max);

// True if the source matches an entry. Cheap (no flash), lock-protected, safe
// from any task, including a 3 KB honeypot stack.
bool ignore_match(uint32_t ip, const uint8_t mac[6]);

#ifdef __cplusplus
}
#endif
