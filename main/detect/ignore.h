#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Ignore list: sources, or one alert code from a source, whose events are
 * logged (flagged "ignored") but never open an incident or send an alert.
 *
 * Up to IGNORE_MAX entries, each an IPv4 and/or a MAC, an optional alert code
 * ("17-01", see describe.h), a note and the time it was added, kept in NVS
 * (namespace "ignore", key "list2"; entries under the old key "list", from
 * before codes, are migrated at boot with an empty code). An entry matches an
 * event when its IP equals the event's source IP or its MAC equals the
 * event's source MAC, so an entry holding both covers the device after DHCP
 * moves it, and when its code is empty (the whole device) or equal to the
 * event's code (that error only).
 *
 * The panel only adds; removal is dashboard-only (POST /api/ignore), so the
 * backend can always undo what the panel did.
 */

#define IGNORE_MAX       32
#define IGNORE_NOTE_MAX  40     // bytes, NUL included
#define IGNORE_CODE_MAX   6     // "17-01" and its NUL

typedef struct {
    uint32_t ip;                // network order; 0 = no IP
    uint8_t  mac[6];            // all zero = no MAC
    char     code[IGNORE_CODE_MAX];   // "" = every code (the whole device)
    uint32_t added_ts;          // unix time (0 before SNTP)
    char     note[IGNORE_NOTE_MAX];
} ignore_entry_t;

// Load from NVS, migrating the pre-code list. Call once at boot, before any
// event can be logged.
void ignore_init(void);

// Add an entry. ip 0 and mac NULL or all zero mean "none"; one of the two must
// be given. code NULL or "" ignores the whole device, else it must look like
// "17-01" (ESP_ERR_INVALID_ARG otherwise; whether the code exists is the
// caller's check, describe_code_name()). An entry with the same IP, MAC and
// code is not added twice (ESP_OK). The note is copied up to
// IGNORE_NOTE_MAX - 1 bytes, control characters replaced. ESP_ERR_NO_MEM when
// the list is full, ESP_ERR_INVALID_ARG when neither address is given.
// Writes NVS: call from a task with a few KB of stack.
esp_err_t ignore_add(uint32_t ip, const uint8_t *mac, const char *code, const char *note);

// Remove entry index (as returned by ignore_list). ESP_ERR_INVALID_ARG if out
// of range.
esp_err_t ignore_remove(int index);

// Copy up to max entries, in list order. Returns the number copied.
int ignore_list(ignore_entry_t *out, int max);

// True if the source matches an entry whose code is empty or equal to code
// (NULL counts as "", so only whole-device entries match it). Cheap (no
// flash), lock-protected, safe from any task, including a 3 KB honeypot stack.
bool ignore_match(uint32_t ip, const uint8_t mac[6], const char *code);

#ifdef __cplusplus
}
#endif
