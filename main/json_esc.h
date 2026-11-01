#pragma once
/*
 * One JSON string escaper for everything the board sends (fork, 2026-11-01).
 *
 * Attacker bytes reach the API, the WebSocket feed, the SD log and Telegram:
 * usernames, passwords, payloads. Before this, each emitter had its own
 * escaper and passed bytes 0x80..0xFF through raw, so a credential like
 * "\xfd\x06" made /api/summary invalid JSON (not UTF-8).
 */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Escape in (at most in_max bytes, stopping at a NUL) as the inside of a JSON
 * string into out (cap bytes, always NUL-terminated). '"' and '\' are
 * backslash-escaped, \n \r \t by name, other control bytes and DEL as \u00XX.
 * Well-formed UTF-8 (RFC 3629: no overlongs, no surrogates, at most U+10FFFF)
 * passes through; every other byte at or above 0x80 becomes U+FFFD. Output is
 * cut at a whole character or escape, never inside one. Returns its length.
 */
size_t json_esc(const char *in, size_t in_max, char *out, size_t cap);

/*
 * Replace, in place, every byte of p[0..n) that is not part of well-formed
 * UTF-8 with '?'. For text that is already JSON (old SD log lines) but may
 * hold raw bytes from before json_esc(); the length does not change.
 */
void utf8_sanitize(char *p, size_t n);

#ifdef __cplusplus
}
#endif
