#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "log_store.h"

/*
 * Discord alerts, Core 1 (fork addition, Robert Mech)
 *
 * Posts to a Discord channel webhook (Settings: discord_webhook):
 *   - incident embeds: opened (red), acknowledged (amber), closed (green), and
 *     a reminder (orange) every alarm_remind_s while unacknowledged
 *   - a deduplicated event log (Settings: discord_log_events): events are
 *     folded by (source IP, attack type, short summary) and posted as plain
 *     code-block lines every DISCORD_BATCH_S, one line per key with a count
 *
 * The alarm and log_store listeners only copy and enqueue. One task does all
 * the HTTPS work, paced for Discord's webhook limit (about 5 posts per 2 s),
 * honouring 429 retry_after. Every post sets allowed_mentions parse [], and
 * attacker text is cut to printable ASCII with backticks replaced, so it can
 * neither ping anyone nor break out of its code span. The webhook URL is never
 * logged or returned.
 */

#define DISCORD_BATCH_S        15    // event log batch interval
#define DISCORD_KEY_WINDOW_S   300   // a key posts at most once per window
#define DISCORD_KEY_IDLE_S     600   // a key idle this long is forgotten
#define DISCORD_TASK_STACK     6144  // bytes; the high-water mark is logged after the first post

// Create the queues and register the alarm and log_store listeners. Call once
// at boot, before the traps start. Never blocks.
void discord_init(void);

// FreeRTOS task entry point, Core 1. Spawn after discord_init().
void discord_task(void *arg);

// Queue an event for the event log without going through the log store (LAN
// discovery keeps its events out of the flash ring). Same path as the
// log_store listener: copy and enqueue, never blocks, safe from any task.
void discord_log_event(const attack_log_t *e);

// Post the LAN discovery digest: "LAN devices seen (last 30 min)" and lines
// (newline-separated, PSRAM heap buffer) in a code block. Ownership of lines
// passes here in every case: freed after the post, or at once (false) when the
// event log or Discord is off or a digest is already waiting. The caller keeps
// it under about 1800 characters. Never blocks.
bool discord_post_digest(char *lines);

// Queue a test embed. Returns its request number (compare with test_done in
// discord_status_t), or 0 when the task is not running.
uint32_t discord_request_test(void);

typedef struct {
    uint32_t test_req;      // last test requested
    uint32_t test_done;     // last test finished
    int      test_status;   // its HTTP status, -1 transport error, 0 no webhook
    bool     test_ok;
    int      last_status;   // last post's HTTP status (same coding)
    uint32_t posted;        // posts accepted by Discord
    uint32_t failed;        // posts given up on
    uint32_t dropped;       // events or transitions lost to a full queue
} discord_status_t;

void discord_get_status(discord_status_t *out);
