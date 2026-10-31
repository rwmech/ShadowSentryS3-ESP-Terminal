#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * microSD event log, Core 1
 *
 * Every attack, alarm transition and boot is appended as one JSON line to
 * /sd/log/YYYY-MM-DD.jsonl (local date of the event; "nosync.jsonl" before
 * SNTP has set the clock). The card shares the display's SPI bus (SPI3_HOST,
 * CS GPIO10), so it is mounted only after the display has initialised the bus.
 * A writer task drains a queue, so callers (honeypot tasks with 3 KB stacks)
 * never touch FAT. The 200-entry flash ring (log_store) stays the fast copy for
 * the panel and dashboard; the card keeps everything.
 */

#define SD_MOUNT_POINT  "/sd"
#define SD_LOG_DIR      SD_MOUNT_POINT "/log"

typedef struct {
    bool     mounted;
    char     card_name[16];
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint32_t lines_written;    // since boot
    uint32_t write_errors;     // since boot
    uint32_t dropped;          // queue full, since boot
} sd_status_t;

// Create the queue and writer task and hook into log_store and the alarm.
// Call from app_main after alarm_init(), before the traps start.
void sd_log_init(void);

// The display has initialised the shared SPI bus: the writer may mount now.
void sd_log_bus_ready(void);

void sd_log_status(sd_status_t *out);

// Write a whole file on the card from the writer task, so callers never touch
// FAT. path must start with SD_MOUNT_POINT "/" and fit 63 chars; its directory
// is created if missing. Ownership of data (any heap_caps_malloc'd buffer)
// passes to sd_log in every case: it is free()d after the write, or at once if
// the request is refused (no card, queue full, bad path). Never blocks.
// Returns true if queued.
bool sd_log_write_file(const char *path, void *data, size_t len);

// Append {"kind":"snap","ts","action","file","size"} to the day log (camera
// snapshot of a panel press). Never blocks. Returns true if queued.
bool sd_log_snap(uint32_t ts, const char *action, const char *file, size_t size);

// Append one preformatted JSON line (ending in a newline) to today's log. The
// writer task owns line from here and frees it; allocate it from PSRAM
// (heap_caps_malloc(MALLOC_CAP_SPIRAM)). Freed at once, and false, if there is
// no card or the queue is full. Never blocks. Used by the HTTP engine for its
// {"kind":"http"} request lines.
bool sd_log_line(char *line, size_t len);

// Save the summary metrics now (queued to the writer task). Call before a
// deliberate restart, then give it ~300 ms.
void sd_log_flush(void);

// ── Summary metrics ───────────────────────────────────────────────────────────
//
// Maintained by the writer task from every attack and saved to /sd/stats.bin
// once a minute (RAM only when there is no card). Top-N tables use the
// space-saving algorithm, so counts for evicted-then-returning entries are
// upper bounds; the leaders are exact in practice.

#define STATS_SRC_MAX   64
#define STATS_CRED_MAX  32
#define STATS_DAYS      30
// by_type[] has room for types added later without a stats.bin format change;
// sd_log.c asserts ATTACK_TYPE_COUNT fits. Only the first ATTACK_TYPE_COUNT are used.
#define STATS_TYPE_SLOTS 16

typedef struct {
    uint32_t ip;               // network order
    uint8_t  mac[6];
    uint8_t  last_type;
    uint8_t  _pad;
    uint32_t count;
    uint32_t first_ts, last_ts;
} stat_src_t;

typedef struct {
    char     user[32];
    char     pass[32];
    uint32_t count;
} stat_cred_t;

typedef struct {
    uint32_t magic, version;
    uint32_t total;
    uint32_t by_type[STATS_TYPE_SLOTS];   // index attack_type_t (v1 had 8)
    uint32_t first_ts, last_ts;
    uint32_t hour_key[24];     // unix hour held in each slot
    uint32_t hour_count[24];
    uint32_t day_key[STATS_DAYS];   // local YYYYMMDD
    uint32_t day_count[STATS_DAYS];
    stat_src_t  src[STATS_SRC_MAX];
    stat_cred_t cred[STATS_CRED_MAX];
} sd_stats_t;

// Consistent snapshot of the metrics.
void sd_log_stats(sd_stats_t *out);

#ifdef __cplusplus
}
#endif
