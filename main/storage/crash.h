#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Crash capture (fork, 2026-11-01): a panic record in RTC memory, reported
 * on the next boot. The board runs without a serial console, so a Guru
 * Meditation would otherwise leave nothing but the reset reason.
 *
 * At panic: esp_panic_handler() is wrapped (-Wl,--wrap=esp_panic_handler in
 * main/CMakeLists.txt). The wrapper copies the exception cause and reason or
 * abort/assert text, the faulting PC, the exception registers, up to
 * CRASH_BT_MAX backtrace PCs, the task on each core, the uptime, the wall
 * clock (from a sample taken every 30 s), free heap (internal and total),
 * the internal minimum, the firmware version and the ELF SHA256 prefix into
 * an RTC_NOINIT record with a magic and a CRC-32, then calls the original
 * handler. No allocation, no lock, no flash or filesystem access. The
 * interrupt watchdog and a task watchdog set to panic take the same path.
 *
 * Next boot (crash_init(), early in app_main): if the reset reason is a
 * panic or a watchdog, a valid record becomes a readable report. A one-line
 * JSON summary is appended to /spiffs/crash.log (the last CRASH_LOG_KEEP,
 * file kept under CRASH_LOG_MAX bytes), the report is saved as
 * /spiffs/crash_last.txt, and a short task queues it to the card as
 * /sd/crash/YYYY-MM-DD_HH-MM-SS.txt once the card and the clock are ready
 * (SNTP waited for up to 60 s, else named by uptime). A watchdog or panic
 * reset without a valid record is logged with its reset reason only. The
 * RTC record is cleared either way.
 *
 * Decode on the PC: tools/decode_crash.py <report or summary> <firmware.elf>.
 */

#define CRASH_BT_MAX        16              // backtrace PCs kept
#define CRASH_LOG_PATH      "/spiffs/crash.log"
#define CRASH_LAST_PATH     "/spiffs/crash_last.txt"
#define CRASH_SD_DIR        "/sd/crash"
#define CRASH_LOG_KEEP      20              // summaries kept in crash.log
#define CRASH_LOG_MAX       (8 * 1024)      // crash.log size cap, oldest lines dropped
#define CRASH_REPORT_MAX    2048            // full report text

// The newest summary, for /api/status and the boot notification.
typedef struct {
    bool     valid;         // a crash has been recorded (this boot or earlier)
    bool     this_boot;     // this boot followed it
    uint32_t ts;            // wall clock at the crash, 0 if the clock was not set
    char     cause[40];     // "LoadProhibited", "abort", "assert", "Interrupt watchdog", ...
    char     task[17];      // task on the faulting core
    uint32_t pc;            // faulting PC, 0 without a record
} crash_summary_t;

// Read and clear the RTC record, write the logs, start the card writer. Call
// from app_main after log_store_init() (SPIFFS mounted), settings_init()
// (time zone set) and sd_log_init() (its queue and mutex), before the traps
// start. Also arms the panic hook's clock sample. The hook itself is live
// from reset; before this call it records no version or ELF hash.
void crash_init(void);

// Copy of the newest summary (from this boot or crash.log). False if none.
bool crash_last(crash_summary_t *out);

// The summaries in crash.log, oldest first, one JSON object a line (written
// by this module, so already valid JSON), and the newest full report as
// plain text. Both are filled in crash_init() and not changed after, so any
// task may read them. Length 0 if there is none.
const char *crash_log_text(size_t *len);
const char *crash_report_text(size_t *len);

// Deliberate abort() for the debug route (POST /api/debug/crash): proves the
// capture end to end. Does not return.
void crash_debug_abort(void) __attribute__((noreturn));
