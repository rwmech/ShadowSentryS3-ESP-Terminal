#pragma once
#include <stdbool.h>

/*
 * Per-device log route on the admin port (fork addition, Robert Mech; Basic
 * auth already checked by admin_panel.c):
 *
 *   GET /api/logs/device?mac=aa:bb:cc:dd:ee:ff&ip=192.168.0.50&days=N&limit=M
 *
 *     Every microSD log line (/sd/log/YYYY-MM-DD.jsonl) whose "mac" or "ip"
 *     is this device's, from the newest N day files (default 2, at most 7),
 *     newest first, at most M lines (default 300, at most 1000).
 *     mac and ip are optional, one is required; mac is matched in any case.
 *     No path input: the files are found by listing the log directory.
 *
 *     The answer is NDJSON (application/x-ndjson): a first line
 *     {"kind":"meta","matched":n,"files":k,"days":N,"limit":M,
 *      "truncated":bool,"timed_out":bool,"long_skipped":n}
 *     then the matching lines as written on the card, newest first.
 *     "truncated" is true when matching lines were left out (the limit, or
 *     the time box). The scan stops after DEVLOG_TIME_MS so the single admin
 *     task never stalls; "timed_out" says so. Lines over DEVLOG_CHUNK bytes
 *     are skipped and counted.
 *
 * Buffers (an 8 KB read chunk and two 8 B-per-line index tables) are in
 * PSRAM, freed before returning. Reads the card from the admin task, one
 * file open at a time (FATFS is reentrant; the SD writer keeps its own).
 * Returns true when the request was this route and has been answered.
 */
bool api_devlog_handle(int sock, const char *req, int req_len);
