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
 *      "truncated":bool,"timed_out":bool,"scanned_bytes":n,"ms":n,
 *      "long_skipped":n}
 *     then the matching lines as written on the card, newest first.
 *     Each file is read backwards from its end, so the newest lines come
 *     first: day files run to several MB and the card reads at about
 *     150 KB/s on this board. The scan stops at the limit, or after
 *     DEVLOG_TIME_MS so the single admin task never stalls ("timed_out");
 *     either way "truncated" is true (older lines may match). Lines over
 *     DEVLOG_CHUNK bytes are skipped and counted.
 *
 * Buffers (a 16 KB read piece and a 256 KB arena for the matching lines,
 * 32 KB if PSRAM is short) are in PSRAM, freed before returning. Reads the
 * card from the admin task, one file open at a time (FATFS is reentrant; the
 * SD writer keeps its own).
 * Returns true when the request was this route and has been answered.
 */
bool api_devlog_handle(int sock, const char *req, int req_len);
