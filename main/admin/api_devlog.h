#pragma once
#include <stdbool.h>

/*
 * Per-device log route on the admin port (fork addition, Robert Mech; Basic
 * auth already checked by admin_panel.c):
 *
 *   (The device page itself, GET /device, and /analysis.js are served by
 *   web_assets.c.)
 *
 *   GET /api/logs/device?mac=aa:bb:cc:dd:ee:ff&ip=192.168.0.50[&limit=M][&cursor=C]
 *
 *     The microSD log lines (/sd/log/YYYY-MM-DD.jsonl) whose "mac" or "ip"
 *     is this device's, newest first, at most M (default 200, at most 1000)
 *     per request. mac and ip are optional, one is required; mac is matched
 *     in any case. No path input: files are found by listing the directory.
 *
 *     Paging: without a cursor the scan starts at the end of the newest day
 *     file. Each file is read backwards from the cursor or its end, then the
 *     next older file from its end, until the limit, the end of the oldest
 *     file, or DEVLOG_TIME_MS (3 s, so the single admin task never stalls).
 *     The answer's "cursor" ("YYYY-MM-DD.jsonl:offset") resumes exactly
 *     there; "" means the whole history has been read. A cursor must name a
 *     dated day file in the log directory and an offset within its size.
 *
 *     The answer is NDJSON (application/x-ndjson): a first line
 *     {"kind":"meta","matched":n,"files":k,"from":"<first file>","limit":M,
 *      "cursor":"..","more":bool,"timed_out":bool,"scanned_bytes":n,"ms":n,
 *      "long_skipped":n}
 *     then the matching lines as written on the card, newest first. Lines
 *     over DEVLOG_CHUNK bytes are skipped and counted; a last line still
 *     being written is left out.
 *
 * Buffers (a 16 KB read piece and a 256 KB arena for the matching lines,
 * 32 KB if PSRAM is short) are in PSRAM, freed before returning. Reads the
 * card from the admin task, one file open at a time (FATFS is reentrant; the
 * SD writer keeps its own).
 * Returns true when the request was this route and has been answered.
 */
bool api_devlog_handle(int sock, const char *req, int req_len);
