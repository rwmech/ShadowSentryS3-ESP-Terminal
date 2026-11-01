#pragma once
/*
 * Crash records on the admin port (fork, 2026-11-01), see storage/crash.h.
 *
 *   GET  /api/crashes      {"count":N,"crashes":[{summary},...],"latest":"<report>",
 *                           "latest_this_boot":bool}: the summaries in
 *                           /spiffs/crash.log, oldest first, and the newest full
 *                           report as text (decode with tools/decode_crash.py)
 *   POST /api/debug/crash  {"type":"abort"|"fault"|"wdt"}: debug only, not in the
 *                           dashboard. Answers 202, then crashes the board on
 *                           purpose (abort(), a store to address 0, or a spin
 *                           with interrupts off for the interrupt watchdog), to
 *                           prove the capture end to end.
 *
 * Basic auth and, for the POST, the X-ShadowSentry header are checked by
 * admin_panel.c before any handler runs.
 */
#include <stdbool.h>

// Handles the routes above; false for anything else.
bool api_crash_handle(int sock, const char *req, int req_len);
