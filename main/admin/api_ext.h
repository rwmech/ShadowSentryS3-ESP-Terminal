#pragma once
#include <stdbool.h>

/*
 * Fork routes on the admin port (Basic auth already checked by admin_panel.c):
 *
 *   GET  /api/settings        settings, secrets reported only as "<name>_set"
 *   POST /api/settings        JSON body, fields present are applied
 *   POST /api/reboot          204, restart after ~500 ms
 *   POST /api/buzzer/test     the alarm pattern, even with the sound off
 *   GET  /api/summary         microSD status and summary metrics
 *   GET  /api/logs            day files on the card, newest first
 *   GET  /api/logs/file?f=NAME[&tail=1][&dl=1]   one day file as NDJSON
 *
 * req is the first recv() of the request, NUL-terminated, req_len bytes.
 * Returns true when the request was one of these routes and has been answered.
 */
bool api_ext_handle(int sock, const char *req, int req_len);

/*
 * Every POST must carry an "X-ShadowSentry:" header. A page on another site
 * cannot add one without a CORS preflight, which this server never grants, so
 * a browser holding the Basic auth can't be used for cross-site POSTs (CSRF).
 */
bool api_ext_csrf_ok(const char *req);
