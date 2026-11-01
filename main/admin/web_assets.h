#pragma once
#include <stdbool.h>

/*
 * The admin port's web pages (fork addition, Robert Mech; Basic auth already
 * checked by admin_panel.c). Embedded gzip-compressed (main/gz/, written by
 * tools/gzip_assets.py at build time) and sent as they are with
 * Content-Encoding: gzip, about a third of the plain size:
 *
 *   GET /device?..     the device page (main/device.html; it reads its own query)
 *   GET /analysis.js   the device analysis rules both pages load (main/analysis.js)
 *   the dashboard      (main/index.html) through web_assets_dashboard(), which
 *                      admin_panel.c calls for every other GET, as upstream did
 *
 * Each has an ETag (a hash of its bytes, worked out once); a request with a
 * matching If-None-Match gets 304 with no body, so a reload costs one small
 * answer. Cache-Control: no-cache, so the browser always asks. A client that
 * does not accept gzip gets 406 (every browser does; use curl --compressed).
 */

// GET /device or /analysis.js: answered, true. Anything else: false.
bool web_assets_handle(int sock, const char *req, int req_len);

// The dashboard, for admin_panel.c's catch-all GET.
void web_assets_dashboard(int sock, const char *req);
