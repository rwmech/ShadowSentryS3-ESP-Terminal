#pragma once
#include <stdbool.h>

/*
 * Vendor database routes on the admin port (Basic auth and the X-ShadowSentry
 * POST header already checked by admin_panel.c):
 *
 *   GET  /api/oui    {"present","count","build_ts","size","lookups","hits",
 *                     "queued","pool_used","card"}
 *   POST /api/oui    the raw oui.bin from tools/make_oui.py as the body, at most
 *                    OUI_MAX_BYTES. Received into PSRAM, header checked against
 *                    the length, then handed to sd_log's writer, which writes
 *                    /sd/oui.bin.tmp and renames it over /sd/oui.bin.
 *                    200 {"ok":true,"count","build_ts","size"}; 400 bad header,
 *                    411 no length, 413 too big, 503 no card or no memory.
 *
 * Returns true when the request was one of these routes and has been answered.
 */
bool api_oui_handle(int sock, const char *req, int req_len);
