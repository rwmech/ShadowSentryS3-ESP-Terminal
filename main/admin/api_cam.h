#pragma once
#include <stdbool.h>

/*
 * Camera routes on the admin port (Basic auth already checked by admin_panel.c):
 *
 *   GET /api/snap/last         the last panel-press snapshot, image/jpeg; 404 if none
 *   GET /api/snap/last.json    {"camera","seq","ts","action","file","size","width","height"}
 *                              (seq 0 and empty fields if there is none yet)
 *
 * A query string (cache-buster) is ignored. req is the first recv() of the
 * request, NUL-terminated. Returns true when the request was one of these
 * routes and has been answered.
 */
bool api_cam_handle(int sock, const char *req, int req_len);
