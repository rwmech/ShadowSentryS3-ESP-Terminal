#pragma once
#include <stdbool.h>

/*
 * Seen-devices route on the admin port (Basic auth already checked by admin_panel.c):
 *
 *   GET /api/devices    the LAN discovery table (main/detect/discovery.h) as
 *                       JSON, newest first, every string escaped:
 *                       {"enabled","packets","listeners":[{"name","port","open",
 *                       "packets","error"}],"mdns","devices":[{"mac","random_mac",
 *                       "vendor","ip","label","label_src","host","protos":{key:count},
 *                       "total","first_ts","last_ts","first_ago_s","last_ago_s",
 *                       "queries":[newest first]}],"count","truncated"}
 *
 * A query string is ignored. Returns true when the request was this route and
 * has been answered.
 */
bool api_devices_handle(int sock, const char *req, int req_len);
