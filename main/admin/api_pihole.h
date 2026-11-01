#pragma once
#include <stdbool.h>

/*
 * Pi-hole routes on the admin port (fork addition, Robert Mech). Basic auth and
 * the POST X-ShadowSentry check are done by admin_panel.c. See pihole.h.
 *
 *   GET  /api/pihole/status        {"enabled":false} when off; else enabled,
 *                                  running, state ("starting", "ok", "error",
 *                                  "v5"), error, version, host, ip (resolved),
 *                                  session (bool), syncing, last_http,
 *                                  last_ok_ts, last_ok_ago_s, next_in_s,
 *                                  backoff_s, devices, with_top, syncs,
 *                                  failures, requests, oversized, tls_seen
 *                                  (https: the server's certificate SHA-256),
 *                                  stack_free, and the test fields test_req,
 *                                  test_done, test_ok, test_status, test_msg
 *   POST /api/pihole/test          queue a connection test (login plus
 *                                  /api/info/version) on the Pi-hole task:
 *                                  {"queued":true,"test":n}, then poll status
 *                                  until test_done >= n. 409 without a URL and
 *                                  password. Works before Pi-hole is switched on.
 *   POST /api/pihole/refresh[?ip=] a sync now; ip (dotted quad) gets its top
 *                                  domains first. 202 {"queued":true}; 429
 *                                  {"error","retry_after_s"} within
 *                                  PIHOLE_REFRESH_MIN_S of the last; 409 when off
 *   GET  /api/pihole/device?mac=&ip=
 *                                  one device, the same object /api/devices
 *                                  carries as "pihole": {"enabled":true,
 *                                  "found":bool,"pihole":{names, ips, mac,
 *                                  vendor, first, last, all_queries, queries,
 *                                  blocked, top_domains [{d,n}], top_of,
 *                                  top_ts, as_of}}; {"enabled":false} when off.
 *                                  mac is aa:bb:cc:dd:ee:ff (":" may be %3A),
 *                                  ip a dotted quad; either may be left out.
 *
 * Returns true when the request was one of these and has been answered.
 */
bool api_pihole_handle(int sock, const char *req, int req_len);
