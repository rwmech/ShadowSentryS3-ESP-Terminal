#pragma once
#include <stdbool.h>

/*
 * Router and device-intelligence routes on the admin port (fork addition,
 * Robert Mech). Basic auth and the X-ShadowSentry check are done by
 * admin_panel.c before this is called.
 *
 *   GET  /api/device/intel?mac=..&ip=..   one device: the honeypot's events,
 *        the router's identity and connections, Pi-hole (if built in), flags
 *        with reasons, and a one-line summary. Either mac or ip is enough.
 *        Asks the router for the device's connections (at most once per 20 s
 *        per device); while that runs "conn.pending" is true: ask again in a
 *        few seconds. Every router-supplied string is JSON-escaped.
 *   GET  /api/mikrotik/status             client state, counts, certificate
 *        fingerprints (recorded, last seen) and the last test's result
 *   POST /api/mikrotik/test               queue a connection test (409 when off)
 *   POST /api/mikrotik/cert/forget        forget the fingerprint recorded on
 *        first use; the next https connection records the one it sees
 *
 * Returns true when the request was one of these and has been answered.
 */
bool api_mikrotik_handle(int sock, const char *req, int req_len);
