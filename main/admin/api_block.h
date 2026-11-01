#pragma once
#include <stdbool.h>

/*
 * Block list routes on the admin port (fork addition, Robert Mech). See
 * blocklist.h for what a block does and what is never blocked.
 *
 * api_block_public(), called before the Basic auth check:
 *   GET  /routeros/block.txt   the list for the router's scheduler, text/plain,
 *        one "dst a.b.c.d" or "src a.b.c.d" line per entry and nothing else.
 *        Answered only when the client's address is the router's (the
 *        MikroTik URL's host or ROUTER_SYSLOG_SRC) and the board's ARP entry
 *        for it is the gateway's MAC; anyone else gets 404. No credentials:
 *        the router's fetch would have to store them.
 *
 * api_block_handle(), after the auth and X-ShadowSentry checks:
 *   GET  /api/block            {"entries":[{"ip","kind","note","ts"}],"max":64,
 *        "count":N,"never":[{"ip","why"}],"router":{"fetches","last_fetch","refused"}}
 *   POST /api/block            {"ip","kind":"dst"|"src","note"}: 200 with the
 *        list as above (an existing ip and kind gets the new note and time);
 *        409 {"error":"<reason>"} when the address may never be blocked or the
 *        list is full; 400 for a bad address, kind or note (at most 40
 *        printable ASCII characters); 507 when NVS could not save it.
 *   POST /api/block/remove     {"ip","kind"}: 200 with the list, 404 when it
 *        was not on it.
 *
 * Both return true when the request was theirs and has been answered.
 */
bool api_block_public(int sock, const char *req, int req_len);
bool api_block_handle(int sock, const char *req, int req_len);
