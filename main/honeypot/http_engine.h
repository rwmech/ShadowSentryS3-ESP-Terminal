#pragma once
#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "trap_listen.h"      // TRAP_PORT_FREE, TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT

/*
 * HTTP engine: one task for every HTTP trap port (fork addition, Robert Mech)
 *
 * Replaces upstream's single-port http_trap_task (honeypot/http_trap.c, left
 * untouched and still built) when HTTP_ENGINE_ENABLE is 1. One task select()s
 * over the listen sockets on HTTP_PORT and up to three alternate ports, and
 * serves up to HTTP_ENG_MAX_CONN connections at once across all of them.
 *
 * Every port serves upstream's NVR page and behaviour unchanged: GET gets the
 * login page, POST gets a 302 back to /, any other method gets an empty 404.
 * Credentials are taken from the POST body's username and password fields, as
 * upstream does.
 *
 * Every request is logged as an HTTP event. The payload starts with a label
 * (below), then the port, the method, the path, Host and User-Agent. The full
 * request line, Host, User-Agent and the first HTTP_ENG_LOG_BODY bytes of the
 * body go to the console and, as a {"kind":"http"} line, to the microSD log.
 *
 * Labels, first match wins. They read only the request's shape and the
 * User-Agent; there is no exploit signature matching.
 *   non-HTTP payload   the first bytes are not "<METHOD> "
 *   oversize request   head over HTTP_ENG_HEAD_MAX, a line over
 *                      HTTP_ENG_LINE_MAX or a request-target over HTTP_ENG_URL_MAX
 *   path with ..       a ".." path segment (after percent-decoding)
 *   login POST         a POST with a username or password field
 *   dotfile path       a path segment starting with "." (after percent-decoding)
 *   unusual method     anything but GET, POST and HEAD
 *   scanner UA         a well-known scanner name in the User-Agent
 *   HTTP library UA    a well-known HTTP client or library in the User-Agent
 *   unclassified       none of the above
 *
 * Limits: HTTP_ENG_MAX_CONN connections in all (further ones wait in the
 * listen backlog), HTTP_ENG_HEAD_MAX of head and HTTP_ENG_BODY_MAX of body
 * read per request, one request per connection, HTTP_RECV_TIMEOUT_S idle and
 * HTTP_ENG_CONN_S in all per connection, a 2 s send timeout. At most
 * HTTP_ENG_EVENTS_PER_MIN events a minute go to the flash ring and alerts;
 * the rest go to the console and the microSD only, and are counted in one
 * summary event. Nothing is fetched or executed.
 *
 * Memory: connection buffers in PSRAM; the task stack is internal because
 * log_store_append() writes SPIFFS from it (flash writes run with the cache off).
 */

#ifndef HTTP_ENGINE_ENABLE
#define HTTP_ENGINE_ENABLE      1       // 0 = upstream's http_trap_task on HTTP_PORT only
#endif

// Alternate HTTP ports, 0 disables one. DShield's top 10 lists 8080, 8000 and 9000.
#ifndef HTTP_ALT_PORT1
#define HTTP_ALT_PORT1          8080
#endif
#ifndef HTTP_ALT_PORT2
#define HTTP_ALT_PORT2          8000
#endif
#ifndef HTTP_ALT_PORT3
#define HTTP_ALT_PORT3          9000
#endif

// The ports the engine really listens on (0 when the engine is off), for detect.c.
#if HTTP_ENGINE_ENABLE
#define HTTP_ENG_PORT1          HTTP_ALT_PORT1
#define HTTP_ENG_PORT2          HTTP_ALT_PORT2
#define HTTP_ENG_PORT3          HTTP_ALT_PORT3
#else
#define HTTP_ENG_PORT1          0
#define HTTP_ENG_PORT2          0
#define HTTP_ENG_PORT3          0
#endif

#define HTTP_ENG_MAX_CONN       4       // across all ports; lwIP sockets: see CLAUDE.md
#define HTTP_ENG_HEAD_MAX       4096    // request line and headers
#define HTTP_ENG_BODY_MAX       8192    // body bytes read
#define HTTP_ENG_LINE_MAX       1024    // one header line, for the oversize label
#define HTTP_ENG_URL_MAX        512     // request-target, for the oversize label
#define HTTP_ENG_CONN_S         10      // whole connection
#define HTTP_ENG_SEND_TIMEOUT_S 2
#define HTTP_ENG_LOG_BODY       512     // body bytes in the console and microSD line
#define HTTP_ENG_EVENTS_PER_MIN 60      // flash ring and alerts
#define HTTP_ENG_TASK_STACK     4096    // internal; high-water logged on each new low

#define HTTP_ALT_OK_(p) ((p) == 0 || (TRAP_PORT_FREE(p) && (p) != TELNET_ALT_PORT && \
                         (p) != SSH_ALT_PORT && (p) != ADB_PORT))
_Static_assert(HTTP_ALT_OK_(HTTP_ALT_PORT1), "HTTP_ALT_PORT1 collides with another port");
_Static_assert(HTTP_ALT_OK_(HTTP_ALT_PORT2), "HTTP_ALT_PORT2 collides with another port");
_Static_assert(HTTP_ALT_OK_(HTTP_ALT_PORT3), "HTTP_ALT_PORT3 collides with another port");
_Static_assert(HTTP_ALT_PORT1 == 0 || (HTTP_ALT_PORT1 != HTTP_ALT_PORT2 && HTTP_ALT_PORT1 != HTTP_ALT_PORT3),
    "HTTP_ALT_PORT1 duplicates another HTTP port");
_Static_assert(HTTP_ALT_PORT2 == 0 || HTTP_ALT_PORT2 != HTTP_ALT_PORT3,
    "HTTP_ALT_PORT2 duplicates another HTTP port");
_Static_assert(HTTP_ALT_PORT1 <= 65535 && HTTP_ALT_PORT2 <= 65535 && HTTP_ALT_PORT3 <= 65535,
    "HTTP ports must be 0..65535");

// FreeRTOS task entry point. Pass NULL as arg. Core 0, like the other traps.
void http_engine_task(void *arg);

// The label key ("non_http", "login_post", ..., "unclassified") of an HTTP
// event's payload, or NULL if the payload has no engine label (an event from
// upstream's http_trap_task). For the microSD line's "category".
const char *http_engine_category_key(const char *payload);
