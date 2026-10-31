#pragma once
#include <stdint.h>
#include "config.h"
#include "trap_listen.h"      // TRAP_PORT_FREE, TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT
#include "http_engine.h"      // HTTP_ALT_OK_, HTTP_ALT_PORT1..3

/*
 * Tripwire listeners (fork addition, Robert Mech)
 *
 * Ports for services this box does not run and nothing on a home LAN should
 * be asking it for: any connection to one is the signal. A hit usually means
 * a compromised host, a worm or a scanner looking for its next target, so the
 * point is an alert to act on (pull the host off the network, find it), not
 * a conversation.
 *
 * One task select()s over the listen sockets and serves one connection at a
 * time across all of them. Per connection:
 *   1. accept, and send the service's banner if it is server-first
 *   2. wait up to TRIPWIRE_FIRST_MS for the client's first bytes, and up to
 *      TRIPWIRE_MORE_MS more for the rest of that first segment, at most
 *      TRIPWIRE_RX_MAX bytes in all
 *   3. log one ATTACK_TRIPWIRE event and close
 * No protocol or credential parsing and no second round trip; TRIPWIRE_CONN_MS
 * per connection in all, a 1 s send timeout. Nothing is ever executed and no
 * connection is made on the client's behalf.
 *
 * Payload: "<service> on <port>: <first bytes as hex>", trimmed to the 128-byte
 * payload (57 bytes of hex at most; the console line has all 64), "no data"
 * if the client sent nothing. tripwire_service_key() maps it back for the SD
 * attack line's "service".
 *
 * Rate limit: one event per source and service every TRIPWIRE_HOLD_S. More
 * connections inside the window are accepted, printed on the console and
 * counted; the count goes into the next event as "(+N held)".
 *
 * Services (port 0 disables one; TRIPWIRE_ENABLE 0 disables them all):
 *   RDP        3389  client first, no banner
 *   VNC        5900  "RFB 003.008\n"
 *   SMB         445  client first, no banner
 *   Redis      6379  client first, no banner
 *   MySQL      3306  a MySQL 5.7 handshake (version, fixed salt,
 *                    mysql_native_password, no TLS offered), so a client
 *                    sends its login packet; only its first bytes are logged
 *   MSSQL      1433  client first, no banner
 *   JetDirect  9100  client first, no banner
 *
 * Memory: the receive, hex and event buffers and the rate-limit table are
 * static (about 0.8 KB); the task stack is internal because log_store_append()
 * writes SPIFFS from it.
 *
 * The defaults below let a config.h written before these options still build.
 */

#ifndef TRIPWIRE_ENABLE
#define TRIPWIRE_ENABLE         1
#endif

#ifndef TRIPWIRE_RDP_PORT
#define TRIPWIRE_RDP_PORT       3389
#endif
#ifndef TRIPWIRE_VNC_PORT
#define TRIPWIRE_VNC_PORT       5900
#endif
#ifndef TRIPWIRE_SMB_PORT
#define TRIPWIRE_SMB_PORT       445
#endif
#ifndef TRIPWIRE_REDIS_PORT
#define TRIPWIRE_REDIS_PORT     6379
#endif
#ifndef TRIPWIRE_MYSQL_PORT
#define TRIPWIRE_MYSQL_PORT     3306
#endif
#ifndef TRIPWIRE_MSSQL_PORT
#define TRIPWIRE_MSSQL_PORT     1433
#endif
#ifndef TRIPWIRE_JETDIRECT_PORT
#define TRIPWIRE_JETDIRECT_PORT 9100
#endif

// The ports really listened on (0 when tripwires are off), for detect.c.
#define TRIPWIRE_LISTEN(p)      (TRIPWIRE_ENABLE ? (p) : 0)

#define TRIPWIRE_FIRST_MS       3000    // wait for the client's first bytes
#define TRIPWIRE_MORE_MS        250     // then for the rest of that segment
#define TRIPWIRE_CONN_MS        5000    // whole connection
#define TRIPWIRE_SEND_TIMEOUT_S 1
#define TRIPWIRE_RX_MAX         64      // bytes read per connection
#define TRIPWIRE_HOLD_S         30      // one event per source and service
#define TRIPWIRE_HOLD_SLOTS     32      // sources x services remembered
#define TRIPWIRE_BACKLOG        2       // per port
#define TRIPWIRE_TASK_STACK     3072    // internal; high-water logged on each new low

// Port collision guards (0 = disabled, never collides). config.h.example
// repeats them; C11 allows a _Static_assert twice.
#define TRIPWIRE_OK_(p) ((p) == 0 || (HTTP_ALT_OK_(p) && (p) != HTTP_ALT_PORT1 && \
                         (p) != HTTP_ALT_PORT2 && (p) != HTTP_ALT_PORT3))
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_RDP_PORT),       "TRIPWIRE_RDP_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_VNC_PORT),       "TRIPWIRE_VNC_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_SMB_PORT),       "TRIPWIRE_SMB_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_REDIS_PORT),     "TRIPWIRE_REDIS_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_MYSQL_PORT),     "TRIPWIRE_MYSQL_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_MSSQL_PORT),     "TRIPWIRE_MSSQL_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_JETDIRECT_PORT), "TRIPWIRE_JETDIRECT_PORT collides with another port");

#define TRIPWIRE_NE_(a, b) ((a) == 0 || (a) != (b))
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_VNC_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_SMB_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_REDIS_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_MYSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_MSSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_RDP_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_RDP_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_VNC_PORT, TRIPWIRE_SMB_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_VNC_PORT, TRIPWIRE_REDIS_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_VNC_PORT, TRIPWIRE_MYSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_VNC_PORT, TRIPWIRE_MSSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_VNC_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_VNC_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_SMB_PORT, TRIPWIRE_REDIS_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_SMB_PORT, TRIPWIRE_MYSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_SMB_PORT, TRIPWIRE_MSSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_SMB_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_SMB_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_REDIS_PORT, TRIPWIRE_MYSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_REDIS_PORT, TRIPWIRE_MSSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_REDIS_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_REDIS_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_MYSQL_PORT, TRIPWIRE_MSSQL_PORT) &&
               TRIPWIRE_NE_(TRIPWIRE_MYSQL_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_MYSQL_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_MSSQL_PORT, TRIPWIRE_JETDIRECT_PORT),
    "TRIPWIRE_MSSQL_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_RDP_PORT <= 65535 && TRIPWIRE_VNC_PORT <= 65535 && TRIPWIRE_SMB_PORT <= 65535 &&
               TRIPWIRE_REDIS_PORT <= 65535 && TRIPWIRE_MYSQL_PORT <= 65535 &&
               TRIPWIRE_MSSQL_PORT <= 65535 && TRIPWIRE_JETDIRECT_PORT <= 65535,
    "tripwire ports must be 0..65535");

// FreeRTOS task entry point. Pass NULL as arg. Core 0, like the other traps.
void tripwire_task(void *arg);

// The service name ("RDP", "VNC", ...) of a tripwire event's payload, or NULL
// if the payload does not start with a known "<service> on ". For the SD
// attack line's "service".
const char *tripwire_service_key(const char *payload);
