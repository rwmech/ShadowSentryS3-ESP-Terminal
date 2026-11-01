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
 * One task select()s over the listen sockets (and the MikroTik UDP sockets,
 * below) and serves one connection at a time across all of them. Per connection:
 *   1. accept, and send the service's banner if it is server-first
 *   2. wait up to TRIPWIRE_FIRST_MS for the client's first bytes, and up to
 *      TRIPWIRE_MORE_MS more for the rest of that first segment, at most
 *      TRIPWIRE_RX_MAX bytes in all
 *   3. log one ATTACK_TRIPWIRE event and close
 * No credential parsing (the RouterOS API decoy reads its command and user
 * name words only, below) and no second round trip; TRIPWIRE_CONN_MS
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
 * MikroTik decoys (MikroTik-specific ports only; the FTP, SSH, Telnet and
 * HTTP traps keep presenting their own devices). Served by mikrotik.c with
 * no socket and no file descriptor (raw lwIP pcbs for TCP, a copy from the
 * station input wrapper for UDP; see mikrotik.h); this task reads their
 * results every TRIPWIRE_POLL_MS and logs them like the others:
 *   Winbox          8291  client first; silent. Logs the first frame's
 *                         first bytes and its length (the bytes of the
 *                         first burst, counted up to TRIPWIRE_FRAME_MAX)
 *   RouterOS API    8728  client first; silent. Reads the sentence's
 *                         length-prefixed words and logs the command word
 *                         and the "=name=" value only: no hex, and the
 *                         password word is never copied, logged or stored
 *   Bandwidth test  2000  sends the 4-byte hello 01 00 00 00, logs the
 *                         client's command (protocol, direction, hex)
 *   MNDP       UDP  5678  passive: a solicitation or announcement from a
 *                         MAC that is not the gateway's or on
 *                         TRIPWIRE_MT_WHITELIST is an event (SEV2: Winbox
 *                         clients also send discovery). Never announces
 *   MAC-Telnet UDP 20561  passive: mactelnet broadcasts its session packets
 *                         at the IP layer, so the board sees them (lwIP
 *                         takes IP broadcasts, even from 0.0.0.0). A packet
 *                         whose header names the board's MAC, from a
 *                         sender not whitelisted, is an event (SEV1);
 *                         sessions for other MACs are counted only
 * The UDP pair is logged here, not in discovery.c, because the events go
 * through log_store_append() (SPIFFS), which needs this task's internal
 * stack; the discovery task's stack is in PSRAM. UDP events are held per
 * source and service for TRIPWIRE_UDP_HOLD_S (Winbox repeats its neighbour
 * scan), and the held ones are counted without a console line.
 *
 * Memory: the receive, hex and event buffers and the rate-limit table are
 * static (about 1 KB), the decoys' ring and queue are in PSRAM; the task
 * stack is internal because log_store_append() writes SPIFFS from it.
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
#ifndef TRIPWIRE_WINBOX_PORT
#define TRIPWIRE_WINBOX_PORT    8291
#endif
#ifndef TRIPWIRE_ROSAPI_PORT
#define TRIPWIRE_ROSAPI_PORT    8728
#endif
#ifndef TRIPWIRE_BTEST_PORT
#define TRIPWIRE_BTEST_PORT     2000
#endif
#ifndef TRIPWIRE_MNDP_PORT
#define TRIPWIRE_MNDP_PORT      5678    // UDP
#endif
#ifndef TRIPWIRE_MACTELNET_PORT
#define TRIPWIRE_MACTELNET_PORT 20561   // UDP
#endif
// MACs never reported by the MNDP and MAC-Telnet decoys besides the gateway's,
// "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66" (up to MT_WHITELIST_MAX), "" for none.
#ifndef TRIPWIRE_MT_WHITELIST
#define TRIPWIRE_MT_WHITELIST   ""
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
#define TRIPWIRE_FRAME_MAX      2048    // Winbox: bytes of the first burst counted
#define TRIPWIRE_UDP_HOLD_S     300     // MNDP and MAC-Telnet: one event per source
#define TRIPWIRE_UDP_RX_MAX     512     // bytes kept per datagram (PSRAM ring)
#define TRIPWIRE_POLL_MS        250     // select() timeout: how often the decoys' queue and ring are read

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

// MikroTik TCP decoys: free of the other ports, and each TCP tripwire port
// used once (the count includes the port itself).
#define TRIPWIRE_TCP_HITS_(p) (((p) == TRIPWIRE_RDP_PORT) + ((p) == TRIPWIRE_VNC_PORT) + \
                               ((p) == TRIPWIRE_SMB_PORT) + ((p) == TRIPWIRE_REDIS_PORT) + \
                               ((p) == TRIPWIRE_MYSQL_PORT) + ((p) == TRIPWIRE_MSSQL_PORT) + \
                               ((p) == TRIPWIRE_JETDIRECT_PORT) + ((p) == TRIPWIRE_WINBOX_PORT) + \
                               ((p) == TRIPWIRE_ROSAPI_PORT) + ((p) == TRIPWIRE_BTEST_PORT))
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_WINBOX_PORT), "TRIPWIRE_WINBOX_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_ROSAPI_PORT), "TRIPWIRE_ROSAPI_PORT collides with another port");
_Static_assert(TRIPWIRE_OK_(TRIPWIRE_BTEST_PORT),  "TRIPWIRE_BTEST_PORT collides with another port");
_Static_assert(TRIPWIRE_WINBOX_PORT == 0 || TRIPWIRE_TCP_HITS_(TRIPWIRE_WINBOX_PORT) == 1,
    "TRIPWIRE_WINBOX_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_ROSAPI_PORT == 0 || TRIPWIRE_TCP_HITS_(TRIPWIRE_ROSAPI_PORT) == 1,
    "TRIPWIRE_ROSAPI_PORT duplicates another tripwire port");
_Static_assert(TRIPWIRE_BTEST_PORT == 0 || TRIPWIRE_TCP_HITS_(TRIPWIRE_BTEST_PORT) == 1,
    "TRIPWIRE_BTEST_PORT duplicates another tripwire port");

// MikroTik UDP decoys: not on a discovery listener (discovery.c's LSN[]),
// mDNS, DHCP, DNS, SNTP or the WebSocket server's control socket, and not on
// each other.
#define TRIPWIRE_UDP_OK_(p) ((p) == 0 || ((p) != 1900 && (p) != 3702 && (p) != 5355 && (p) != 137 && \
                             (p) != 9999 && (p) != 20002 && (p) != 56700 && (p) != 987 && \
                             (p) != 9302 && (p) != 67 && (p) != 68 && (p) != 5353 && \
                             (p) != 53 && (p) != 123 && (p) != 32768))
_Static_assert(TRIPWIRE_UDP_OK_(TRIPWIRE_MNDP_PORT),      "TRIPWIRE_MNDP_PORT collides with another UDP port");
_Static_assert(TRIPWIRE_UDP_OK_(TRIPWIRE_MACTELNET_PORT), "TRIPWIRE_MACTELNET_PORT collides with another UDP port");
_Static_assert(TRIPWIRE_NE_(TRIPWIRE_MNDP_PORT, TRIPWIRE_MACTELNET_PORT),
    "TRIPWIRE_MNDP_PORT and TRIPWIRE_MACTELNET_PORT must differ");
_Static_assert(TRIPWIRE_WINBOX_PORT <= 65535 && TRIPWIRE_ROSAPI_PORT <= 65535 && TRIPWIRE_BTEST_PORT <= 65535 &&
               TRIPWIRE_MNDP_PORT <= 65535 && TRIPWIRE_MACTELNET_PORT <= 65535,
    "tripwire ports must be 0..65535");

// FreeRTOS task entry point. Pass NULL as arg. Core 0, like the other traps.
void tripwire_task(void *arg);

// The service name ("RDP", "VNC", ..., "Winbox", "RouterOS API", "Bandwidth
// test", "MNDP", "MAC-Telnet") of a tripwire event's payload, or NULL
// if the payload does not start with a known "<service> on ". For the SD
// attack line's "service".
const char *tripwire_service_key(const char *payload);
