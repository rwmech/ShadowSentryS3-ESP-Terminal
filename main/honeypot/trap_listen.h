#pragma once
#include <stdint.h>
#include "config.h"

struct sockaddr_in;   // forward decl, avoid pulling lwip/sockets.h into the header

/*
 * Trap listeners: more than one port per trap task (fork addition)
 *
 * Bots scan the alternate ports as much as the standard ones: SANS ISC DShield
 * lists 2222 and 2323 next to 22 and 23, and Mirai-family worms try Telnet on
 * 23 and 2323. Rather than a second task per trap (8 KB internal stack for
 * Telnet, 16 KB for SSH, and a second wolfSSH context), one trap task serves
 * its standard and alternate port through select(). Like upstream's single
 * port, it serves one session at a time: a connection to the other port waits
 * in the listen backlog until the current session ends.
 *
 * Ports:
 *   TELNET_ALT_PORT  2323  same Telnet login and fake shell as TELNET_PORT
 *   SSH_ALT_PORT     2222  same wolfSSH server and fake shell as SSH_PORT
 *   ADB_PORT         5555  Android Debug Bridge trap (adb_trap.c)
 * 0 disables a port. Events keep their types (Telnet, SSH, Shell, ADB); an
 * event from an alternate port says "(port N)" in its payload.
 *
 * The defaults below let a config.h written before these options still build.
 */

#ifndef TELNET_ALT_PORT
#define TELNET_ALT_PORT     2323
#endif

#ifndef SSH_ALT_PORT
#define SSH_ALT_PORT        2222
#endif

#ifndef ADB_PORT
#define ADB_PORT            5555
#endif

// Port collision guards for the fork's ports (0 = disabled, never collides).
// config.h.example repeats them; C11 allows a _Static_assert twice.
#define TRAP_PORT_FREE(p) ((p) != RTSP_PORT && (p) != HTTP_PORT && (p) != TELNET_PORT && \
                           (p) != SSH_PORT && (p) != FTP_PORT && (p) != ADMIN_PORT && \
                           (p) != ADMIN_WS_PORT && (p) != ADMIN_WS_PORT + 1)
_Static_assert(TELNET_ALT_PORT == 0 || TRAP_PORT_FREE(TELNET_ALT_PORT),
    "TELNET_ALT_PORT collides with another port");
_Static_assert(SSH_ALT_PORT == 0 || TRAP_PORT_FREE(SSH_ALT_PORT),
    "SSH_ALT_PORT collides with another port");
_Static_assert(ADB_PORT == 0 || TRAP_PORT_FREE(ADB_PORT),
    "ADB_PORT collides with another port");
_Static_assert(TELNET_ALT_PORT == 0 || TELNET_ALT_PORT != SSH_ALT_PORT,
    "TELNET_ALT_PORT and SSH_ALT_PORT must differ");
_Static_assert(ADB_PORT == 0 || (ADB_PORT != TELNET_ALT_PORT && ADB_PORT != SSH_ALT_PORT),
    "ADB_PORT collides with an alternate port");
_Static_assert(TELNET_ALT_PORT <= 65535 && SSH_ALT_PORT <= 65535 && ADB_PORT <= 65535,
    "trap ports must be 0..65535");

// Open a TCP listen socket on port with SO_REUSEADDR. port 0 is
// disabled and returns -1 quietly; a bind or listen failure logs and returns -1.
int trap_listen(uint16_t port, int backlog);

// Wait until one of the n listen sockets has a connection and accept it.
// Negative entries in srv[] are skipped. On success returns the client socket,
// fills *client and sets *port to ports[i] of the socket that accepted;
// returns -1 on a transient error (the caller loops).
int trap_accept_any(const int *srv, const uint16_t *ports, int n,
                    struct sockaddr_in *client, uint16_t *port);
