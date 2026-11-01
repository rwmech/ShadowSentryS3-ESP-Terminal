#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "tripwire.h"           // TRIPWIRE_*_PORT, TRIPWIRE_RX_MAX, TRIPWIRE_UDP_RX_MAX

/*
 * MikroTik decoys: listeners and bounded readers (fork addition, Robert Mech)
 *
 * The listeners behind tripwire.c's MikroTik decoys: Winbox (TCP 8291), the
 * RouterOS API (TCP 8728), the bandwidth-test server (TCP 2000), MNDP
 * neighbour discovery (UDP 5678) and MAC-Telnet (UDP 20561). None of them
 * takes a socket or a file descriptor (FD_SETSIZE 64 is shared between lwIP
 * sockets and open files, and both are fully budgeted):
 *   TCP  raw lwIP pcbs. The callbacks run on the tcpip thread, so each does
 *        constant, bounded work: no logging, no allocation, no blocking
 *        lock, no flash. At most MT_RAW_CONN_MAX connections at once (from
 *        a static pool; past that a new one is aborted in the accept
 *        callback), each closed by a tcp_poll deadline. A connection keeps
 *        at most TRIPWIRE_RX_MAX bytes; when it ends, one fixed-size result
 *        is posted to the tripwire task with a 0 timeout (a full queue drops
 *        it and counts it). The RouterOS API's words are read in the
 *        callback and only the command word and the "=name=" value are put
 *        in the result: the password word never leaves the connection's
 *        buffer, which is zeroed when the connection ends. Bandwidth test
 *        sends its 4-byte hello from the accept callback; nothing else is
 *        ever sent.
 *   UDP  no socket: mikrotik_frame_tap(), called from the station
 *        interface's input wrapper in detect.c (Wi-Fi RX task, every frame),
 *        copies each IPv4 UDP datagram to the MNDP or MAC-Telnet port that
 *        is for this board (its address, 255.255.255.255 or the subnet
 *        broadcast) into a ring of MT_UDP_SLOTS in PSRAM, at most
 *        TRIPWIRE_UDP_RX_MAX bytes each, with the frame's source MAC; full
 *        ring = dropped and counted. Without a socket, lwIP answers a
 *        unicast datagram to these ports with ICMP port unreachable, as for
 *        any closed port; broadcasts get nothing.
 *
 * Formats, written from the public descriptions (no code copied):
 *   RouterOS API  MikroTik's API manual: sentences of length-prefixed words,
 *                 a zero-length word ends one.
 *   btest         samm-git/btest-opensource's protocol notes (MIT): the server
 *                 says 01 00 00 00, the client answers with a 16-byte command
 *                 (protocol, direction, ...).
 *   MNDP          the format as Wireshark's MNDP dissector reads it (GPL,
 *                 consulted only): a 4-byte header, then type / length / value
 *                 records with 16-bit big-endian type and length. A bare
 *                 4-byte datagram is a solicitation (what Winbox and
 *                 mactelnet send to find neighbours).
 *   MAC-Telnet    the header as haakonnessjoen/MAC-Telnet reads it (GPL,
 *                 consulted only): version, packet type, source MAC,
 *                 destination MAC, then session fields, 22 bytes in all.
 *
 * Whitelist: the gateway's MAC (wifi_manager_get_gateway() and the ARP cache,
 * looked up again every 60 s) and the MACs in TRIPWIRE_MT_WHITELIST. A real
 * MikroTik router announces itself by MNDP every 60 s; that is not an event.
 */

#define MT_LABEL_LEN        33      // identity, version, board: 32 characters
#define MT_API_CMD_LEN      25      // the API command word, 24 characters
#define MT_API_USER_LEN     25      // the "=name=" value, 24 characters
#define MT_API_WORDS_MAX    8       // words read per sentence
#define MT_MNDP_TLV_MAX     32      // records read per datagram
#define MT_WHITELIST_MAX    8       // MACs from TRIPWIRE_MT_WHITELIST
#define MT_MACTELNET_HDR    22      // header bytes
#define MT_RAW_CONN_MAX     2       // TCP decoy connections open at once
#define MT_POLL_TICKS       1       // tcp_poll interval, in lwIP's 500 ms ticks
#define MT_NODATA_POLLS     6       // close after 3 s without data
#define MT_CONN_POLLS       10      // and after 5 s in all
#define MT_TCP_QDEPTH       4       // results waiting for the tripwire task
#define MT_UDP_SLOTS        8       // datagrams waiting for the tripwire task

typedef enum { MT_TCP_WINBOX, MT_TCP_API, MT_TCP_BTEST, MT_TCP_N } mt_tcp_kind_t;

// One finished TCP decoy connection, for the tripwire task.
typedef struct {
    uint32_t ip;                        // network byte order
    uint32_t total;                     // bytes received, capped at TRIPWIRE_FRAME_MAX + 1
    uint16_t port;
    uint8_t  kind;                      // mt_tcp_kind_t
    uint8_t  n;                         // bytes received, up to TRIPWIRE_RX_MAX
    bool     api_ok;                    // API: the bytes read as API words
    union {
        uint8_t data[TRIPWIRE_RX_MAX];  // Winbox, btest: the first bytes
        struct {                        // API: these only, never the bytes
            char cmd[MT_API_CMD_LEN];
            char user[MT_API_USER_LEN];
        } api;
    };
} mt_tcp_result_t;

// One datagram from the frame tap.
typedef struct {
    uint32_t ip;                        // source, network byte order (may be 0.0.0.0)
    uint16_t dport;
    uint16_t len;                       // bytes in data
    uint16_t full_len;                  // the datagram's UDP payload length
    uint8_t  mac[6];                    // the frame's source MAC
    uint8_t  data[TRIPWIRE_UDP_RX_MAX];
} mt_dgram_t;

typedef enum {
    MT_MNDP_OTHER = 0,      // not MNDP as far as we can tell
    MT_MNDP_SOLICIT,        // a bare 4-byte request for announcements
    MT_MNDP_ANNOUNCE,       // records: who the sender says it is
} mt_mndp_kind_t;

typedef struct {
    char    identity[MT_LABEL_LEN];
    char    version[MT_LABEL_LEN];
    char    board[MT_LABEL_LEN];        // board name, else the platform
    uint8_t mac[6];                     // the MAC record, as claimed
    bool    has_mac;
} mt_mndp_t;

typedef struct {
    uint8_t ptype;          // 0 session start, 1 data, 2 ack, 4 ping, 5 pong, 255 end
    uint8_t src[6];         // as claimed in the header
    uint8_t dst[6];         // the MAC the session is for
} mt_mactelnet_t;

// Tripwire task, once: the result queue, the datagram ring and the raw TCP
// listeners (opened on the tcpip thread). False if nothing could be set up.
bool mikrotik_init(void);

// True if that TCP decoy is listening.
bool mikrotik_tcp_listening(mt_tcp_kind_t k);

// True if the datagram ring is set up and a UDP decoy port is on.
bool mikrotik_udp_on(void);

// The next finished TCP connection, without waiting.
bool mikrotik_tcp_next(mt_tcp_result_t *out);

// The oldest datagram in the ring, or NULL; mikrotik_udp_pop() frees it.
const mt_dgram_t *mikrotik_udp_peek(void);
void mikrotik_udp_pop(void);

// Counters: results dropped (queue full), connections refused (pool full),
// datagrams dropped (ring full).
void mikrotik_counters(uint32_t *tcp_drop, uint32_t *tcp_refused, uint32_t *udp_drop);

// Wi-Fi RX task: copy a UDP datagram to the MNDP or MAC-Telnet port that is
// for this board into the ring. Bounded copy, never blocks.
void mikrotik_frame_tap(const uint8_t *frame, size_t len, uint32_t our_ip, uint32_t netmask);

// Parse TRIPWIRE_MT_WHITELIST; returns how many MACs it holds.
int mikrotik_whitelist_init(void);

// True for the gateway's MAC and the configured ones. Tripwire task only.
bool mikrotik_whitelisted(const uint8_t mac[6]);

// The gateway's MAC as last looked up, false if unknown. Tripwire task only.
bool mikrotik_gateway_mac(uint8_t mac[6]);

// The API sentence's command word (starting with '/') and the "=name=" value,
// printable ASCII only, "" if absent. False if the bytes are not API words.
bool mikrotik_api_parse(const uint8_t *b, size_t n, char *cmd, size_t cmd_cap,
                        char *user, size_t user_cap);

// "TCP both" and the like from a btest command; false if it does not look like one.
bool mikrotik_btest_label(const uint8_t *b, size_t n, char *out, size_t cap);

mt_mndp_kind_t mikrotik_mndp_parse(const uint8_t *b, size_t n, mt_mndp_t *o);

bool mikrotik_mactelnet_parse(const uint8_t *b, size_t n, mt_mactelnet_t *o);

// "session start", "data", ... for a MAC-Telnet packet type.
const char *mikrotik_mactelnet_ptype(uint8_t t);
