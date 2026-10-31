#pragma once
#include <stdint.h>

/*
 * ADB Honeypot: Port 5555  (Android Debug Bridge over TCP, fork addition)
 *
 * Impersonates an Android 6 TV box with ADB over TCP open and auth disabled,
 * the device that Android botnets (Kimwolf, BADBOX 2.0, ADB.Miner and
 * similar) hunt for on home networks. A hit on this port from inside the LAN
 * usually means an infected box or a residential-proxy app is looking for its
 * next host.
 *
 * Protocol handling is ported from Glutton's protocols/tcp/adb.go and
 * protocols/tcp/adb/adb.go (https://github.com/mushorg/glutton, MIT,
 * Copyright (c) 2016 MushMush; notice in THIRD_PARTY_NOTICES). Wire formats
 * from AOSP packages/modules/adb protocol.txt and SYNC.TXT.
 *
 * Attack flow:
 *   1. Bot connects to port 5555 and sends CNXN with its banner
 *      ("host::features=...")
 *   2. Device answers CNXN with a TV-box banner (no AUTH challenge)
 *      → ATTACK_ADB event with the client banner + Telegram alert
 *   3. Bot opens a service:
 *        shell:<cmd> / exec:<cmd>  canned output for recon commands, silence
 *                                  for everything else, then close
 *        shell:                    interactive prompt; every line is logged
 *        sync:                     file push (SEND/DATA/DONE): the remote
 *                                  path, size and SHA-256 are logged + alert;
 *                                  STAT/LIST answer plausibly, RECV fails
 *        tcp:, localabstract:, reverse:, anything else
 *                                  refused (CLSE) and logged + alert: the
 *                                  honeypot never forwards a connection
 *   4. Every OPEN → ATTACK_ADB event (+ Telegram alert)
 *
 * A host smart-socket request ("000chost:version", the adb client to adb
 * server framing) is logged and the connection closed, as Glutton does.
 *
 * Nothing is ever executed and no connection is ever made on the attacker's
 * behalf. Pushed bytes are hashed and counted, not kept (see the TODO in
 * adb_trap.c for storing them on the microSD).
 *
 * Bounds: one session at a time; ADB_SESSION_S per session, ADB_RECV_TIMEOUT_S
 * idle, ADB_MAX_BYTES received, ADB_MAX_MSGS messages, ADB_MAX_EVENTS logged
 * events, ADB_MAX_STREAMS open streams; a message body over ADB_MAX_DATA
 * (also the max_data we advertise) ends the session.
 *
 * Designed to run pinned to Core 0 (Hacker World). Session buffers live in
 * PSRAM; the task stack stays internal because log_store_append() writes
 * SPIFFS from the calling task.
 */

// Per-session wall-clock limit in seconds.
#ifndef ADB_SESSION_S
#define ADB_SESSION_S       60
#endif

// Per-read idle timeout in seconds.
#define ADB_RECV_TIMEOUT_S  10

// Total bytes received per session before it is closed (a push past this is
// logged as truncated).
#ifndef ADB_MAX_BYTES
#define ADB_MAX_BYTES       (1024 * 1024)
#endif

// Transport messages handled per session (Glutton: 4096).
#define ADB_MAX_MSGS        4096

// Events logged per session; past this the session is only printed on the
// console. Bounds flash and SD writes against a chatty bot.
#define ADB_MAX_EVENTS      64

// Streams open at once per session (Glutton: 16).
#define ADB_MAX_STREAMS     4

// Largest message body accepted, and the max_data we advertise in CNXN so a
// compliant client never sends more. adbd's own limit is 1 MB.
#define ADB_MAX_DATA        4096

// Maximum queued TCP connections on port 5555.
#define ADB_BACKLOG         2

// The persona: what we answer CNXN with (Glutton's TV box). The trailing NUL
// is part of the banner on the wire.
#ifndef ADB_BANNER
#define ADB_BANNER          "device::ro.product.name=p281;ro.product.model=MBOX;ro.product.device=p281;"
#endif
#define ADB_SHELL_PROMPT    "shell@p281:/ $ "

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void adb_trap_task(void *arg);
