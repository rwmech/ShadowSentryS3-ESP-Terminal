#pragma once

/*
 * Live WebSocket push server
 *
 * A small esp_http_server instance dedicated to pushing attack events to the
 * dashboard in real time, so the browser no longer has to poll /api/attacks.
 * It registers a log_store listener; every new attack is marshalled onto the
 * httpd task (httpd_queue_work) and broadcast as a JSON text frame to all
 * connected WebSocket clients — the same per-entry shape the REST API emits, so
 * the dashboard reuses its existing render code.
 *
 * Runs on its own port (ADMIN_WS_PORT) alongside the raw-socket admin panel.
 * The endpoint is unauthenticated: it only emits attack metadata already shown
 * on the LAN dashboard, same threat model as the panel itself. Polling remains
 * as a fallback for browsers that can't open the socket.
 */

// Dedicated port for the WebSocket endpoint (ws://<device-ip>:ADMIN_WS_PORT/ws).
#ifndef ADMIN_WS_PORT
#define ADMIN_WS_PORT   9998
#endif

// Maximum simultaneous dashboard WebSocket clients. Kept small: every slot the
// WS httpd reserves is an lwIP socket taken from the shared pool that the 6
// honeypot listeners + admin panel + Telegram/GeoIP clients also draw on.
#ifndef ADMIN_WS_MAX_CLIENTS
#define ADMIN_WS_MAX_CLIENTS  2     // fork: was 3; the socket budget in CLAUDE.md
#endif

// Start the WebSocket push server and hook it into the log store and the alarm.
// Call once after the network is up (Core 1). esp_http_server manages its own
// task. Alarm changes are pushed as {"alarm":{...}}, attacks as bare entries.
void ws_server_start(void);

// Incident JSON object, shared by the WebSocket push and GET /api/status:
// {"state":0|1|2,"cond":"green|yellow|red","code":"17-01","headline":"..",
//  "id":n,"ip":u32,"type":t,"count":n,"first":ts,"last":ts,"mac":"..",
//  "vendor":"..","acked_by":"|panel|dashboard","resolved_by":"|panel|dashboard",
//  "intel":".."}   intel: the source's router and Pi-hole summary (correlate.h), "" if none
// state: 0 idle (green), 1 active (red, unacked), 2 acked (yellow).
// buf should hold WS_ALARM_JSON_MAX bytes.
#include <stddef.h>
#include "alarm.h"
#define WS_ALARM_JSON_MAX  896     // worst case about 820: headline 191, vendor 127, intel 144 escaped
void ws_format_alarm_json(const alarm_info_t *a, char *buf, size_t len);
