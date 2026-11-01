#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Recon detection: port scans, probes and ARP sweeps, plus admin-port stealth.
 *
 *   lwIP IPv4 input hook (tcpip task, constant time, never allocates or logs):
 *     inbound TCP SYN (and FIN / NULL / Xmas, which carry no SYN or ACK) and
 *     UDP to our address, minus the gateway and replies to our own DNS, DHCP,
 *     NTP and mDNS, are queued as (source, port, protocol). With a non-empty
 *     admin allowlist, a SYN to ADMIN_PORT or ADMIN_WS_PORT from anyone else is
 *     freed and eaten, so those ports read as filtered; it is still queued.
 *   Station netif input wrapper (Wi-Fi RX task): ARP who-has requests are
 *     queued as (sender MAC, sender IP, target IP); every frame is passed on.
 *   Detector task (Core 1, priority 2) drains the queue:
 *     - scan_ports distinct ports from one source within scan_window_s: one
 *       ATTACK_SCAN event, then nothing until 60 s of quiet, then a summary
 *       ATTACK_SCAN event ("Scan ended: N ports total").
 *     - a SYN to a trap port (FTP, SSH, Telnet, HTTP, RTSP, Telnet 2323, SSH 2222,
 *       ADB 5555, HTTP 8080/8000/9000, the tripwire ports): one ATTACK_PROBE per
 *       source, port and minute, held 1.5 s so a scan that starts meanwhile
 *       folds it in; none while that source is scanning. On the ports whose
 *       service logs every connection (HTTP engine, ADB, tripwires) the hold
 *       is 6 s and the service's detect_note_logged() drops it, so only a SYN
 *       that never became a logged connection is a probe there.
 *     - arp_targets distinct who-has targets from one MAC within arp_window_s:
 *       one ATTACK_ARP_SWEEP, a summary after 60 s of quiet. The gateway and
 *       our own MAC are excluded.
 *   Every event goes through log_store_append(), so it is logged everywhere;
 *   the alarm and Telegram apply the alert mask and the ignore list.
 *
 * USB serial console recovery (the same task polls the console every 100 ms):
 *   admin-allow          print the admin allowlist
 *   admin-allow clear    empty it, so the admin ports are open to all again
 */

typedef struct {
    uint32_t queued;          // hook and ARP tap messages queued since boot
    uint32_t dropped;         // queue full
    uint32_t admin_dropped;   // SYNs to the admin ports eaten by the allowlist
    uint32_t arp_requests;    // who-has requests seen
    uint32_t scans, probes, sweeps;   // events raised
    bool     arp_tap;         // the station netif wrapper is in place
} detect_stats_t;

// After settings_init(), before alarm_init(): loads the ignore list, creates
// the queue and the detector task. The ARP tap installs itself once the
// station netif exists.
void detect_init(void);

void detect_get_stats(detect_stats_t *out);

// A service that logs every connection it takes (HTTP engine, ADB, tripwires)
// logged one from ip (network order) on port: drop the probe held for it, so
// one connection is one event. Queues only; safe from any task.
void detect_note_logged(uint32_t ip, uint16_t port);

#ifdef __cplusplus
}
#endif
