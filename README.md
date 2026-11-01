<div align="center">

# ShadowSentry S3

> Zero-Configuration, Serverless Hardware Honeypot on a Single ESP32-S3

**🌐 Language:** **English** · [Українська](README.ua.md)

[![Release](https://img.shields.io/github/v/release/Rdx1S/ShadowSentryS3?logo=github&color=success)](https://github.com/Rdx1S/ShadowSentryS3/releases/latest)
[![Hackaday](https://img.shields.io/badge/Hackaday-project-1A1A1A?logo=hackaday&logoColor=yellow)](https://hackaday.io/project/205961-shadowsentry-s3-esp32-hardware-honeypot)
![Platform](https://img.shields.io/badge/platform-ESP32--S3-E7352C?logo=espressif&logoColor=white)
![Framework](https://img.shields.io/badge/framework-ESP--IDF%20v5.x-blue)
![Language](https://img.shields.io/badge/language-C-555555?logo=c&logoColor=white)
![Traps](https://img.shields.io/badge/honeypots-RTSP%20%7C%20HTTP%20%7C%20Telnet%20%7C%20SSH%20%7C%20FTP-1f9d55)
![Alerts](https://img.shields.io/badge/alerts-Telegram-26A5E4?logo=telegram&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

![ShadowSentry S3 Dashboard](docs/demo.gif)

<sub>The live dashboard streaming captured attacks in real time — protocol traps, GeoIP-located sources, harvested credentials and a captured shell session. (Illustrative data.)</sub>

</div>

ShadowSentry S3 is a self-contained **Edge Deception** hardware honeypot. It turns a single ESP32-S3 board (~$5) into an invisible trap for botnets, scanners and malware inside your local network. No Raspberry Pi, no cloud servers, no external databases — all processing and logging happen on one chip.

---

## This fork: Elecrow ESP Terminal 3.5" edition

This repository is a fork of [Rdx1S/ShadowSentryS3](https://github.com/Rdx1S/ShadowSentryS3) that runs on the Elecrow ESP Terminal 3.5" (sold as CrowPanel ESP32 Terminal, model ER-DLC35020S: "ESP Terminal 3.5 inch 320*480 SPI TFT Capacitive Touch Display with OV2640 Camera"). It adds a local front panel, an audible incident alarm, port scan, probe and ARP sweep detection, an ADB trap, the alternate Telnet and SSH ports, HTTP on 8080, 8000 and 9000 with request labels, tripwires on RDP, VNC, SMB, Redis, MySQL, MSSQL and JetDirect, MikroTik decoys (Winbox, the RouterOS API, the bandwidth-test server, MNDP and MAC-Telnet), log-only LAN discovery listeners with a seen-devices table, an ignore list, hidden admin ports, a microSD event log with summary metrics, runtime settings and over-the-air updates. Upstream's traps and monitors behave as before; Telnet and SSH also listen on their alternate ports, and the NVR page is also served on the alternate HTTP ports.

### Hardware (board revision V1.0)

| | |
|---|---|
| Module | ESP32-S3-WROOM-1-N16R8: 16 MB quad flash, 8 MB octal PSRAM |
| Display | 3.5" ILI9488, 480x320, SPI (SCLK 12, MOSI 13, MISO 14, CS 3, DC 42, backlight 46) |
| Touch | FT6236 capacitive, I2C 0x38 (SDA 2, SCL 1) |
| microSD | on the display's SPI bus, CS 10 |
| Camera | OV2640 on J5 (24-pin FPC): XCLK 7, PCLK 17, VSYNC 4, HREF 5, D0-D7 8, 47, 48, 21, 18, 16, 15, 6; SCCB on the touch I2C bus, 0x30; no PWDN or RESET |
| Buzzer | passive, GPIO 45 |
| USB | CH340C serial bridge; V1.0 has no auto-reset wiring |

Pin map: [`main/board/board.h`](main/board/board.h). The I2S microphone is not used.

### Traps and ports

| Port | Trap | Events | |
|---|---|---|---|
| 21 | FTP (upstream) | FTP | |
| 22, 2222 | SSH, wolfSSH (upstream), then the fake shell | SSH, Shell | 2222 is a fork addition, `SSH_ALT_PORT` |
| 23, 2323 | Telnet (upstream), then the fake shell | Telnet, Shell | 2323 is a fork addition, `TELNET_ALT_PORT` |
| 80, 8080, 8000, 9000 | HTTP, fake NVR (upstream page), one engine task | HTTP | 8080, 8000 and 9000 are fork additions, `HTTP_ALT_PORT1..3` |
| 554 | RTSP, fake Hikvision (upstream) | RTSP | |
| 5555 | ADB, fake Android TV box (fork) | ADB | `ADB_PORT` |
| 445 | SMB tripwire (fork) | Tripwire | `TRIPWIRE_SMB_PORT` |
| 1433 | MSSQL tripwire (fork) | Tripwire | `TRIPWIRE_MSSQL_PORT` |
| 3306 | MySQL tripwire, sends a 5.7 handshake (fork) | Tripwire | `TRIPWIRE_MYSQL_PORT` |
| 3389 | RDP tripwire (fork) | Tripwire | `TRIPWIRE_RDP_PORT` |
| 5900 | VNC tripwire, sends `RFB 003.008` (fork) | Tripwire | `TRIPWIRE_VNC_PORT` |
| 6379 | Redis tripwire (fork) | Tripwire | `TRIPWIRE_REDIS_PORT` |
| 9100 | JetDirect tripwire (fork) | Tripwire | `TRIPWIRE_JETDIRECT_PORT` |
| 2000 | MikroTik bandwidth-test decoy, sends its 4-byte hello (fork) | Tripwire | `TRIPWIRE_BTEST_PORT` |
| 8291 | MikroTik Winbox decoy, silent (fork) | Tripwire | `TRIPWIRE_WINBOX_PORT` |
| 8728 | MikroTik RouterOS API decoy, silent (fork) | Tripwire | `TRIPWIRE_ROSAPI_PORT` |
| UDP 5678 | MikroTik MNDP neighbour discovery, listen only, never announces (fork) | Tripwire | `TRIPWIRE_MNDP_PORT`, `TRIPWIRE_MT_WHITELIST` |
| UDP 20561 | MikroTik MAC-Telnet and MAC-Winbox, listen only (fork) | Tripwire | `TRIPWIRE_MACTELNET_PORT` |
| UDP 1900, 3702, 5355, 137, 9999, 20002, 56700, 987, 9302, 67 | LAN discovery listeners, log only, never answer (fork) | Discovery | `DISCOVERY_ENABLE`, `DISCOVERY_DHCP` |

The fork's ports follow a ranking of what reaches a home LAN most often: unauthenticated ADB (infected Android TV boxes and residential-proxy apps hunt for it), then Telnet and SSH bruteforce on the alternate ports. Each port option takes 0 to disable it; `main/honeypot/trap_listen.h` has defaults for a `config.h` written before these options. The alternate ports run on the existing Telnet and SSH tasks through `select()` (no extra stack, one wolfSSH context), so each service serves one session at a time across its two ports, as upstream does on one port. An event from an alternate port ends in "(port N)".

### What this fork adds

- Front panel (LVGL 8 + LovyanGFX, using Elecrow's own panel config), laid out for status and control rather than a scrolling log, in a bright palette (white and light grey text, saturated accents, slate cards) because the ILI9488 has no gamma tuning:
  - status bar: name, IP : port, clock, and a GREEN / YELLOW / RED condition pill
  - running light (GREEN): a 3 px bar under the status bar with a bright segment sweeping left to right every 2 s. The UI task drives it, so if the panel ever freezes the light stops: moving means alive. During an incident the alert emblem's rolling stripes take its place
  - GREEN: summary metrics only, no log, in the style of the Pi-hole dashboard (dark rounded cards, big numbers, thin frequency bars). Four tiles: alerts, probes and port scans today, and LAN devices seen. "Top offenders today": the five sources with the most alerts (SEV1 and SEV2) today, each with its discovery label or MAC vendor, IP, count and a bar against the top one. "LAN talkers": the five devices sending the most discovery traffic, each with its label or vendor, IP, packets an hour and one to five activity lights (under 30, 100, 300 and 600 an hour, then five; green, amber from three, red from four), and a bar. A footer line: ports listening, uptime, microSD free space, Wi-Fi RSSI. Tiles and offenders update on a change (checked every 2 s), talkers and the footer once a minute, and only changed text is redrawn
  - RED (unacknowledged): the whole screen goes black with a red alert emblem across the top, after the Starfleet alert graphic and drawn natively from LVGL lines, pills and labels: a rounded chevron above and below a central band, stacked stripes inside each, and "ALERT" over "CONDITION: RED" in the band. Under it the details: "Code 17-01 ARP sweep", the source IP and vendor, the headline's detail (wrapped at words over up to two lines), and the event count, first and last seen and how long it has been open. Then three buttons: ACKNOWLEDGE (2 s hold), IGNORE ERROR, IGNORE DEVICE. The backlight is forced to 100 %. The only motion is in the emblem's stripes: they roll toward the centre band (the upper ones down, the lower ones up) and loop, fading out at the band, a stripe from the top to the band in 1 s (2 s on YELLOW). The text and the chevron outlines stay still, and a frame repaints only the two stripe areas
  - YELLOW (acknowledged, or a SEV2 incident): the status bar stays, a smaller amber emblem ("ALERT / CONDITION: YELLOW"), the same details, IGNORE ERROR and IGNORE DEVICE, and a line "Resolve from the dashboard" that also says who acknowledged. There is no resolve on the panel
  - headlines: every event gets an alert code (see Alert codes below) and one line, for example "Code 17-02 Port scan | 192.168.0.75: 1000 ports in 3 s", "Code 20-02 Telnet login | 192.168.0.75: attempt as root" or "Code 30-02 Web dotfile | 192.168.0.75: /.env on port 8080" (`main/alarm/describe.c`). The same line leads on the dashboard's feed, attack table and Logs table, in Discord's incident and event-log posts, Telegram and WhatsApp, and in the microSD lines (`"headline"`, with `"tier"` and `"code"`)
  - hold to confirm: ACKNOWLEDGE takes a 2 s hold. A fill grows across the button as you hold; letting go or sliding off early empties it with no action, and completing it plays the acknowledgement tone
  - IGNORE ERROR and IGNORE DEVICE each ask first, naming exactly what will be ignored ("Ignore Code 17-01 ARP sweep from 192.168.0.75 (ASUSTek)?", "Ignore all alerts from 192.168.0.75 (ASUSTek)?"), and say the dashboard can undo it. Confirming calls `alarm_ignore_error()` (this code from this source) or `alarm_ignore_device()` (every code from it), which add the entry and resolve the incident (a later event whose code is not ignored opens a new one)
  - backlight brightness is a setting
- Sounds: at every boot, the opening of Grieg's "In the Hall of the Mountain King" (public domain), the theme's whole first statement in the score's rhythm at its marked tempo (crotchet = 138), short and detached as written, ending on its held A, about 7 s, played from its own task so boot does not wait. The red alert klaxon cuts it short at once. The boot sound can be switched off in Settings.
- Alert and console sounds, synthesised on the passive piezo (square wave, LEDC), after the Star Trek red alert and LCARS panel sounds (by ear from descriptions, no audio files):
  - red alert klaxon, for a RED incident and its reminders: three bursts of a deep two-tone warble, 860 and 1000 Hz alternating every 75 ms for 900 ms, then a rise from 2300 to 3100 Hz in 160 ms, 200 ms apart, 3.3 s in all. The piezo is weak far below its 2.7 kHz resonance, so the pair is chosen for their 3rd harmonics (2580 and 3000 Hz), which flank the resonance: both notes come out loud while the ear hears the low pitch. Acknowledging cuts it short within 25 ms
  - YELLOW attention call, once when a YELLOW incident opens: 2000 Hz for 100 ms, 30 ms quiet, 2600 Hz for 160 ms, at 12.5 % duty (about 8 dB softer)
  - console chirps: a tap on any press (2600 then 3200 Hz, 18 ms each), a confirm (2400, 2900, 3400 Hz, 20 to 25 ms each), a cancel (3200 then 2400 Hz), and the acknowledgement tone when a hold completes (3000 Hz 60 ms, 30 ms quiet, 3400 Hz 120 ms). They play on the buzzer task, never during the klaxon or the boot tune, and follow the touch click setting; the klaxon and the attention call follow the alarm sound setting
- Incident alarm, with three conditions kept by the firmware and echoed 1:1 to the panel, the dashboard (`/api/status` and the WebSocket push) and the alerts:
  - GREEN: no open incident.
  - RED: an open incident with a SEV1 event, unacknowledged. The red alert klaxon (above), then the klaxon again every minute until someone acknowledges it, by holding the button on the panel or clicking Acknowledge on the dashboard. Acknowledging cuts the klaxon short and turns the incident YELLOW.
  - YELLOW: a RED incident that was acknowledged, or one opened by SEV2 events only (an ARP sweep from a PC waking up, a probe, a web scanner). Never the klaxon: one soft attention call when it opens directly, no reminders.
  - In YELLOW the same source stays quiet. A SEV1 event from a new source, or from the same source after 10 quiet minutes, opens a new RED incident; a SEV1 event from the same source in a YELLOW incident nobody acknowledged turns it RED in place. A SEV2 event from a new source opens a new YELLOW one.
  - Resolve (Resolve on the dashboard, `POST /api/alarm/resolve`; not on the panel) goes to GREEN from RED or YELLOW at once, so the next event alarms again. It deletes nothing: the logs, metrics and the panel's last-incident summary all stay. A YELLOW incident also goes GREEN by itself after the quiet time without events; a RED one never does.
  - The incident survives a reboot: RED keeps reminding, YELLOW stays YELLOW and its quiet time starts again. The reminder interval (default 60 s), quiet time and alarm sound are settings.
- ADB trap on 5555 (`main/honeypot/adb_trap.c`, protocol handling ported from [Glutton](https://github.com/mushorg/glutton), MIT, see [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES)): it answers the CNXN handshake as an Android 6 TV box with auth off (`device::ro.product.name=p281;ro.product.model=MBOX;...`) and logs, as ADB events:
  - the connection with the client's banner (alert)
  - every OPEN: `shell:<cmd>` and `exec:<cmd>` get canned output for recon commands (`id`, `whoami`, `uname -m`, `getprop ...`, a plain `echo`) and silence for everything else; `shell:` gives an interactive prompt and every line is logged; anything else (`tcp:`, `localabstract:`, `reverse:`, ...) is refused and logged, so the honeypot never forwards a connection (alert)
  - `sync:` pushes: the remote path, size and SHA-256 of each pushed file (alert); an unfinished push is logged with the bytes received. The bytes themselves are not kept yet. Pulls are logged and fail with "No such file or directory".
  - Bounds: one session at a time, 60 s per session, 10 s idle, 1 MB received, 4096 messages, 4 streams, 64 logged events, 4 KB per message (the maximum we advertise). Nothing is executed.
- HTTP engine (`main/honeypot/http_engine.c`, `HTTP_ENGINE_ENABLE`, default on): one task `select()`s over 80, 8080, 8000 and 9000 (DShield top 10 ports; `HTTP_ALT_PORT1..3`, 0 disables one) and serves up to 4 connections at once across them. Every port serves upstream's NVR page and replies, byte for byte: GET the login page, POST a 302 to /, anything else an empty 404. Upstream's `http_trap.c` is untouched; `HTTP_ENGINE_ENABLE 0` runs it instead, on port 80 only.
  - Every request is an HTTP event (flash ring, panel, dashboard, alerts). The payload starts with a label, then the port: `<label> on <port>: <method> <path> [user:pass] H=<Host> UA=<User-Agent>`. POSTed `username` and `password` fields go in the event's user and pass, as upstream.
  - Labels, first match wins, from the request's shape and the User-Agent only: non-HTTP payload, oversize request (head over 4 KB, a line over 1 KB, a URL over 512 B), path with .., login POST, dotfile path (a segment starting with "."), unusual method (not GET, POST or HEAD), scanner UA (nmap, masscan, zgrab, Nuclei, Nikto and a few more), HTTP library UA (curl, Wget, python-requests, Go-http-client and a few more), else unclassified. The microSD attack line gets `"category"` (`non_http`, `oversize`, `dotdot_path`, `login_post`, `dotfile_path`, `odd_method`, `scanner_ua`, `library_ua`, `unclassified`).
  - The whole request is kept on the card: a `{"kind":"http"}` line per request with the port, category, request line, Host, User-Agent, the first 512 B of the body and the lengths. The console prints the same.
  - Limits: 4 KB head and 8 KB body read, one request per connection, 5 s idle and 10 s per connection, 2 s send timeout. At most 60 events a minute reach the flash ring and the alerts; past that, requests go to the console and the card only, and one event says how many. Nothing is fetched or executed. Buffers are in PSRAM; the 4 KB task stack is internal (it writes SPIFFS) and its high-water is printed at each new low.
- Tripwires (`main/honeypot/tripwire.c`, `TRIPWIRE_ENABLE`, default on): ports for services the board does not run and nothing on a home LAN should ask it for, so any connection is the alert (find the host, or pull it off the network). RDP 3389, VNC 5900, SMB 445, Redis 6379, MySQL 3306, MSSQL 1433 and JetDirect 9100 (`TRIPWIRE_<NAME>_PORT`, 0 disables one).
  - Per connection: accept, send the banner if the service speaks first (VNC `RFB 003.008`; MySQL a 5.7 handshake with no TLS offered, so a client sends its login packet), wait up to 3 s for the client's first bytes, read at most 64, log one Tripwire event and close. No protocol or credential parsing, no second round trip, 5 s per connection, one connection at a time across all the tripwire ports.
  - The event reads `<service> on <port>: <first bytes in hex>` (`no data` if the client sent nothing), trimmed to the 128-byte payload; the console prints all 64 bytes. The microSD attack line gets `"service"` (`RDP`, `VNC`, `SMB`, `Redis`, `MySQL`, `MSSQL`, `JetDirect`, and for the MikroTik decoys below `Winbox`, `RouterOS API`, `Bandwidth test`, `MNDP`, `MAC-Telnet`).
  - Rate limit: one event per source and service per 30 s. Further connections in that window are accepted, printed on the console and counted, and the next event says how many (`RDP on 3389 (+4 held): ...`).
  - Each tripwire port is also a trap port for the probe detector. One internal 3 KB task stack (it writes SPIFFS); its high-water is printed at each new low.
- MikroTik decoys (logged by the tripwire task, same rate limit and event type; `main/honeypot/mt_decoy.c` reads the protocols, bounded, and never sends; written from MikroTik's API manual, btest-opensource's protocol notes (MIT) and, consulted only, Wireshark's MNDP dissector and MAC-Telnet (both GPL), see [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES)). They use MikroTik-specific ports only: the FTP, SSH, Telnet and HTTP traps on 21, 22, 23 and 80 keep presenting their own devices, since one box answering as a Hikvision NVR on 80 and a RouterOS router on 22 would give the honeypot away. On a home LAN an internet scanner cannot reach the board, so a hit means a LAN host is looking for routers to attack, as Glupteba-infected PCs do with their own gateway.
  - Winbox, TCP 8291 (`TRIPWIRE_WINBOX_PORT`): the client speaks first; the decoy stays silent, logs the first frame (its first 64 bytes in hex, and its length: the bytes of the first burst, counted up to 2048) and closes. `Winbox on 8291: frame 41 B: <hex>`, headline "Code 40-10 Winbox | <ip>: Winbox connection, first frame 41 bytes".
  - RouterOS API, TCP 8728 (`TRIPWIRE_ROSAPI_PORT`): silent. The first sentence's length-prefixed words are read per MikroTik's API manual (at most 8 words in the first 64 bytes); only the command word and the `=name=` value are copied out. The password word is skipped without being copied, so it is never logged, stored or printed, and no hex of this port's bytes is kept anywhere. `RouterOS API on 8728: /login as admin, 38 B`; the user name also goes in the event's user field.
  - Bandwidth test, TCP 2000 (`TRIPWIRE_BTEST_PORT`): sends the server hello `01 00 00 00` (the only reply any MikroTik decoy sends), then logs the client's command (protocol and direction when it reads as one, then hex) and closes.
  - MNDP, UDP 5678 (`TRIPWIRE_MNDP_PORT`): passive, never announces. A solicitation (the 4-byte request Winbox and mactelnet broadcast to find neighbours) or an announcement (identity, version and board read from its type-length-value records) is an event, unless the sender's MAC is the gateway's (looked up by itself from the default gateway and the ARP cache, every 60 s), one of the router's own interface MACs (read with `/rest/interface` when the MikroTik client below is on, at its first poll and hourly) or on `TRIPWIRE_MT_WHITELIST`, or the datagram's IP source is the gateway's: RouterOS announces from each interface's own MAC, which need not be the one ARP gives for the gateway. For the first 60 s after boot MNDP and MAC-Telnet datagrams wait in the ring until the gateway's MAC and the router's MACs are known, so the router's first announcement is not taken for a stranger's. A real MikroTik router announces itself every 60 s; the first whitelisted datagram is said once on the console and the rest are counted. SEV2, so a YELLOW at most: Winbox on a PC sends discovery too. One event per source per 5 minutes, since Winbox repeats its scan.
  - MAC-Telnet, UDP 20561 (`TRIPWIRE_MACTELNET_PORT`): these sessions are layer 2 by name, but mactelnet broadcasts its packets at the IP layer, so the board receives them through lwIP. A packet whose header names the board's MAC is an event (session start, data, ping, ...), unless it comes from a whitelisted MAC as for MNDP (the gateway's IP alone does not count here); sessions for other MACs are counted only.
  - No sockets and no file descriptors: lwIP's sockets and the open files share the 64 descriptors of `FD_SETSIZE`, and both are fully budgeted. The TCP decoys are raw lwIP pcbs (callbacks on the tcpip thread doing bounded work only: at most 64 bytes copied, the API words read there so only the command and user name leave the callback, a fixed-size result posted with no wait; at most 2 connections at once, the rest aborted; each closed after 3 s without data or 5 s in all). The UDP decoys have no socket: the station interface's input wrapper (the one the ARP sweep detector uses) copies each datagram to 5678 or 20561 that is for the board (its address or a broadcast) into an 8-slot ring in PSRAM, up to 512 bytes each, with the frame's source MAC. Without a socket, a unicast datagram to these ports gets lwIP's ICMP port unreachable, as any closed port does; broadcasts get nothing. The tripwire task reads the queue and the ring every 250 ms and logs as for the other tripwires (its internal stack writes the flash ring, which the discovery task's PSRAM stack cannot).
- LAN discovery listeners (`main/detect/discovery.c`, `DISCOVERY_ENABLE`, default on), to see which devices on the LAN scan or discover the others (an LG TV opening Photo & Video or Home Dashboard, phone apps, Home Assistant, Windows) and with what. Log only: these sockets never send, so nothing in the house sees them or changes behaviour.
  - SSDP on UDP 1900 (joins 239.255.255.250): M-SEARCH with ST, MAN, MX and USER-AGENT, NOTIFY with NT, NTS, SERVER and LOCATION. WS-Discovery on 3702 (same group): the action (Probe, Hello, Resolve), Types, Scopes and XAddrs, read with bounded string scans, no XML parser. LLMNR on 5355 (joins 224.0.0.252): the queried names and types, queries only. NBNS on 137 (broadcast): the queried name; a registration's name is the sender's own NetBIOS name. Kasa on 9999 and 20002, LIFX on 56700, PlayStation on 987 and 9302: the size and first 16 bytes in hex, plus Kasa's XOR-encoded JSON on 9999, LIFX's message type and a PlayStation request's first line. DHCP on 67 (client broadcasts, receive only; the board's own client is on 68): the hostname (option 12), vendor class (60) and parameter request list (55) as a fingerprint (`DISCOVERY_DHCP` 0 leaves 67 alone). UDP 9999 coexists with the admin panel on TCP 9999.
  - mDNS (5353) has no socket: the espressif/mdns component owns 5353 on a raw lwIP pcb without `SO_REUSEADDR`, so a second socket cannot bind, and one that won the race would take `.local` away from the board. Instead the station interface's input wrapper (the one the ARP sweep detector uses) copies each mDNS query (to 224.0.0.251, or unicast to the board; responses skipped) into an 8-slot ring in PSRAM, at most 512 bytes each, dropped and counted when the ring is full. The discovery task reads the questions (names and types, up to 8) with the same bounded DNS name reader as LLMNR. The mdns component is untouched and still answers for `.local`. IPv4 only.
  - Source MACs come from that same wrapper, which notes the sender's MAC for UDP to these ports; DHCP uses the packet's client MAC; otherwise the ARP cache.
  - Seen devices: up to 64, keyed by MAC, least recently seen evicted, in PSRAM. Each has the IP, first and last seen, the protocols with a packet count each, the best label so far, the DHCP or NetBIOS hostname and the last 4 distinct query strings. Labels, best first: a known string in an SSDP USER-AGENT or SERVER, a DHCP hostname or vendor class (LG webOS, Samsung, Roku, Sonos, Philips Hue, Fire TV, Xbox, PlayStation, Chromecast, Windows, Android), then a raw hostname, a raw vendor class or SERVER string, and the MAC vendor last. A locally administered MAC (phones randomise theirs) is marked "random MAC".
  - Logging: a `{"kind":"discovery"}` line on the card (and the console) only for a new device, a new protocol, a new label or hostname, or a query string that device never sent before (the last 32 distinct ones per device are remembered), at most 20 at once then one every 3 s. Once an hour each device that sent anything gets one `{"kind":"discovery_summary"}` line with its packet count per protocol and how many new queries it made. Nothing is written per packet; a chatty LAN costs well under 1 MB a day.
  - Discord: discovery does not post event by event. Every 30 minutes, and only when something new was seen, one message "LAN devices seen (last 30 min)" lists each device with news, newest first: its label (marked "(new)" if first seen), its IP (or MAC before it has one), and what it did in plain words, for example `LG TV (webOS) 192.168.0.50: looking for media servers (DLNA); DHCP request, hostname LGwebOSTV`. At most 20 lines within Discord's 2000 characters, each cut at a word boundary, then "+N more on the Devices tab". The words come from a table in flash (SSDP search targets such as DIAL, DLNA, Roku, WeMo and the router; announcements; Kasa, LIFX and PlayStation probes; NetBIOS and LLMNR names, WPAD called out; DHCP type, hostname and vendor class; WS-Discovery printers, scanners and ONVIF cameras; mDNS services such as Chromecast, AirPlay, Spotify Connect, HomeKit and printers); anything else is shown shortened.
  - Discovery events stay out of the 200-entry flash ring, so they never push real attacks out of it, the dashboard's attack list and feed, or the panel's last events. They are not counted in the summary metrics (`stats.bin`) either; the Devices tab has its own counts.
  - Discovery is background noise, so its Alert on switch is off by default: it opens no incident unless switched on (then it goes straight to the incident logic and Telegram, as other types do). A mask saved by older firmware does not switch it on (settings remember how many types the saved mask knew).
  - Every datagram is hostile: every length and offset is checked, DNS names follow at most 8 compression pointers and only backwards, strings are cut to printable ASCII on the way in and escaped on the way out. The task never touches flash, so its 3.5 KB stack is in PSRAM; its high-water is printed at each new low.
- MAC vendor database (`main/storage/oui.c`): vendor names for every MAC the board shows (panel, dashboard, Discord, the Devices tab), from the IEEE Registration Authority's public registry (MA-L, MA-M, MA-S and IAB), kept on the microSD card as `/sd/oui.bin`.
  - Build it on a PC: `python tools/make_oui.py --download` (or give it the four CSVs saved from standards-oui.ieee.org). It writes a sorted binary (prefix, prefix length, an offset into a deduplicated table of names cut to 40 characters) and prints its size and record count. Upload it with `python tools/oui_upload.py oui.bin <board IP>` or the Settings page's "Update vendor database" (file picker and progress); the Settings page shows whether it is present, the record count and the build date.
  - `POST /api/oui` takes the raw file (at most 4 MB) into PSRAM, checks the header against its length and hands it to the microSD writer, which writes `/sd/oui.bin.tmp` and renames it.
  - Lookups search the 36-bit, then 28-bit, then 24-bit prefix, reading only what each step needs, and keep the last 64 results in PSRAM. Only the discovery task and the admin task read the card; everywhere else (traps, panel, Discord) gets the cached name or the compact built-in list, and a miss is resolved in the background. A randomised (locally administered) MAC is shown as "randomized (private)" and never looked up. Without the file the compact built-in list answers, as before.
- Fake shell input (upstream's `main/honeypot/fake_shell.c`, shared by Telnet and SSH), made sturdier; the command output is upstream's:
  - Idle limit 120 s in the shell (`FAKE_SHELL_IDLE_S`; the login prompts keep 30 s), then bash's TMOUT message "timed out waiting for input: auto-logout" and the close. Before, the 30 s login timeout also applied in the shell, so a pause of 30 s closed the session with no message.
  - Session cap 600 s (`FAKE_SHELL_SESSION_S`, checked as bytes arrive, so an idle wait can add up to 120 s) and 64 KB received (`FAKE_SHELL_MAX_INPUT`).
  - A bare LF ends a line, so netcat and other LF-only clients get a prompt for an empty line (only an LF straight after a CR is swallowed now). Ctrl-C drops the line and prints `^C`. Escape sequences (`ESC [ ... final`, `ESC O x`: arrow and function keys) are dropped. A line longer than 255 bytes is dropped whole up to its newline, not cut down and run.
  - The console's "shell session ended" line says why (logout, closed, idle, session cap, byte cap, command cap) and how many bytes came in.
- Recon detection (`main/detect/detect.c`), so a scan raises an alert before any trap sees a login:
  - an lwIP IPv4 input hook sees every inbound TCP SYN (plus FIN, NULL and Xmas probes) and UDP datagram to the board, open port or not. It only queues (source, port, protocol); the gateway and replies to the board's own DNS, DHCP, NTP and mDNS are skipped.
  - Port scan: 5 distinct ports from one source within 10 s (both settings) raise one "Port scan" event with the port count, lowest to highest port, protocol and sample ports. Nothing more while it continues; after 60 s of quiet a summary follows ("Scan ended: N ports total", with the trap ports it found).
  - Probe: a SYN to a trap port (21, 22, 23, 80, 554, 2222, 2323, 5555, 8000, 8080, 9000 and the tripwire ports 445, 1433, 2000, 3306, 3389, 5900, 6379, 8291, 8728, 9100; a disabled one excluded) raises one "Probe" per source, port and minute. It is held 1.5 s, so a scan that starts meanwhile folds it in; none while that source is scanning. The HTTP engine, ADB and the tripwires log every connection they take, so on their ports the probe is held 6 s and dropped once the service has logged the connection: one connection is one event, and only a SYN that never became a logged connection (a half-open scan, a connect that sent nothing to HTTP or ADB) is a probe.
  - ARP sweep: a wrapper on the station interface's input sees ARP who-has requests (every frame is passed on). One MAC asking for 10 distinct hosts within 10 s (settings) raises one "ARP sweep" event with the MAC, vendor, count and range, then a summary after 60 s of quiet. The gateway and the board itself are excluded.
  - The three are new attack types (appended, so the flash ring stays readable) shown everywhere: panel, dashboard type list, filters and charts, microSD `tname`, Telegram.
  - The Logs page shows the detector's counters since boot (scans, probes, sweeps, packets queued and dropped, admin SYNs hidden, ARP tap on or off).
- Alert on: one switch per attack type on the Settings page decides whether that type opens an incident (siren, panel, Telegram, Discord). Every event is logged either way (flash ring, microSD, dashboard).
- Ignore list: up to 32 entries, each an IP and/or a MAC (DHCP moves IPs) and an optional alert code, with a note and the time added, in NVS. An entry matches on either address; with a code it ignores only that code from the device (say 17-01, the ARP sweep a PC makes when it wakes), without one the whole device. Lists saved by older firmware are migrated as whole-device entries. Ignored events are still logged, flagged "ignored" (`"ignored":true` on the microSD line, a chip in the dashboard tables), and never open an incident or alert. View, add and remove (with a confirm) on the Settings page; the panel can add. Ignore error and Ignore device (`POST /api/alarm/ignore`) add the open incident's source with its code, or with none, and resolve the incident, whatever else it saw; a later event whose code is not ignored opens a new one.
- Hidden admin ports: with an admin allowlist set (up to 8 IPv4s, Settings), the IPv4 hook drops SYNs to 9999 and 9998 from anyone else, so a scan shows them filtered rather than giving the honeypot away. Those dropped SYNs still count toward port scan detection. An empty list means open, as before. The dashboard refuses a list that does not include the address you are saving it from. Locked out anyway (a new DHCP lease, say)? Open the USB serial console (115200, `pio device monitor -e crowpanel35`) and type `admin-allow clear` then Enter: the list is emptied in NVS and the ports open at once. `admin-allow` alone prints the list.
- microSD event log: every attack, alarm transition and boot is appended as one JSON line to `/sd/log/YYYY-MM-DD.jsonl` (device local date; `nosync.jsonl` before the clock is set). A writer task drains a queue, so the traps never touch FAT. The card must be FAT32 or exFAT; the firmware never formats it.
- Summary metrics, kept from every attack and saved to `/sd/stats.bin` once a minute (and before a reboot or OTA): total and per-type counts, 24 hourly and 30 daily buckets, the top 64 sources and top 32 credential pairs. Top-N counts are upper bounds for entries that were evicted and came back.
- Dashboard tabs: Dashboard (upstream, plus the condition banner), Logs, Devices and Settings.
  - Condition banner, under the header on every tab, the panel's condition 1:1. It follows `/api/status` (every 5 s) and the WebSocket alarm push, so it changes the second the panel does. RED: "ALERT / CONDITION: RED" in a large red band with a chevron emblem; YELLOW: a smaller amber band; GREEN: a slim green "Condition green" line. Red and yellow show the code and headline, the source (IP, vendor and MAC), the event count, first and last, and who acknowledged it. Buttons: ACKNOWLEDGE (red only), RESOLVE (red or yellow; the dashboard is the only place to resolve), IGNORE ERROR (this code from this device) and IGNORE DEVICE (every alert from it), each ignore behind a confirm that names exactly what goes on the ignore list. With firmware that sends no condition, state 1 reads as red and 2 as yellow, RESOLVE falls back to the re-arm route and IGNORE DEVICE to the ignore list; IGNORE ERROR needs a code, so it is hidden.
  - Error codes: every event, incident and log line from firmware with codes shows "Code NN-NN" before its headline, in the feed, the attack table, the event popup, the Logs table (a Code column and a code filter) and the Devices tab. The names and tiers come from `GET /api/codes` (the table in `main/alarm/describe.c`), so the page needs no copy of it. The banner's buttons show the state the firmware answers with at once.
  - Event popup: the title is "Code NN-NN <name>" with the tier (Info, Probe or Alert); without a code it is the type name, and "attack" only for the alert tier, so a TV announcing itself reads "Discovery event". Copy details copies a plain-text report of every row the popup shows (code, headline, tier, time, protocol, source, location, MAC, vendor, credentials, payload, alerting state, counts), with the labels aligned. The Source IP row has a button that copies `ip:port`, the trap port the event hit (from the event, else the type's port). The dashboard is plain http, where browsers withhold `navigator.clipboard`, so both copy through a hidden text area (`document.execCommand('copy')`) and say "Copy failed" if that fails too.
  - Devices: the seen-devices table, newest first, refreshed every 10 s: label (and where it came from, and the hostname), IP, MAC and vendor (and "random MAC"), protocols with packet counts, last seen, the last queries; above it, which listeners are open.
    - Click a device for its analysis and its alert switches. "Alerts from this device" has one switch per code seen from it, plus "All alerts from this device", each showing whether it alerts or is ignored; switching one off adds the matching ignore entry (that code, or "" for all), switching it on removes it.
    - Open device page (in the same row): the device's own page, `/device?mac=..&ip=..`, in a new window. At the top its identity (label, vendor, IP, MAC, randomised flag, hostname, protocols, first and last seen), the same analysis and Get AI advice. Then an issue summary of everything loaded from its log: one row per code with its name and tier, the count and the first and last time, worst tier first then by count, with the per-code alert switch and "All alerts from this device"; LAN discovery lines count as 60-01, lines with no code by kind (incident changes, HTTP request details). An activity chart (per hour over up to 48 h, else per day) and "summary covers N lines back to <time>". Then the messages, newest first, as readable rows (time, code, plain-English headline); a click opens the full detail as labelled fields, as in the event popup, with Copy details and Copy ip:port (both with the plain-http fallback) and the raw line only behind a collapsed "raw" toggle. The newest 100 load at once; Load older pages further back, and Scan full history pages to the end with a progress bar (bytes read over the day files' size) and a Stop button. Discovery is logged per new observation (a new device, protocol, label or query), not per packet.
    - Router section on the device page (from `GET /api/device/intel`, hidden when the MikroTik client is off or the firmware has no route): how the device is connected (Wi-Fi and its access point, SSID and signal in dBm with a word for it, or the switch port and bridge), its DHCP hostname, client ID and lease, and whether it is new on the network; the flags, worst first (a blocked name reached anyway, regular check-ins, upload-heavy, unusual port, DNS that skips Pi-hole, encrypted DNS, no DNS name, many outside hosts), each with the firmware's reason and a line on what it means; and the outbound table, busiest first: name and where the name came from, address, port and protocol, up and down in B, KB, MB or GB, connections, first and last seen (the board's reads of the router's table), country and network owner, the per-destination flags and a beacon note ("every N s, M times"). A line above the table says what it is: the connections the router's table held at each read (when the page opens, then every 60 s for 15 minutes), so a connection that opens and closes between two reads is missed. Local destinations are behind a tick box. While the board is still asking the router (`conn.pending`), the page asks again every 3 s, five times at most; Refresh asks again. A row with a `source` field gets a Seen by column, ready for flow records. For the router's own address, the configuration checks that changed since the baseline.
    - Blocking from the device page (needs the router's block list, `GET /api/block`; the buttons stay hidden when the firmware answers 404): "Block traffic to this address" on each internet destination and "Block this device" at the top. Each asks first, in plain words: the address goes on ShadowSentry's block list in the router, which drops the traffic within about a minute; a destination block stops every device reaching that address, since the list holds addresses; a device block cuts it off from the internet and your other networks, not always from devices on the same LAN segment, and follows the IP; and how to undo it. A blocked row shows "Blocked" and since when, with Unblock (`POST /api/block/remove`); the header shows the device's state and how much of the list is used. A refusal (an address that must never be blocked, or a full list) is shown with the router lane's reason.
    - Pi-hole section on the device page (from `GET /api/pihole/device`, hidden when Pi-hole is off): Pi-hole's names and addresses for the device, its vendor, first seen and last lookup, lookups and blocked lookups over Pi-hole's last 24 h (with the share blocked), all-time lookups, and the top domains of its last 100 lookups with counts; "Pi-hole does not know this device" when it does not. Refresh from Pi-hole (`POST /api/pihole/refresh?ip=`) asks for this device first, then the page reads the result every 3 s for up to 18 s; a refresh within 30 s of the last says when it can be asked again.
    - Get AI advice (on the device, on the device page and in the event popup): opens claude.ai in a new tab with a plain-text prompt ("I run a home-network honeypot. Analyse this device and tell me if it's a risk and what to do:", then the identity, behaviour, rates, last queries, risk notes and suggestion; on the device page also the router's flags and top outbound destinations, Pi-hole's lookup counts and top domains, the issue summary and the newest log lines; or the event report), at most about 4000 characters, and copies the same prompt to the clipboard, since claude.ai's `?q=` prefill is undocumented and has broken before. Privacy: the device's or event's details (IPs, MACs, vendor, names, queries, payloads) go to claude.ai only when you click the button, and only from your browser; the board itself never contacts claude.ai.
    - The analysis is worked out in the page from the same data by a small rule table (no firmware or device RAM): identity (MAC vendor, model hint from the label or SERVER string, DHCP vendor class, randomised MAC), behaviour in plain words (what it searches for or announces, WPAD and broadcast name lookups), short risk notes (old Android, WPAD, scanning for other makers' IoT gear, very chatty multicast, unidentifiable; a Google or Nest, Amazon or Apple device scanning other makers' gear is a smart-home hub doing its job, so it gets Watch with that reason, not Isolate), a suggestion (known and benign: name it, watch, or isolate on a guest or IoT network) and packets per hour per protocol.
  - Speed: the pages are embedded gzip-compressed (`tools/gzip_assets.py` writes `main/gz/` at build time, from CMake at configure time and from PlatformIO as a pre: script) and served with `Content-Encoding: gzip` and an ETag, so a reload gets 304 with no body: the dashboard is 34 KB on the wire instead of 116 KB, the device page 11 KB instead of 31 KB, `analysis.js` 4 KB instead of 8 KB. The admin port holds up to 4 connections at once under `select()` and serves whichever has a complete request, so a browser's speculative connection that sends nothing no longer holds every other request for 5 s; silent connections are closed after 2 s (after 500 ms when all 4 are taken). Requests are still answered one at a time, so a device-log scan (3 s at most) or an OTA still holds the others while it runs. The page asks for `/api/status` first, then only the visible tab's data, refreshes only the visible tab, and keeps at most 2 requests in flight. Every panel shows a spinner until its data arrives, or the error with a Retry button.
  - Heartbeat: the shield in the header gives one soft pulse (a slight glow and scale, under 1 s) each time the 5 s status poll gets an answer. After two missed polls in a row it stops and fades to grey until the device answers again. The ACTIVE pill is unchanged.
  - Logs: summary cards, 24 h, daily and by-type charts, top sources and top credentials, card status, and a day picker that loads a day file (the last 256 KB, or the whole file) into a filterable table, newest first, with a download link.
    - Discovery lines are hidden unless "Show discovery" is ticked (remembered in the browser), and consecutive identical ones collapse into one row with xN and the time range. Username and Password columns appear only when a row on screen has one; Details takes the rest of the width and wraps. Vendor and MAC share one column as "vendor (mac)".
  - Readability: base text 15 px, tables 14 to 15 px, small text 13 px, text near white (#f1f5f9) and secondary text #cbd5e1; monospace only for IPs and MACs; tables scroll sideways on a narrow screen instead of shrinking.
  - Ignore list (Settings): a Code column ("All alerts" for a whole-device entry), and the Add row has a code list: "All alerts from this device", then every code with its name.
  - Settings: admin password, Wi-Fi, Telegram, Discord, WhatsApp, Pi-hole (collapsed, optional), MikroTik, timezone (POSIX TZ, with presets), alarm timings, brightness and the three sounds, the Alert on switches, the scan and sweep thresholds, the admin allowlist, plus Save, Reboot and Test buzzer (Discord and WhatsApp each have a Send test button), and below them the ignore list. Settings live in NVS over the `config.h` defaults and survive OTA. Wi-Fi and Telegram apply after a reboot, the rest at once. If a Wi-Fi network saved here gets no IP within 90 s at boot, the board drops it and comes back on the `config.h` network.
- Discord alerts, to a channel webhook (`main/admin/discord.c`):
  - Incidents, each titled with the code first ("Code 17-02 Port scan: incident #12 opened, RED"): an embed when one opens (red for RED, amber for YELLOW: the headline, source IP, MAC and vendor, attack type, the event's username and payload, the device's IP and name) or escalates to RED, a reminder every alarm reminder interval while it is RED (orange: events so far, how long it has been open), one when it is acknowledged (amber, YELLOW, saying whether from the panel or the dashboard) and one when it goes GREEN (green: event count and duration, and whether it was resolved, and where, or closed by the quiet time). Count-only updates never post.
  - Event log (the Discord twin of the microSD log), on by default: events are folded by source IP, attack type and a short summary (shell: the command's first word, so 110 runs of `ls` post once as `ran ls x110`; credential traps: user:pass; HTTP: method and path; otherwise the first 40 characters), and posted every 15 s as lines in a code block. A line that has posted waits 5 minutes before its next post, which shows only the new count (`+40 more`); a line idle for 10 minutes is forgotten. At most 32 lines per post, the rest follow in the next one.
  - Set it up: in Discord, channel settings, Integrations, Webhooks, New Webhook, Copy Webhook URL. Paste the URL into Settings, Discord (or set `DISCORD_WEBHOOK_URL` in `main/config.h` as the default), Save, then Send test. It applies at once, no reboot. "Clear webhook" turns Discord off; "Post the event log" turns the log off while incident alerts stay on.
  - The URL is a secret: it is never logged or returned by the API, only reported as set. Every post has `allowed_mentions` empty, attacker text is cut to printable ASCII with backticks replaced, so it can't ping anyone or break out of its code formatting. Posts are paced for Discord's webhook limit and honour HTTP 429 `retry_after`.
- Notifications (`main/admin/notify.c`): one small layer, `notify_send(kind, title, text, severity)`, fans a message out to every enabled backend (Discord, Telegram, WhatsApp). Each backend keeps its own queue and task, so a slow HTTPS post never holds the caller; a new backend (ntfy, Slack, a generic webhook) is one new file that registers a `notify_backend_t`.
  - Reboots: after Wi-Fi is up, every boot sends one "online" message to every enabled backend with the device IP and mDNS name, the firmware version and build, the dashboard URL and the reset reason in words: power-on, software restart, panic/crash, interrupt watchdog, task watchdog, other watchdog, brown-out, deep sleep, external pin or unknown. A software restart says why when the firmware knows: OTA update, reboot from the dashboard, or the saved Wi-Fi getting no IP (the reason is stored in NVS just before the restart and cleared at boot). Crashes and watchdogs post in red, brown-outs in amber, the rest in green. The microSD log's `boot` line carries the same text as `reason`, next to the numeric `reset`.
  - Telegram (upstream) now sends nothing while it is not configured; before, each alert was tried three times against api.telegram.org with the placeholder token. Its boot message comes through this layer, with the reset reason.
- WhatsApp alerts via [CallMeBot](https://www.callmebot.com/blog/free-api-whatsapp-messages/) (`main/admin/whatsapp.c`), the usual free route for an ESP32: an HTTPS GET to `api.callmebot.com/whatsapp.php` with the phone number, the URL-encoded text and an apikey.
  - Sends the boot message and incidents (opened RED or YELLOW, escalated, acknowledged, resolved or closed), not the event log, each titled with the alert code. Messages are short plain text: incident number, the headline (attacker tokens in it are cut to short printable ASCII), attack type, source IP, event count.
  - CallMeBot documents no rate limit, so the sender stays well clear: one message every 10 s at most, 20 an hour, anything over the cap dropped and counted. The free API is for personal use and only sends to the number that registered the key.
  - Set it up: follow the activation steps on CallMeBot's page to get an apikey for your number, then enter the number (international format, country code first, e.g. `+34123123123`) and the apikey in Settings, WhatsApp (or set `WHATSAPP_PHONE` and `WHATSAPP_APIKEY` in `main/config.h`), Save, then Send test. Both set means on; it applies at once. "Clear apikey" turns it off.
  - The apikey is a secret: it is never logged or returned by the API (only `whatsapp_apikey_set`), and the request URL that carries it is never logged.
  - Not implemented: Meta's official [WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api), the heavier alternative (a Meta business account, a registered sender number, approved message templates for business-initiated messages, and access tokens to manage).
- Pi-hole device data, optional (`main/admin/pihole.c`): with a [Pi-hole v6](https://docs.pi-hole.net/api/) on the LAN, the board reads what Pi-hole knows about each device and adds it to the device reporting. Read only: nothing on the Pi-hole is changed. Without a Pi-hole, leave it unset: it stays off, with no task, no memory used and no traffic, and the Devices tab looks as before.
  - What it adds: per device, Pi-hole's names for it, its addresses and vendor, first seen and last query, its DNS query and blocked counts over Pi-hole's in-memory window (24 h by default), and the top 10 domains of its last 100 queries. The Devices tab shows the Pi-hole name and query count columns when Pi-hole knows a device, and a Pi-hole box in the device's analysis; `/api/devices` entries gain a `"pihole"` object, and `GET /api/pihole/device?mac=..&ip=..` gives the same object for one device. A device whose own label is only its MAC vendor (or nothing) takes Pi-hole's name as its label ("from Pi-hole's name for it"), on the panel too.
  - Set it up: in Pi-hole, Settings, Web interface / API, switch to Expert, "Configure app password", copy the password and enable it. On the dashboard, Settings, Pi-hole: the URL without `/admin` (for example `http://ph.local` or `http://192.168.0.2`), the app password, Save, then Test connection, then tick "Read device data from Pi-hole" and Save. Or set `PIHOLE_URL` and `PIHOLE_APP_PASSWORD` in `main/config.h`, which turns it on by default. It applies at once, no reboot.
  - Security: over `http://` the app password crosses the LAN in the clear on every login, so use an app password (it can read everything but cannot change Pi-hole's configuration), never the admin one. `https://` works with Pi-hole's self-signed certificate only with its SHA-256 fingerprint pinned in Settings; verification is never turned off. Test connection shows the server's fingerprint when it does not match, to check against `openssl s_client -connect ph.local:443 </dev/null | openssl x509 -noout -fingerprint -sha256` and paste. If Pi-hole renews its certificate, paste the new one. The password is never logged or returned by the API (only `pihole_password_set`), nor is the session ID.
  - How: one login (`POST /api/auth`), its session reused until it expires (one of Pi-hole's 16 session seats, freed with `DELETE /api/auth` on a settings change or when turned off); every 10 minutes `/api/network/devices`, `/api/stats/top_clients` (twice: all and blocked) and `/api/queries?client_ip=` for up to 16 of the devices the board knows (the Devices table and recent attackers), in turn; on demand from the device page, at most once per 30 s. `.local` names resolve by mDNS. A failure backs off from 1 to 30 minutes, keeps the last good data with its time, and shows once in the Settings section and `/api/pihole/status`, never as an alert or on Discord. A Pi-hole v5 is detected and reported as not supported.
- MikroTik router as a second pair of eyes (`main/admin/mikrotik.c`, `main/detect/correlate.c`), read only, over the RouterOS v7 [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API). Off until a URL, user and password are set (no task, no RAM). Setup below, under "MikroTik".
  - Every 5 minutes, one request at a time: DHCP leases (`/rest/ip/dhcp-server/lease`: `mac-address`, `address`, `active-address`, `host-name`, `client-id`, `status`, `last-seen`), ARP (`/rest/ip/arp`), the bridge host table (`/rest/interface/bridge/host`: `on-interface` is the switch port) and whichever Wi-Fi registration table the router has (`/rest/interface/wifi/registration-table`, `/rest/interface/wireless/registration-table`, `/rest/caps-man/registration-table`: AP and signal). At the first poll and then hourly, `/rest/interface` (`mac-address`): the router's own MACs, for the MNDP and MAC-Telnet whitelist (`own_macs` in `GET /api/mikrotik/status`). Cached by MAC; when the router stops answering, the last good cache is served with its "as of" time and the client backs off quietly (30 s doubling to 30 min).
  - When you open a device on the Devices tab (at most once per 20 s per device): its connection tracking, `/rest/ip/firewall/connection?src-address=<ip>` (the router filters), at most 200 connections, summarised by destination IP and port with bytes up and down, packets, connection count, first and last seen (by the board's fetches: conntrack has no age), external (non-RFC 1918) ones marked, busiest first. Each destination gets a name where one is known (the Pi-hole query that resolved it for this client, when a Pi-hole client supplies answers; else the router's DNS cache, `/rest/ip/dns/cache`, read at most every 2 minutes) and, for external ones, GeoIP country and AS (the board's ip-api.com path; only for a device you open, at most 8 lookups a time, so opening a device sends its top destinations to ip-api.com). Reverse DNS is not done. The device is then watched for 15 minutes (and an incident's source while the incident is open): its connections are read again every minute, so repeated check-ins show.
  - New device: a bound DHCP lease from a MAC never seen before raises Code 60-02 "New device on network" (SEV3: logged, in Discord's event log and on the card as a `netdev` line; its Alert on switch is off by default). The known MACs live in NVS (160, the oldest dropped first); the first poll on a new board learns the current leases without events.
  - Correlation (`GET /api/device/intel`): the honeypot's own events from the device by code, the router's identity (hostname, port or AP, signal), its external connections and, when a Pi-hole client is built in, Pi-hole's lookups, with flags and a plain-English reason each: DNS bypass (DNS straight to an outside server, or outside connections with no lookups through Pi-hole), a blocked name reached anyway, beaconing (new connections to one destination at a near-regular interval with little data), unusual ports out (23, 2323, 6667, 6697, 4444, 5555, 445, 135, 139, 31337, 9001) many external hosts at once, DNS over HTTPS or TLS to a known public resolver (Google, Cloudflare, Quad9, OpenDNS, AdGuard, CleanBrowsing, Control D, Mullvad, NextDNS on 443 or 853), upload-heavy destinations (1 MB or more up and four times what came back) and direct-IP connections (external hosts with no DNS name behind them, when a name source covers the device). Each destination lists the flags it raised. Pi-hole v6's query log has no answer addresses, so without another source of them the Pi-hole flags work from DNS ports and lookup counts, not from matching each address to a name.
  - The incident carries a one-line summary of its source ("on ether4, 3 external connections, 1 flagged": `intel` in the alarm JSON), Discord's opened post adds it as "Network" (waiting up to 6 s for the router), and the Devices tab's analysis row has a Network section (port or AP, hostname, external connections, flags; hidden while the router and Pi-hole are off).
- Router integrity, the router as a sensor (`main/admin/mikrotik_watch.c`): snapshot and diff of the router's configuration over the same read-only REST user. Arm the baseline in Settings, MikroTik, "Arm router baseline" (and again after a planned change); from then on an added, removed or changed record raises a Code 55 event, once per change, which goes everywhere a trap event goes (ring, dashboard feed, panel, microSD, Discord, Telegram, the alarm). Each menu is read every 5 minutes, one request at a time, staggered; a menu the router lacks is marked missing.
  - Menus: `/system/scheduler` and `/system/script` (55-01), `/user`, `/user/group`, `/user/ssh-keys` (55-02), `/ip/socks`, `/ip/proxy` (55-03), `/ip/firewall/nat` (55-04), `/ip/service` (55-05), `/ip/firewall/filter` chain input (55-06), `/ip/dns`, `/ip/dns/static` (55-07), `/interface` tunnel types (55-08), `/system/logging`, `/system/logging/action` (55-09), `/log` login failures (3 or more in a check) and logins from a new address or service, `/user/active` (55-10, always on, no baseline), `/system/package`, `/system/resource` version, `/system/routerboard` firmware (55-11). Counters (run-count, next-run, last-started, bytes, packets, uptime) are left out of each record's hash; dynamic records (UPnP rules, l2tp-in sessions) are skipped.
  - The static checks of [routeros-scanner](https://github.com/microsoft/routeros-scanner) (MIT, `THIRD_PARTY_NOTICES`) run on every record and are named in the event and the status: a scheduler entry named u&lt;digits&gt; or fetching from the web, the default admin in group full, a user without an allowed address, dst-nat between public addresses, a service off its default port, SOCKS or the web proxy enabled, DNS answering remote requests.
  - Script source: diffed only if this user can read it; if the reply leaves it out, scripts are compared on name, owner and policy, and the status says so.
  - NVS keeps only a digest per menu and the arm time (the partition is 16 KB); the per-record baseline is in PSRAM. After a reboot each menu is compared with its armed digest, and a mismatch is reported once, without record detail, until you re-arm.
  - The router's own entry on the Devices tab (and `GET /api/device/intel` for its address) shows the integrity state.
- Router tripwires, the router's own log as a sensor (`main/detect/router_trip.c`, Rob's choice "Syslog + list check"): the router sends logins, failed logins, configuration changes, DHCP leases and three firewall tripwires to the board over UDP syslog (setup below, under "Router setup"). The rules on the router only log and add to an address list: nothing is dropped and admin access is untouched.
  - No socket: datagrams to UDP 514 on the board's address are copied off the Wi-Fi input into a PSRAM ring, and only when they come from the router's address (`ROUTER_SYSLOG_SRC`, else the MikroTik URL's host) with the gateway's MAC; those are then consumed, so the router gets no port-unreachable back. Anything else sent to that port is treated as before (a closed port).
  - Codes 55-21 to 55-27 (table below), each with the offender as the source (not the router), so the incident, the device page and the ignore list name the device. Admins (`ROUTER_ADMIN_IPS` and the admin allowlist) are logged, not alerted, except a burst of 3 failed logins in 5 minutes. The board's own read-only REST login is ignored. One event per code and source per 5 minutes (DNS bypass per hour), repeats counted into the next.
  - Every classified line is also a `router_log` line on the card (Logs page, kind "router_log"; at most 30 a minute). A DHCP assignment from a MAC the MikroTik client has never seen raises 60-02 once, whichever of syslog and the 5-minute lease poll sees it first.
  - List check: every 15 s the board reads the router's `shadowsentry-trip` address list over the read-only REST login (GET only). A new entry whose address raised no syslog tripwire in the last day raises 55-27 (syslog lost or not set up); the first read only learns.
  - While syslog is live, router integrity's 55-10 login events (from polling `/log` and `/user/active`) are not raised, so a login is not reported twice.
  - Line formats parsed (RouterOS 7.24 manual's Log page and the 7.26 page's syslog section): "login failure for user U from A via S", "user U logged in from A via S", "&lt;item&gt; changed|added|removed|moved by &lt;actor&gt;" (actor "admin", "scheduler:..." or "&lt;client&gt;/&lt;service&gt;:&lt;user&gt;@&lt;address&gt;"), "&lt;server&gt; assigned &lt;ip&gt; for &lt;MAC&gt; &lt;host&gt;", and firewall lines with the SS-TRIP- prefix. The user name and the DHCP host name are attacker text: the source is taken from the last " from &lt;IPv4&gt; via" (and RouterOS's `src=` field when present), each kind is matched only at the start of the message and, when the topics are sent (tripwires.rsc turns them on), only under its own topic.
- Panel-press camera: the OV2640 faces whoever stands at the screen. A press on the panel's ACKNOWLEDGE button (action `ack`), or a confirmed IGNORE ERROR or IGNORE DEVICE (action `ignore`), takes a photo (640x480 JPEG, Elecrow's sensor settings; 320x240 if the sensor will only start at Elecrow's own size) at the moment the press starts, not when the hold completes, so a press let go early is photographed too. To light the face, the screen first turns white above the button row (the emblem and the details; the buttons stay visible and a hold on ACKNOWLEDGE carries on in sight) and the backlight full on (`CAM_FLASH_ENABLE`, default 1); the camera drops frames for `CAM_FLASH_SETTLE_MS` (500) while its exposure settles on that light, captures, and the white comes down, in under a second. It is saved as `/sd/snap/YYYY-MM-DD_HH-MM-SS_<action>.jpg` (through the SD writer task) with a `snap` line in the day log (shown on the Logs page, kind "snap"), and the last one is kept in PSRAM for the dashboard's "Last panel action" card (thumbnail, action, time; refreshed on every alarm state change and every 30 s). At most one photo a second. Without a camera the board logs it once and runs as before. The camera's SCCB runs on the new `i2c_master` driver and attaches to the bus touch already owns (touch polling pauses for the second or so the sensor takes to start, and both run at 100 kHz), so the legacy I2C driver (which would abort IDF 5.4 at boot) is never linked.
- Telegram (upstream's per-event alerts): each message now starts with the event's code and headline in bold.
- OTA updates: two 6 MB app slots and `POST /api/ota` on the admin panel (same Basic auth). A new image has to reach Wi-Fi to confirm itself, otherwise the bootloader rolls back.
- Crash capture (`main/storage/crash.c`), for a board with no serial console:
  - At a panic (a fault, `abort()`, an assert, a stack overflow, the interrupt watchdog, or the task watchdog when it is set to panic) a wrapper around IDF's `esp_panic_handler()` (`-Wl,--wrap`) copies the cause and its text, the faulting PC and exception registers, up to 16 backtrace PCs, the task on each core, the uptime and wall clock, free heap (internal and total) and the internal minimum, the firmware version and the ELF SHA256 prefix into a record in RTC memory with a magic and a CRC-32, then hands over to IDF's handler as before. Nothing in that path allocates, locks or touches flash.
  - On the next boot, after a panic or watchdog reset, the record becomes a report: a one-line JSON summary in `/spiffs/crash.log` (the last 20, at most 8 KB), the full text in `/spiffs/crash_last.txt`, and once the card and the clock are ready (SNTP waited for up to 60 s) `/sd/crash/YYYY-MM-DD_HH-MM-SS.txt` (`up<seconds>s_<n>.txt` without a clock) plus a `crash` line in the day log. A watchdog reset with no record (a hardware watchdog, or a hung handler) is logged with its reset reason only.
  - `GET /api/crashes`, `last_crash` in `/api/status`, a Crashes card on the Settings page, and the boot "online" message adds "Crash: <cause> in task <task> at PC 0x...".
  - Decode on a PC: `python tools/decode_crash.py <report, summary line or saved /api/crashes> <firmware.elf>` runs addr2line over the PCs and prints function:file:line for each. Given a folder instead of an ELF it picks the ELF whose SHA256 matches the record. `python tools/archive_elf.py` copies `.pio/build/crowpanel35_ota/firmware.elf` to `builds/<git short hash>/` beside the repository after a build, so every image that went to the board can be decoded later.
- Wi-Fi (`main/wifi_manager.c`, `main/wifi_roam.c`): the station joins the strongest AP for the SSID (all-channel scan, sorted by signal) and accepts 802.11k/v steering from the AP (`CONFIG_ESP_WIFI_11KV_SUPPORT`, RRM and BTM on). If the signal stays below -75 dBm for 60 s it scans, and moves to a BSSID of the same SSID at least 8 dB stronger, at most once every 5 minutes (`WIFI_ROAM_*` in `config.h`). Each BSSID change is logged and written to the card as a `wifi` line; `/api/status` has `wifi` (SSID, BSSID, channel, RSSI, roam count). The Wi-Fi threat monitor does not count a roam's own disconnect, or a failed reconnect within 20 s of it, as a deauth.
- Memory: the large buffers, Wi-Fi/lwIP and mbedTLS allocate from PSRAM, keeping internal RAM free for the display.

### Alert codes

Every event carries a two-part console code, "Code CC-NN": the category, then the item (`main/alarm/describe.c`, `GET /api/codes`). HTTP codes come from the request label, tripwire codes from the service. The tier decides what an event can open: SEV1 a RED incident, SEV2 a YELLOW one at most, SEV3 nothing unless its Alert on switch is on (then YELLOW). The Alert on switches and the ignore list apply first.

| Code | Name | Tier | Event |
|---|---|---|---|
| 17-01 | ARP sweep | SEV2 | one MAC asking who-has for many hosts |
| 17-02 | Port scan | SEV1 | many ports from one source |
| 17-03 | Probe | SEV2 | a SYN to a trap port with no login or request |
| 17-04 | Scan ended | SEV2 | the summary after a port scan or ARP sweep goes quiet |
| 20-01 | SSH login | SEV1 | SSH credentials |
| 20-02 | Telnet login | SEV1 | Telnet credentials |
| 20-03 | FTP login | SEV1 | FTP credentials |
| 20-04 | RTSP auth | SEV1 | camera (RTSP) credentials |
| 20-05 | Shell command | SEV1 | a command in the fake shell |
| 20-06 | Shell session | SEV1 | a fake shell session opened |
| 30-01 | Web login | SEV1 | HTTP `login_post` (and upstream's single-port trap's POST) |
| 30-02 | Web dotfile | SEV2 | HTTP `dotfile_path` |
| 30-03 | Web traversal | SEV2 | HTTP `dotdot_path` |
| 30-04 | Web odd method | SEV2 | HTTP `odd_method` |
| 30-05 | Web oversize | SEV2 | HTTP `oversize` |
| 30-06 | Web non-HTTP | SEV2 | HTTP `non_http` |
| 30-07 | Web scanner | SEV2 | HTTP `scanner_ua` |
| 30-08 | Web script | SEV2 | HTTP `library_ua` |
| 30-09 | Web request | SEV2 | HTTP `unclassified` (and upstream's trap's other requests) |
| 40-01 | ADB | SEV1 | the ADB trap on 5555 |
| 40-02 | RDP tripwire | SEV1 | 3389 |
| 40-03 | VNC tripwire | SEV1 | 5900 |
| 40-04 | SMB tripwire | SEV1 | 445 |
| 40-05 | Redis tripwire | SEV1 | 6379 |
| 40-06 | MySQL tripwire | SEV1 | 3306 |
| 40-07 | MSSQL tripwire | SEV1 | 1433 |
| 40-08 | JetDirect tripwire | SEV1 | 9100 |
| 40-09 | Tripwire | SEV1 | a tripwire service added later without its own code |
| 40-10 | Winbox | SEV1 | MikroTik Winbox decoy, 8291 |
| 40-11 | RouterOS API | SEV1 | MikroTik API decoy, 8728 (command and user name only) |
| 40-12 | Bandwidth test | SEV1 | MikroTik bandwidth-test decoy, 2000 |
| 40-13 | MNDP discovery | SEV2 | an MNDP solicitation or announcement on UDP 5678 from a sender not whitelisted (gateway, router interfaces, `TRIPWIRE_MT_WHITELIST`) |
| 40-14 | MAC-Telnet | SEV1 | a MAC-Telnet packet for the board's MAC on UDP 20561 |
| 50-01 | ARP spoof | SEV1 | the gateway's MAC changed, or one MAC claims two addresses |
| 50-02 | Wi-Fi deauth | SEV1 | forced disconnects or a broadcast deauth flood |
| 55-01 | Router scheduler | SEV1 | a scheduler entry or script added, removed or changed |
| 55-02 | Router users | SEV1 | a user, group or SSH key added, removed or changed |
| 55-03 | Router proxy | SEV1 | SOCKS or the web proxy settings changed |
| 55-04 | Router NAT | SEV1 | a NAT rule added, removed or changed |
| 55-05 | Router service | SEV1 | a service's port, allowed addresses or state changed |
| 55-06 | Router firewall | SEV1 | an input-chain filter rule added, removed or changed |
| 55-07 | Router DNS | SEV1 | the DNS servers, remote requests or a static entry changed |
| 55-08 | Router tunnel | SEV1 | a tunnel interface added, removed or changed |
| 55-09 | Router logging | SEV1 | a logging rule or action changed (someone may be blinding the sensor) |
| 55-10 | Router login | SEV2 | a burst of login failures, or a login from a new address or service |
| 55-11 | Router version | SEV2 | packages, the RouterOS version or the RouterBOOT firmware changed |
| 55-21 | Router login failed | SEV1 | the router logged a failed login from an address that is not an admin, or 3 in 5 minutes from an admin |
| 55-22 | Router login | SEV1 | the router logged a login from an address that is not an admin |
| 55-23 | Router config change | SEV1 | the router logged a change by a non-admin address, a scheduler or a script |
| 55-24 | Router port scan | SEV1 | the router's port scan detector (psd) fired on a LAN source (SS-TRIP-PSD) |
| 55-25 | Router management | SEV2 | a non-admin host opened a connection to the router's management ports (SS-TRIP-MGMT) |
| 55-26 | DNS bypass | SEV2 | a device sent DNS or DNS over TLS to a server that is not the Pi-hole (SS-TRIP-DNS) |
| 55-27 | Router tripwire list | SEV2 | a new entry on the router's shadowsentry-trip list that no syslog line explained |
| 60-01 | LAN discovery | SEV3 | a new device, protocol or label |
| 60-02 | New device on network | SEV3 | a DHCP lease on the router from a MAC never seen before |

"00-00" marks an event no code covers (an attack type added later); it counts as SEV2.

This table is sorted by code. `GET /api/codes` lists the same 55 codes in the order of `describe.c`'s table, where new codes are appended so the existing ones keep their position.

### Fork API (admin port, Basic auth)

Every `POST` needs an `X-ShadowSentry: 1` header (any value), including upstream's `/api/clear` and `/api/ack` (now an alias of `/api/alarm/ack`). A page on another site can't add a custom header without a CORS preflight, which the device never grants, so a browser that holds the login can't be driven into cross-site POSTs. Example: `curl -u admin -X POST -H 'X-ShadowSentry: 1' http://<ip>:9999/api/ack`.

| Method | Path | |
|---|---|---|
| `GET` | `/api/status` | upstream's uptime, heap and RSSI, plus `reset_reason` (e.g. "software restart (OTA update)"), `internal_free`, `internal_min` and `internal_after_boot` (internal heap once every task is up), and `alarm`: `state` (0 idle, 1 active, 2 acked), `cond` (`green`, `yellow`, `red`), `code`, `headline`, `id`, `ip` (u32), `mac`, `vendor`, `type`, `count`, `first`, `last`, `acked_by` and `resolved_by` (`""`, `panel`, `dashboard`). The WebSocket pushes the same object as `{"alarm":{...}}` on every change. `last_crash` (`ts`, `cause`, `pc`, `task`) once a crash has been recorded, and `wifi` (`ssid`, `bssid`, `channel`, `rssi`, `roams`) |
| `GET` | `/api/crashes` | `{"crashes":[...],"count","latest_this_boot","latest"}`: the summaries in `/spiffs/crash.log`, oldest first (`ts` of the crash, 0 if the clock was not set, `boot_ts`, `record`, `reset`, `cause`, `detail`, `exc`, `task`, `task0`, `task1`, `fw`, `elf`, `core`, `up_s`, `pc`, `excvaddr`, `bt`, `bt_corrupt`, `bt_more`, `nested`, `heap_int`, `heap_total`, `heap_int_min`), and the newest full report as text |
| `GET` | `/api/tasks` | per-task CPU share over one second (`cpu_pct`, of both cores together) and since boot, priority, core and stack high-water; holds the admin task about 1 s |
| `GET` | `/api/codes` | the alert code table: `{"codes":[{"code","name","tier"}]}` |
| `GET` | `/api/settings` | settings; secrets only as `*_set` flags; also `alert_mask` (bit per type), `scan_ports`, `scan_window_s`, `arp_targets`, `arp_window_s`, `admin_allow` (array) and `client_ip` |
| `POST` | `/api/settings` | JSON body, fields present are applied; blank secrets are left alone (`"discord_webhook_clear":true` clears the webhook, `"whatsapp_apikey_clear":true` the WhatsApp apikey, `"pihole_password_clear":true` the Pi-hole password; Pi-hole also takes `pihole_url`, `pihole_password`, `pihole_tls_sha256`, `pihole_enabled`); `{"ok":true,"reboot":bool}` or 400 `{"error":...}` |
| `POST` | `/api/reboot` | 204, restart after 500 ms |
| `GET` | `/api/ignore` | `{"max":32,"entries":[{"index","ip","mac","vendor","code","code_name","note","ts"}]}`; `code` "" means the whole device |
| `POST` | `/api/ignore` | `{"action":"add","ip":"..","mac":"..","code":"17-01","note":".."}` (one of ip, mac; `code` optional, "" or absent for the whole device, else a code from `/api/codes`) or `{"action":"remove","index":N,"ip":"..","mac":".."}` (ip and mac, and code if given, as listed; 409 if the list changed); answers with the list |
| `POST` | `/api/buzzer/test` | the red alert klaxon, even with the sound off; 204 at once, the klaxon plays after |
| `GET` | `/api/summary` | card status and summary metrics |
| `GET` | `/api/logs` | day files, newest first |
| `GET` | `/api/logs/file?f=NAME[&tail=1][&dl=1]` | one day file as NDJSON; `tail=1` sends the last 256 KB |
| `POST` | `/api/discord/test` | queue a test embed; `{"queued":true,"test":N}`, 409 with no webhook |
| `GET` | `/api/discord/status` | `test_done`, `test_ok`, `test_status` (HTTP status, -1 no connection), post and drop counters |
| `POST` | `/api/whatsapp/test` | queue a test message; `{"queued":true,"test":N}`, 409 without a phone number and apikey |
| `GET` | `/api/whatsapp/status` | `test_done`, `test_ok`, `test_status` (HTTP status, -1 no connection), `sent`, `failed`, `dropped` |
| `POST` | `/api/alarm/ack` | acknowledge: RED to YELLOW; 200 `{"alarm":{...}}` once applied, 409 unless RED. `/api/ack` is the same |
| `POST` | `/api/alarm/resolve` | resolve: RED or YELLOW to GREEN; 200 `{"alarm":{...}}` once applied, 409 when GREEN; logs untouched. `/api/alarm/clear` is the same |
| `POST` | `/api/alarm/ignore` | `{"scope":"error"}` ignores the incident's code from its source, `{"scope":"device"}` the whole source; then resolves the incident whatever else it saw; 200 `{"alarm":{...}}`, 409 when GREEN or the list is full |
| `GET` | `/device?mac=..&ip=..` | the device page (`main/device.html`) |
| `GET` | `/analysis.js` | the device analysis rules (`main/analysis.js`), loaded by the dashboard and the device page |
| `GET` | `/api/logs/device?mac=..&ip=..[&limit=M][&cursor=C]` | one device's microSD log lines (mac or ip, or both; mac in any case), newest first, at most M a request (default 200, at most 1000), as NDJSON after a first `{"kind":"meta","matched","files","from","limit","cursor","more","timed_out","scanned_bytes","ms","long_skipped"}` line. Day files are read backwards from the end, newest file first; each answer stops at the limit or after 3 s and gives a `cursor` ("YYYY-MM-DD.jsonl:offset", validated against the file's size) that resumes exactly there, across day files; "" once the oldest file has been read to its start |
| `GET` | `/api/devices` | the LAN discovery table: `listeners` (name, port, open, packets, error), `mdns_queries`, `mdns_dropped`, `devices` newest first (`mac`, `random_mac`, `vendor`, `ip`, `label`, `label_src`, `host`, `protos` {name: packets}, `total`, `first_ts`, `last_ts`, `first_ago_s`, `last_ago_s`, `queries` newest first), `count`, `truncated` |
| `GET` | `/api/pihole/status` | `{"enabled":false}` when Pi-hole is off; else `state` (`starting`, `ok`, `error`, `v5`), `error`, `version`, `host`, `ip` (resolved), `session`, `last_ok_ts`, `last_ok_ago_s`, `next_in_s`, `backoff_s`, `devices`, `with_top`, counters, `tls_seen` (https: the server's certificate SHA-256) and the test result (`test_done`, `test_ok`, `test_status`, `test_msg`) |
| `POST` | `/api/pihole/test` | queue a connection test (login and `/api/info/version`), works before Pi-hole is switched on; `{"queued":true,"test":N}`, 409 without a URL and password |
| `POST` | `/api/pihole/refresh[?ip=a.b.c.d]` | sync now, that device's top domains first; 202, 429 `{"retry_after_s"}` within 30 s of the last, 409 when off |
| `GET` | `/api/pihole/device?mac=..&ip=..` | one device: `{"enabled":true,"found":bool,"pihole":{names, ips, mac, vendor, first, last, all_queries, queries, blocked, top_domains [{d,n}], top_of, top_ts, as_of}}`; `{"enabled":false}` when off |
| `GET` | `/api/oui` | vendor database status: `present`, `count`, `build_ts`, `size`, cache counters, `card` |
| `POST` | `/api/oui` | raw `oui.bin` from `tools/make_oui.py`, at most 4 MB; `{"ok":true,"count","build_ts","size"}`, 400 bad header, 413 too big, 503 no card or memory |
| `GET` | `/api/snap/last` | last panel-press photo, `image/jpeg`; 404 if none since boot |
| `GET` | `/api/snap/last.json` | `{camera, seq, ts, action, file, size, width, height}`; `seq` 0 if none |
| `GET` | `/api/device/intel?mac=..&ip=..` | one device (mac, ip or both): `summary`, `honeypot` (`events`, `last`, `codes` [{`code`,`name`,`count`}]), `mikrotik` (`state`, `as_of`, `identity` {`hostname`,`client_id`,`lease_status`,`last_seen`,`port`,`bridge`,`arp_interface`,`ap`,`ssid`,`signal`,`wifi`,`lease`,`new_device`,`first_seen`} or null, `conn` {`state`,`pending`,`as_of`,`total`,`external`,`external_hosts`,`truncated`,`dst` [{`ip`,`port`,`proto`,`proto_num`,`external`,`conns`,`bytes_out` (up),`bytes_in` (down),`pkts_out`,`pkts_in`,`tcp_state`,`name`,`name_src` (`pihole`, `router_dns` or ""),`first_seen`,`last_seen`,`cc`,`asn`,`org`,`flags` [keys],`beacon` {`every_s`,`times`}}] busiest first}), `pihole` (`state` "off" or "ok" with `total`, `blocked`, `queries`), `flags` [{`key`,`reason`}]. Asks the router for the connections (once per 20 s per device); `conn.pending` true means ask again in a few seconds |
| `GET` | `/api/mikrotik/status` | `enabled`, `running`, `state` (`off`, `starting`, `ok`, `unreachable`, `auth_failed`, `cert_mismatch`, `http_error`), `detail`, `last_ok`, `next_s`, `backoff_s`, counts, `cert` {`pin_set`,`tofu`,`seen`}, the last test |
| `POST` | `/api/mikrotik/test` | queue a test (`/rest/system/resource`: board and RouterOS version); `{"queued":true,"test":N}`, 409 when off; poll the status for `test_done` |
| `POST` | `/api/mikrotik/cert/forget` | forget the certificate recorded on first use |
| `GET` | `/api/mikrotik/integrity` | `running`, `armed`, `arming`, `armed_at`, `last_check`, `checks` [{`key`,`title`,`code`,`state` (`pending`, `ok`, `changed`, `drift`, `missing`, `error`, `not_armed`),`records`,`armed_records`,`changes`,`last`,`note`,`findings`}] |
| `GET` | `/api/router/status` | the router's feeds to this board: `syslog` {`enabled`,`port`,`router`,`gateway_mac_known`,`live`,`last`,`received`,`foreign` (to the port, not from the router),`dropped`,`cut`,`parsed`,`events`,`held`,`sd_lines`,`sd_dropped`,`lines` {per kind},`list` {`name`,`learned`,`checks`,`errors`,`status`,`entries`,`events`,`last`}} |
| `POST` | `/api/mikrotik/integrity/arm` | arm or re-arm the baseline from the router's current state (one pass, about 30 s); 409 when off |
| `POST` | `/api/ota` | raw app image |

### MikroTik

Read only, from a user that can only read and only from the board's address. RouterOS 7.24 commands (Rob's router: CCR1036-8G-2S+, RouterOS 7.24.5):

```
/user group add name=shadowsentry policy=read,api,rest-api,!write,!policy,!sensitive,!password,!reboot,!sniff,!test,!ftp,!ssh,!telnet,!winbox,!web,!local,!romon
/user add name=shadowsentry group=shadowsentry address=192.168.0.118/32 password=...
```

- The group: `read` to print, `api` and `rest-api` because the REST server logs in to the API with the user's credentials, so it needs both ([REST API, 7.25](https://manual.mikrotik.com/docs/7.25/developer-guides/rest-api/)). A `!` revokes a policy and any policy not listed is revoked anyway, so the `!` list is belt and braces. Without `sensitive`, secrets stay hidden from this user.
- `address=` limits the login to the board. REST honours it from RouterOS 7.12; before that a REST login worked from any address (CVE-2023-41570).
- By version: REST exists since 7.1beta4 over `www-ssl` only, and over plain `www` since 7.9. 7.26beta4 fixes REST logins for users with `rest-api` but without `api`, so from 7.26 `api` may no longer be needed; on 7.24 keep both. I could not find the release that added the `rest-api` policy itself.
- Plain HTTP (`www`, `MIKROTIK_URL "http://192.168.0.1:8080"` on Rob's router): Basic auth sends the user and password in the clear on the LAN, readable by anything that can sniff it. Fine with this read-only, address-restricted user on a trusted LAN; otherwise use `www-ssl`. Also consider `/ip/service/set www available-from=192.168.0.118/32,<your admin PC>`.
- HTTPS (`www-ssl`) with a self-signed certificate:

```
/certificate/add name=shadowsentry-https common-name=192.168.0.1 subject-alt-name=IP:192.168.0.1 days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
/certificate/sign shadowsentry-https
/ip/service/set www-ssl certificate=shadowsentry-https disabled=no tls-version=only-1.2
```

- Then `MIKROTIK_URL "https://192.168.0.1"`. The board checks the certificate by its SHA-256 fingerprint: `MIKROTIK_CERT_SHA256` (or the pin field in Settings) if set, else the first certificate it sees is recorded in NVS and shown in Settings ("trust on first use"; that first connection already carries the password). A different certificate is refused (state `cert_mismatch`, with the new fingerprint shown) until you pin it or press "Forget recorded certificate". Verification is never switched off. mbedTLS also checks the key usage, so a certificate without `digital-signature` and `tls-server` fails the handshake (shown as `unreachable`). To read the fingerprint yourself: `openssl s_client -connect 192.168.0.1:443 </dev/null | openssl x509 -noout -fingerprint -sha256`.
- `main/config.h`: `MIKROTIK_URL` (`http://host[:port]` or `https://host[:port]`, no path), `MIKROTIK_USER`, `MIKROTIK_PASSWORD` (empty user or password means off), `MIKROTIK_CERT_SHA256` (64 hex digits, colons allowed, https only). Settings, MikroTik, holds the same plus a "Use the router" switch and Test connection; it applies at once, no reboot. The password is never logged or returned by the API.
- Nothing is written to the router: the client only sends GET.

### Router setup

The router sends to the board; the board never writes to the router (its REST user stays read-only). The RouterOS side is in `tools/routeros/`, written against the RouterOS 7.24 CLI reference (pages cited in each file) and not yet run on a router: read it before pasting.

- `tools/routeros/tripwires.rsc`: the syslog action and logging rules, the `shadowsentry-admin` and `shadowsentry-dns` address lists, and a mangle chain `shadowsentry-trip` with three tripwires (psd, management ports from a non-admin host, DNS to anything but the Pi-hole), each `add-src-to-address-list` with `log=yes` and a `SS-TRIP-` prefix. Edit the lines marked EDIT: your admin PC, the sentry's and the Pi-hole's addresses, the router's LAN address (`src-address=` on the logging action), the LAN interface list, the management ports. The file ends with the commands that remove it again.
- On the board, `main/config.h`: `ROUTER_ADMIN_IPS` (your admin PC, the same as in `shadowsentry-admin`), and `ROUTER_SYSLOG_SRC` if the MikroTik URL is not a dotted quad. Defaults in `main/detect/router_trip.h`.
- Check: `GET /api/router/status` shows `syslog.live` true and `received` counting once the router sends; `foreign` counts datagrams to the port from anything else (a wrong `src-address=` on the router shows here).
- The psd values (21,3s,3,1) are a common choice from MikroTik's forum, not from the manual; raise the first number if a busy LAN host trips it.

### Build and flash (PlatformIO)

```bash
cp main/config.h.example main/config.h   # Wi-Fi, admin password, DISPLAY_TZ, alarm timings
pio run -e crowpanel35                   # build
```

First flash over USB: hold BOOT, tap RESET, then `pio run -e crowpanel35 -t upload`. The board restarts into the new firmware on its own.

After that, update over Wi-Fi with no buttons. Set `upload_port` in the `crowpanel35_ota` env of [`platformio.ini`](platformio.ini) to the board's IP (shown in the panel's status bar), then:

```bash
pio run -e crowpanel35_ota -t upload
```

[`tools/ota_upload.py`](tools/ota_upload.py) takes the admin password from `tools/ota_password` (one line) when that file exists, otherwise from `main/config.h`. Both are git-ignored, so the password never appears on a command line or in a committed file. Once the password has been changed on the Settings page, put the new one in `tools/ota_password`.

### Pulling upstream updates

`upstream` points at the original project. To bring in its changes:

```bash
git remote add upstream https://github.com/Rdx1S/ShadowSentryS3.git   # once, on a fresh clone
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

The rest of this README is the upstream documentation. Where it says `idf.py`, this fork uses the PlatformIO commands above.

---

## Features

**Honeypot traps (Core 0)**
- **5 protocol traps** — RTSP (554, fake Hikvision camera), HTTP (80, fake NVR login + per-request fingerprinting), Telnet (23), SSH (22), FTP (21). Every credential pair is captured.
- **Real SSH server (wolfSSH)** — genuine SSH-2.0 handshake (curve25519 + ECDSA host key) that decrypts the auth exchange and **captures the plaintext username + password** — not just a banner fingerprint.
- **Interactive fake shell (Cowrie-style)** — Telnet *and* SSH accept the login and drop the attacker into a believable Ubuntu 20.04 shell that answers recon commands while **logging every command**; download/exec commands (`wget`/`curl`/`chmod +x`/`./…`) are flagged as IOCs and escalated.

**Network & radio monitors (Core 1)**
- **ARP-spoof / MITM monitor** — watches the lwIP ARP cache for cache-poisoning signatures (gateway MAC change, one MAC claiming many IPs).
- **Wi-Fi threat monitor** — detects 802.11 deauth/disassoc attacks (incl. the single-frame deauth used for handshake capture) via reason-code-classified forced disconnects + promiscuous broadcast-flood sniffing.
- **MAC + vendor** for every event — resolves the attacker's L2 MAC from the ARP table with a best-effort OUI vendor guess; randomized (private) MACs flagged.
- **Threat-intel / GeoIP enrichment** — resolves each attacker IP to country, ISP/ASN and a reputation tag (`hosting`/`proxy`/`mobile`) via ip-api.com; private IPs labelled `Private LAN` with no external call.

**Platform**
- **Live web dashboard + REST API** on port 9999 (HTTP Basic Auth) — stat cards, attack feed, clickable attack-detail modal. A dedicated **WebSocket push server** (port 9998) streams every new attack to the dashboard in real time, so the feed updates the instant a probe lands instead of waiting for the next poll.
- **Telegram alerts** — async queue with resilient delivery (waits for reconnect + retries, so an alert survives the very deauth that knocks the board offline).
- **SPIFFS persistence** — attack log ring buffer + all-time counter survive reboots.
- **Dual-core design** — honeypot traps on Core 0, admin/alerting/monitors on Core 1.
- **Zero-config & serverless** — flash, set Wi-Fi + Telegram token, done. mDNS `.local` name, no cloud, no database.

---

## How it works

Thanks to the dual-core Xtensa LX7 processor, the project is split into two isolated worlds:

| Core | Role | Tasks |
|------|------|-------|
| **Core 0** — Hacker World | Receives attacks | RTSP :554 · HTTP :80 · Telnet :23 · SSH :22 · FTP :21 |
| **Core 1** — Admin World  | Management & alerts | Admin Panel :9999 · Telegram · SPIFFS |

```
Attacker / bot
     │
     ├─ Port 554  (RTSP)   → Fake Hikvision DS-2CD camera  ─┐
     ├─ Port  80  (HTTP)   → Fake Hikvision NVR login page  │
     ├─ Port  23  (Telnet) → Fake Ubuntu 20.04 server       ├──► log_store → SPIFFS
     ├─ Port  22  (SSH)    → Fake OpenSSH 8.9p1             │         │
     └─ Port  21  (FTP)    → Fake vsFTPd 3.0.5             ─┘         ▼
                                                                Telegram Alert
                                                                       │
                                                              Admin Panel :9999
                                                             (Dark-mode Dashboard)
```

### What gets captured

| Protocol | Captured | Example |
|----------|----------|---------|
| RTSP | Username + Password | `admin:12345` from the Basic Auth header |
| HTTP | Username + Password + **path + User-Agent** | NVR login POST form; every request (GET/POST/other) is fingerprinted by path and the scanner's User-Agent |
| Telnet | Username + Password **+ post-login commands** | Login prompt, then a fake interactive shell that logs every command |
| SSH | Username + Password **+ post-login commands** | Real SSH-2.0 server (wolfSSH) — `root:hunter2`, then the interactive shell |
| FTP | Username + Password | `USER admin` / `PASS password` (RFC 959) |

> **Real SSH server (wolfSSH).** Port 22 is a genuine SSH-2.0 server, not a banner: wolfSSH performs the full key exchange (curve25519) and presents an ECDSA host key, so the device terminates the crypto and **captures the plaintext username and password** the attacker submits — something a banner-only trap can't do. The login is then accepted (any password; it's a decoy) and the attacker lands in the same interactive fake shell as Telnet, with every command logged. One caveat: wolfSSH advertises its own version string, so a fingerprinting client can tell it isn't OpenSSH — the value here is credential + command capture, not banner mimicry.

> **Interactive fake shell (Cowrie-style).** Instead of endlessly replying "Login incorrect", the Telnet and SSH honeypots *accept* the login and drop the attacker into a believable Ubuntu 20.04 shell that answers common recon commands (`ls`, `cat /etc/passwd`, `uname -a`, `ps`, `ifconfig`, `wget`, …) while **logging every command they type** as a `Shell` event. Capturing the post-login command set reveals attacker TTPs and IOCs — which payloads they fetch, which binaries they try to run — that a credential-only honeypot never sees. Download/exec commands (`wget`/`curl`/`tftp`/`chmod +x`/`./…`) are flagged and escalated to a Telegram alert. Nothing is ever executed: responses are canned, the filesystem is fictional, and downloads are faked. Tunable via `TELNET_SHELL_ENABLE` / `TELNET_LOGIN_GRANT_ATTEMPT` in `config.h`.

> **MAC address for every protocol.** Since the attacker is on the same local network, for each event ShadowSentry resolves their MAC via the lwIP ARP table and shows it together with a best-effort vendor guess (OUI). A randomized MAC (private, typical for smartphones) is flagged separately. The MAC is shown both in the dashboard and in the Telegram alert.

> **Threat-intel enrichment.** A background worker resolves each attacker IP to its country, ISP/ASN and a reputation tag (`hosting` / `proxy` / `mobile`) via [ip-api.com](https://ip-api.com) — free and key-less, so it works the moment you flash it. The result (with a country flag) shows in the dashboard and the Telegram alert; private/LAN source IPs are labelled `Private LAN` without any external call. Lookups run off the hot path and are cached by IP. Tunable via `GEOIP_ENABLE` / `GEOIP_CACHE_SIZE` in `config.h`.

> **Wi-Fi threat monitor (radio layer).** The ESP32 isn't just a TCP stack — it's a Wi-Fi radio, so it can catch **802.11 deauthentication / disassociation attacks** that no software honeypot on a normal network stack can see — including the single-frame deauth used to force a reconnect and capture a WPA2 handshake. Two signals: (1) *forced disconnects* — a deauth knocks the device off-air, so it always observes its own drop, and each drop is classified by its 802.11 reason code (a deauth-induced drop carries a low code 1–9; a benign RF loss reports 200+ and is ignored), so even **one** deauth-attributable disconnect fires an alert with no false positives from a flaky link; (2) *broadcast deauth floods* sniffed in promiscuous mode, carrying the attacker's transmitter MAC and target BSSID. Either raises a `WiFi` event. Runs on the channel the device is associated to — no channel hopping. (Rogue/evil-twin AP detection would need channel hopping and is out of scope for now.) Tunable via `WIFI_MON_ENABLE` / `WIFI_MON_DEAUTH_DISC_THRESHOLD` in `config.h`.

> **ARP-spoof / MITM monitor.** A background task periodically scans the lwIP ARP cache for cache-poisoning signatures — the gateway's MAC changing after a stable baseline is learned, or one MAC claiming several IPs — and raises an `ARP` event (dashboard feed + Telegram) when it sees one. This catches L2 man-in-the-middle attacks that the port honeypots are blind to, since they never complete a TCP handshake. Scope: it detects spoofing that targets this host or is broadcast network-wide (the default for bettercap/ettercap); a strictly point-to-point spoof between two other hosts is out of scope. Tunable via `ARP_MONITOR_ENABLE` / `ARP_SCAN_INTERVAL_S` / `ARP_ALERT_COOLDOWN_S` in `config.h`.

**Detection in action.** Verified on real ESP32-S3 hardware against a live `bettercap` ARP spoof — the instant the attacker poisoned the board's gateway entry, the monitor logged it and pushed a Telegram alert (values below are anonymized):

```
ARP-MON: Gateway 192.168.1.1 MAC changed
         aa:bb:cc:dd:ee:01  ->  de:ad:be:ef:13:37   (MITM redirect)
```

---

## Requirements

### Hardware

- **ESP32-S3** DevKit (any board with ≥ 4 MB Flash)
- USB cable for flashing
- 2.4 GHz Wi-Fi network

### Software

| Component | Version |
|-----------|---------|
| [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/) | **v5.2+** |
| Python | 3.8+ |
| CMake | 3.16+ |

---

## Installing ESP-IDF

### macOS / Linux

```bash
git clone --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf
cd ~/esp/esp-idf
git checkout v5.2.1
./install.sh esp32s3
. ./export.sh
```

### Windows

Download and run the [ESP-IDF Windows Installer](https://dl.espressif.com/dl/esp-idf/).

> After installation, open the **ESP-IDF Command Prompt** for all commands below.

---

## Configuration

```bash
# Copy the configuration template
cp main/config.h.example main/config.h

# Edit it for your setup
nano main/config.h
```

All parameters live in a **single file** — `main/config.h`:

```c
// Network identity (what shows up in the router's device list)
#define DEVICE_HOSTNAME     "Hikvision-NVR"

// Wi-Fi
#define WIFI_SSID           "YourWiFiSSID"
#define WIFI_PASSWORD       "YourWiFiPassword"

// Telegram (get it from @BotFather)
#define TELEGRAM_BOT_TOKEN  "YOUR_BOT_TOKEN"
#define TELEGRAM_CHAT_ID    "YOUR_CHAT_ID"

// Admin panel  →  http://<ip>:9999
#define ADMIN_PASSWORD      "changeme1"
#define ADMIN_PORT          9999

// Honeypot ports
#define RTSP_PORT           554
#define HTTP_PORT           80
#define TELNET_PORT         23
#define SSH_PORT            22
#define FTP_PORT            21
```

> `main/config.h` is added to `.gitignore` — real credentials never reach the repository.

### Getting a Telegram Bot Token

1. Send `/newbot` to [@BotFather](https://t.me/BotFather)
2. Copy the returned token into `TELEGRAM_BOT_TOKEN`
3. Send any message to your bot, then open:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Find `"chat":{"id":...}` — that is your `TELEGRAM_CHAT_ID`

---

## Build & flash

```bash
# 1. Clone the repository
git clone https://github.com/Rdx1S/ShadowSentryS3.git
cd ShadowSentryS3

# 2. Activate ESP-IDF
. ~/esp/esp-idf/export.sh

# 3. Copy and fill in the config
cp main/config.h.example main/config.h
nano main/config.h

# 4. Build and flash (replace /dev/ttyUSB0 with your port)
idf.py -p /dev/ttyUSB0 flash monitor
```

### Finding the port

| OS | Command |
|----|---------|
| Linux | `ls /dev/ttyUSB*` or `ls /dev/ttyACM*` |
| macOS | `ls /dev/cu.usb*` |
| Windows | Device Manager → Ports (COM & LPT) |

---

## First boot

After flashing, the monitor shows:

```
I (426) MAIN: ╔══════════════════════════════════════╗
I (428) MAIN: ║    ShadowSentry S3  v1.0             ║
I (434) MAIN: ║    Edge Deception HoneyPot           ║
I (439) MAIN: ║    ESP32-S3  |  ESP-IDF v5.x         ║
I (444) MAIN: ╚══════════════════════════════════════╝
I (1827) WIFI: IP acquired: 192.168.1.105
I (1830) WIFI: Admin panel → http://192.168.1.105:9999
I (1842) WIFI: mDNS started → http://hikvision-nvr.local:9999
I (1904) RTSP: Honeypot listening on port 554
I (1910) HTTP: Honeypot listening on port 80
I (1916) TELNET: Honeypot listening on port 23
I (1924) SSH: Honeypot listening on port 22
I (1930) FTP: Honeypot listening on port 21
I (1938) ADMIN: Admin panel on port 9999
```

Open a browser → `http://192.168.1.105:9999`  
Login: `admin` / the password from `ADMIN_PASSWORD`.

> **No need to memorize the IP.** Thanks to mDNS the device is always reachable at a stable name — `http://hikvision-nvr.local:9999` — regardless of the address DHCP assigns. Works out of the box on macOS, Linux (avahi), Windows 10+, iOS and Android. The name is configurable via `MDNS_HOSTNAME` in `config.h`.

---

## Admin Dashboard

A dark-mode web interface with a real-time WebSocket feed (new attacks appear instantly), backed by a 10-second poll for reconciliation and threat-intel updates. Every stat card and distribution row is **clickable to filter** the feed/table by attack type:

- **6 stat cards** — Total, Unique IPs, RTSP, HTTP, Telnet, SSH, FTP
- **Donut chart** — real-time breakdown of attacks per protocol
- **Attack table** — timestamp, IP, **MAC + vendor**, protocol, captured credentials, payload
- **Footer** — device uptime, free heap, Wi-Fi signal strength (RSSI)
- **Clear button** — wipes the logs from flash

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/attacks` | Attack log + statistics (JSON) |
| `GET` | `/api/status` | Uptime / heap / RSSI (JSON) |
| `POST` | `/api/clear` | Clear the log |

All endpoints are protected with HTTP Basic Auth (`admin` / `ADMIN_PASSWORD`).

---

## Project structure

```
ShadowSentryS3/
├── CMakeLists.txt              ESP-IDF root build file
├── sdkconfig.defaults          ESP32-S3 defaults (240 MHz, dual-core)
├── partitions.csv              NVS(24KB) + App(3MB) + SPIFFS(1MB)
└── main/
    ├── config.h.example        ← Configuration template (copy to config.h)
    ├── config.h                ← Real settings (in .gitignore)
    ├── idf_component.yml        Managed dependencies (espressif/mdns)
    ├── main.c                  Entry point, task distribution across cores
    ├── wifi_manager.c/h        Wi-Fi STA, DHCP hostname, SNTP, mDNS, ARP helpers
    ├── arp_monitor.c/h         ARP-spoof / MITM detector              (Core 1)
    ├── wifi_monitor.c/h        Wi-Fi deauth-flood detector (promisc)  (Core 1)
    ├── geoip.c/h               Threat-intel enrichment (ip-api.com)   (Core 1)
    ├── index.html              Dashboard HTML (embedded into the firmware)
    ├── CMakeLists.txt
    ├── honeypot/               ── Core 0 — Hacker World ──────────────
    │   ├── rtsp_trap.c/h       Port 554, Fake Hikvision, Base64 creds
    │   ├── http_trap.c/h       Port 80, Fake NVR login page
    │   ├── telnet_trap.c/h     Port 23, Fake Ubuntu 20.04 login
    │   ├── fake_shell.c/h      Interactive post-login shell (command capture)
    │   ├── ssh_trap.c/h        Port 22, Real SSH server (wolfSSH) — captures creds
    │   ├── ssh_hostkey.h       Embedded ECDSA host key (decoy)
    │   └── ftp_trap.c/h        Port 21, Fake vsFTPd 3.0.5, full creds
    ├── admin/                  ── Core 1 — Admin World ───────────────
    │   ├── admin_panel.c/h     Port 9999, HTTP Basic Auth, REST API
    │   ├── ws_server.c/h       Port 9998, live WebSocket event push
    │   └── telegram.c/h        Async FreeRTOS queue → Telegram Bot API
    └── storage/
        └── log_store.c/h       RAM ring buffer (200 entries) + SPIFFS
```

---

## How an attack is detected

No legitimate home-network device (laptop, phone, Smart TV) **ever** connects to ports 554, 80, 23, 22 or 21 on the ESP32 board.

> **Any connection to ShadowSentry S3 = a 100% anomaly.**

Typical detection scenarios:

| Threat | Behaviour | Detection time |
|--------|-----------|----------------|
| Mirai / Mozi botnet | Brute-force RTSP/Telnet/FTP | < 5 s |
| Post-login intrusion | Commands run in the fake Telnet shell (recon, payload fetch) | per command |
| Ransomware lateral movement | Subnet scanning | < 5 s |
| SSH scanner | Version fingerprint on port 22 | < 1 s |
| Web scanner | GET / on port 80 | < 1 s |
| Manual scan (nmap) | SYN on any port | < 1 s |
| ARP spoofing / MITM | Gateway MAC change or one MAC claiming many IPs | ≤ scan interval (8 s) |
| Wi-Fi deauth / disassoc attack | Reason-code-classified forced disconnect (≥1) or broadcast flood (promiscuous) | ≤ window (2 s) |

---

## ESP-IDF dependencies

All components ship with ESP-IDF — nothing to install separately:

- `lwIP` — TCP/IP stack, raw sockets
- `FreeRTOS` — multitasking, queues
- `esp_http_client` — Telegram Bot API
- `mbedTLS` — Base64 decode for Basic Auth
- `SPIFFS` — flash file system
- `esp_netif_sntp` — time synchronization

One component is fetched automatically by the component manager (declared in `main/idf_component.yml`, downloaded on the first build):

- `espressif/mdns` — `.local` name resolution (reach the admin panel by name)

---

## Troubleshooting

**Won't connect to Wi-Fi**
```
ESP32-S3 supports 2.4 GHz only. Check the SSID/password in config.h.
```

**`idf.py: command not found`**
```bash
. ~/esp/esp-idf/export.sh
```

**Permission denied on /dev/ttyUSB0 (Linux)**
```bash
sudo usermod -a -G dialout $USER
# Log out and back in
```

**`SPIFFS: mount failed` error**
```bash
idf.py -p /dev/ttyUSB0 erase-flash
idf.py -p /dev/ttyUSB0 flash
```

**Telegram doesn't send alerts**
```
Make sure the bot isn't blocked and you sent it /start.
TELEGRAM_CHAT_ID is a number (can be negative for groups).
```

---

## Roadmap

**Shipped**
- [x] 5 protocol honeypot traps (RTSP / HTTP / Telnet / SSH / FTP)
- [x] Per-attack MAC + vendor (OUI) resolution
- [x] HTTP request fingerprinting (method / path / User-Agent)
- [x] Telegram alerts with resilient delivery + retry
- [x] Live web dashboard + REST API, clickable attack-detail modal
- [x] mDNS `.local` resolution
- [x] ARP-spoof / MITM monitor
- [x] Threat-intel / GeoIP enrichment (country · ASN · reputation)
- [x] Wi-Fi deauth/disassoc threat monitor (reason-code classified)
- [x] Interactive fake shell with per-command logging + IOC escalation (Telnet)
- [x] Real SSH server via wolfSSH — credential capture + fake shell
- [x] Live WebSocket dashboard — real-time event push (polling fallback)

**Planned**
- [ ] SSH version-banner spoofing (present as OpenSSH, not wolfSSH)
- [ ] Per-device SSH host-key generation at first boot (NVS-cached)
- [ ] Rogue / evil-twin AP detection (requires channel hopping)
- [ ] Additional protocol traps (SMB, MQTT, UPnP)

---

## License

MIT — use, modify and distribute freely.
