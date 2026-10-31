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

This repository is a fork of [Rdx1S/ShadowSentryS3](https://github.com/Rdx1S/ShadowSentryS3) that runs on the Elecrow ESP Terminal 3.5" (sold as CrowPanel ESP32 Terminal, model ER-DLC35020S: "ESP Terminal 3.5 inch 320*480 SPI TFT Capacitive Touch Display with OV2640 Camera"). It adds a local front panel, an audible incident alarm, port scan, probe and ARP sweep detection, an ADB trap, the alternate Telnet and SSH ports, HTTP on 8080, 8000 and 9000 with request labels, tripwires on RDP, VNC, SMB, Redis, MySQL, MSSQL and JetDirect, log-only LAN discovery listeners with a seen-devices table, an ignore list, hidden admin ports, a microSD event log with summary metrics, runtime settings and over-the-air updates. Upstream's traps and monitors behave as before; Telnet and SSH also listen on their alternate ports, and the NVR page is also served on the alternate HTTP ports.

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
| UDP 1900, 3702, 5355, 137, 9999, 20002, 56700, 987, 9302, 67 | LAN discovery listeners, log only, never answer (fork) | Discovery | `DISCOVERY_ENABLE`, `DISCOVERY_DHCP` |

The fork's ports follow a ranking of what reaches a home LAN most often: unauthenticated ADB (infected Android TV boxes and residential-proxy apps hunt for it), then Telnet and SSH bruteforce on the alternate ports. Each port option takes 0 to disable it; `main/honeypot/trap_listen.h` has defaults for a `config.h` written before these options. The alternate ports run on the existing Telnet and SSH tasks through `select()` (no extra stack, one wolfSSH context), so each service serves one session at a time across its two ports, as upstream does on one port. An event from an alternate port ends in "(port N)".

### What this fork adds

- Front panel (LVGL 8 + LovyanGFX, using Elecrow's own panel config), laid out for status and control rather than a scrolling log, in a bright palette (white and light grey text, saturated accents, slate cards) because the ILI9488 has no gamma tuning:
  - status bar: name, IP : port, clock, and an ARMED / ALARM / ACKED pill (the only place the state is spelled out)
  - running light: a 3 px bar under the status bar with a bright segment sweeping left to right every 2 s, green when armed, amber when acknowledged, red and bouncing every 0.7 s during an alarm. The UI task drives it, so if the panel ever freezes the light stops: moving means alive
  - armed: only the key figures (all-time events, distinct sources, microSD free space or "no card", Wi-Fi RSSI) directly under the running light, and one muted line on the last incident under them, if there was one
  - during an incident: the incident card (number, how long it has been open, source IP in large type, attack type, event count, MAC, vendor, first and last seen) and the incident's last 3 events (its source, or anything since it opened; tap a row for details)
  - hold to confirm: ACKNOWLEDGE (unacknowledged) and RE-ARM (acknowledged) take a 2 s hold. A fill grows across the button as you hold; letting go or sliding off early empties it with no action, and completing it gives two short rising pips
  - IGNORE SOURCE, beside ACKNOWLEDGE or RE-ARM on the incident card, opens an "are you sure" dialog with the IP, vendor and MAC. Ignore puts the source on the ignore list and, if the open incident is from it, acknowledges and re-arms it so the siren and the side bars stop. The panel can only add to the list; removing is done on the dashboard
  - while an incident is unacknowledged, two 40 px light bars at the screen edges flash a police pattern (left red, then right blue, two flashes each, 2 cycles a second) with the backlight forced to 100 %. Only the bars repaint, so the flash stays crisp over the SPI link, and the small burst-flash area stays clear of photosensitivity limits. Acknowledging stops them and restores the brightness setting
  - backlight brightness is a setting
- Sounds: at every boot, the opening of Grieg's "In the Hall of the Mountain King" (public domain), the theme's whole first statement in the score's rhythm at its marked tempo (crotchet = 138), short and detached as written, with a short close on the tonic, about 8 s, played from its own task so boot does not wait. An alarm siren cuts it short at once. A click sounds on every touch of the screen. The boot sound and the click can each be switched off in Settings.
- Incident alarm: the first attack sounds a 3.2 s siren on the buzzer (a sweep from 2300 to 3100 Hz and back, across the piezo's 2.7 kHz resonance, four times), then the same siren every minute until someone acknowledges it, by holding the button on the panel or clicking Acknowledge on the web dashboard. Acknowledging cuts a siren short. After acknowledgement the same source stays quiet; a new source, or the same one after 10 quiet minutes, alarms again. Re-arm (hold RE-ARM on the panel, or Re-arm on the dashboard) ends an acknowledged incident at once, so the next event alarms again; it deletes nothing, the logs, metrics and the panel's last-incident summary all stay. An unacknowledged incident survives a reboot. The reminder interval (default 60 s), quiet time and alarm sound are settings.
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
  - Per connection: accept, send the banner if the service speaks first (VNC `RFB 003.008`; MySQL a 5.7 handshake with no TLS offered, so a client sends its login packet), wait up to 3 s for the client's first bytes, read at most 64, log one Tripwire event and close. No protocol or credential parsing, no second round trip, 5 s per connection, one connection at a time across all seven ports.
  - The event reads `<service> on <port>: <first bytes in hex>` (`no data` if the client sent nothing), trimmed to the 128-byte payload; the console prints all 64 bytes. The microSD attack line gets `"service"` (`RDP`, `VNC`, `SMB`, `Redis`, `MySQL`, `MSSQL`, `JetDirect`).
  - Rate limit: one event per source and service per 30 s. Further connections in that window are accepted, printed on the console and counted, and the next event says how many (`RDP on 3389 (+4 held): ...`).
  - Each tripwire port is also a trap port for the probe detector. One internal 3 KB task stack (it writes SPIFFS); its high-water is printed at each new low.
- LAN discovery listeners (`main/detect/discovery.c`, `DISCOVERY_ENABLE`, default on), to see which devices on the LAN scan or discover the others (an LG TV opening Photo & Video or Home Dashboard, phone apps, Home Assistant, Windows) and with what. Log only: these sockets never send, so nothing in the house sees them or changes behaviour.
  - SSDP on UDP 1900 (joins 239.255.255.250): M-SEARCH with ST, MAN, MX and USER-AGENT, NOTIFY with NT, NTS, SERVER and LOCATION. WS-Discovery on 3702 (same group): the action (Probe, Hello, Resolve), Types, Scopes and XAddrs, read with bounded string scans, no XML parser. LLMNR on 5355 (joins 224.0.0.252): the queried names and types, queries only. NBNS on 137 (broadcast): the queried name; a registration's name is the sender's own NetBIOS name. Kasa on 9999 and 20002, LIFX on 56700, PlayStation on 987 and 9302: the size and first 16 bytes in hex, plus Kasa's XOR-encoded JSON on 9999, LIFX's message type and a PlayStation request's first line. DHCP on 67 (client broadcasts, receive only; the board's own client is on 68): the hostname (option 12), vendor class (60) and parameter request list (55) as a fingerprint (`DISCOVERY_DHCP` 0 leaves 67 alone). UDP 9999 coexists with the admin panel on TCP 9999.
  - mDNS (5353) is not captured: the espressif/mdns component owns 5353 on a raw lwIP pcb without `SO_REUSEADDR`, so a second socket cannot bind, and one that won the race would take `.local` away from the board.
  - Source MACs come from the station interface's input wrapper (the one the ARP sweep detector uses), which notes the sender's MAC for UDP to these ports; DHCP uses the packet's client MAC; otherwise the ARP cache.
  - Seen devices: up to 64, keyed by MAC, least recently seen evicted, in PSRAM. Each has the IP, first and last seen, the protocols with a packet count each, the best label so far, the DHCP or NetBIOS hostname and the last 4 distinct query strings. Labels, best first: a known string in an SSDP USER-AGENT or SERVER, a DHCP hostname or vendor class (LG webOS, Samsung, Roku, Sonos, Philips Hue, Fire TV, Xbox, PlayStation, Chromecast, Windows, Android), then a raw hostname, a raw vendor class or SERVER string, and the MAC vendor last. A locally administered MAC (phones randomise theirs) is marked "random MAC".
  - Logging: a `{"kind":"discovery"}` line on the card (and the console) for each new device, protocol, label or query string, at most 20 at once then one every 3 s. A new device, protocol or label is also a Discovery event (flash ring, dashboard feed, panel, Discord event log), at most 8 at once then one every 30 s, the rest counted into the next as "(+N held)".
  - Discovery is background noise, so its Alert on switch is off by default: it opens no incident unless switched on. A mask saved by older firmware does not switch it on (settings remember how many types the saved mask knew).
  - Every datagram is hostile: every length and offset is checked, DNS names follow at most 8 compression pointers and only backwards, strings are cut to printable ASCII on the way in and escaped on the way out. One 3.5 KB internal task stack (it writes SPIFFS); its high-water is printed at each new low.
- Recon detection (`main/detect/detect.c`), so a scan raises an alert before any trap sees a login:
  - an lwIP IPv4 input hook sees every inbound TCP SYN (plus FIN, NULL and Xmas probes) and UDP datagram to the board, open port or not. It only queues (source, port, protocol); the gateway and replies to the board's own DNS, DHCP, NTP and mDNS are skipped.
  - Port scan: 5 distinct ports from one source within 10 s (both settings) raise one "Port scan" event with the port count, lowest to highest port, protocol and sample ports. Nothing more while it continues; after 60 s of quiet a summary follows ("Scan ended: N ports total", with the trap ports it found).
  - Probe: a SYN to a trap port (21, 22, 23, 80, 554, 2222, 2323, 5555, 8000, 8080, 9000 and the tripwire ports 445, 1433, 3306, 3389, 5900, 6379, 9100; a disabled one excluded) raises one "Probe" per source, port and minute. It is held 1.5 s, so a scan that starts meanwhile folds it in; none while that source is scanning.
  - ARP sweep: a wrapper on the station interface's input sees ARP who-has requests (every frame is passed on). One MAC asking for 10 distinct hosts within 10 s (settings) raises one "ARP sweep" event with the MAC, vendor, count and range, then a summary after 60 s of quiet. The gateway and the board itself are excluded.
  - The three are new attack types (appended, so the flash ring stays readable) shown everywhere: panel, dashboard type list, filters and charts, microSD `tname`, Telegram.
  - The Logs page shows the detector's counters since boot (scans, probes, sweeps, packets queued and dropped, admin SYNs hidden, ARP tap on or off).
- Alert on: one switch per attack type on the Settings page decides whether that type opens an incident (siren, panel, Telegram, Discord). Every event is logged either way (flash ring, microSD, dashboard).
- Ignore list: up to 32 entries, each an IP and/or a MAC (DHCP moves IPs), with a note and the time added, in NVS. An entry matches on either. Ignored sources are still logged, flagged "ignored" (`"ignored":true` on the microSD line, a chip in the dashboard tables), and never open an incident or alert. View, add and remove (with a confirm) on the Settings page; the panel can add.
- Hidden admin ports: with an admin allowlist set (up to 8 IPv4s, Settings), the IPv4 hook drops SYNs to 9999 and 9998 from anyone else, so a scan shows them filtered rather than giving the honeypot away. Those dropped SYNs still count toward port scan detection. An empty list means open, as before. The dashboard refuses a list that does not include the address you are saving it from. Locked out anyway (a new DHCP lease, say)? Open the USB serial console (115200, `pio device monitor -e crowpanel35`) and type `admin-allow clear` then Enter: the list is emptied in NVS and the ports open at once. `admin-allow` alone prints the list.
- microSD event log: every attack, alarm transition and boot is appended as one JSON line to `/sd/log/YYYY-MM-DD.jsonl` (device local date; `nosync.jsonl` before the clock is set). A writer task drains a queue, so the traps never touch FAT. The card must be FAT32 or exFAT; the firmware never formats it.
- Summary metrics, kept from every attack and saved to `/sd/stats.bin` once a minute (and before a reboot or OTA): total and per-type counts, 24 hourly and 30 daily buckets, the top 64 sources and top 32 credential pairs. Top-N counts are upper bounds for entries that were evicted and came back.
- Dashboard tabs: Dashboard (upstream, plus the incident banner: Acknowledge while unacknowledged, Re-arm once acknowledged), Logs, Devices and Settings.
  - Devices: the seen-devices table, newest first, refreshed every 10 s: label (and where it came from, and the hostname), IP, MAC and vendor (and "random MAC"), protocols with packet counts, last seen, the last queries; above it, which listeners are open.
  - Heartbeat: the shield in the header gives one soft pulse (a slight glow and scale, under 1 s) each time the 5 s status poll gets an answer. After two missed polls in a row it stops and fades to grey until the device answers again. The ACTIVE pill is unchanged.
  - Logs: summary cards, 24 h, daily and by-type charts, top sources and top credentials, card status, and a day picker that loads a day file (the last 256 KB, or the whole file) into a filterable table, newest first, with a download link.
  - Settings: admin password, Wi-Fi, Telegram, Discord, WhatsApp, timezone (POSIX TZ, with presets), alarm timings, brightness and the three sounds, the Alert on switches, the scan and sweep thresholds, the admin allowlist, plus Save, Reboot and Test buzzer (Discord and WhatsApp each have a Send test button), and below them the ignore list. Settings live in NVS over the `config.h` defaults and survive OTA. Wi-Fi and Telegram apply after a reboot, the rest at once. If a Wi-Fi network saved here gets no IP within 90 s at boot, the board drops it and comes back on the `config.h` network.
- Discord alerts, to a channel webhook (`main/admin/discord.c`):
  - Incidents: an embed when one opens (red: incident number, source IP, MAC and vendor, attack type, the first event's username and payload, the device's IP and name), a reminder every alarm reminder interval while it is unacknowledged (orange: events so far, how long it has been open), one when it is acknowledged (amber, saying whether from the panel or the dashboard) and one when it closes (green: event count and duration, and whether it was re-armed or closed by the quiet time). Count-only updates never post.
  - Event log (the Discord twin of the microSD log), on by default: events are folded by source IP, attack type and a short summary (shell: the command's first word, so 110 runs of `ls` post once as `ran ls x110`; credential traps: user:pass; HTTP: method and path; otherwise the first 40 characters), and posted every 15 s as lines in a code block. A line that has posted waits 5 minutes before its next post, which shows only the new count (`+40 more`); a line idle for 10 minutes is forgotten. At most 32 lines per post, the rest follow in the next one.
  - Set it up: in Discord, channel settings, Integrations, Webhooks, New Webhook, Copy Webhook URL. Paste the URL into Settings, Discord (or set `DISCORD_WEBHOOK_URL` in `main/config.h` as the default), Save, then Send test. It applies at once, no reboot. "Clear webhook" turns Discord off; "Post the event log" turns the log off while incident alerts stay on.
  - The URL is a secret: it is never logged or returned by the API, only reported as set. Every post has `allowed_mentions` empty, attacker text is cut to printable ASCII with backticks replaced, so it can't ping anyone or break out of its code formatting. Posts are paced for Discord's webhook limit and honour HTTP 429 `retry_after`.
- Notifications (`main/admin/notify.c`): one small layer, `notify_send(kind, title, text, severity)`, fans a message out to every enabled backend (Discord, Telegram, WhatsApp). Each backend keeps its own queue and task, so a slow HTTPS post never holds the caller; a new backend (ntfy, Slack, a generic webhook) is one new file that registers a `notify_backend_t`.
  - Reboots: after Wi-Fi is up, every boot sends one "online" message to every enabled backend with the device IP and mDNS name, the firmware version and build, the dashboard URL and the reset reason in words: power-on, software restart, panic/crash, interrupt watchdog, task watchdog, other watchdog, brown-out, deep sleep, external pin or unknown. A software restart says why when the firmware knows: OTA update, reboot from the dashboard, or the saved Wi-Fi getting no IP (the reason is stored in NVS just before the restart and cleared at boot). Crashes and watchdogs post in red, brown-outs in amber, the rest in green. The microSD log's `boot` line carries the same text as `reason`, next to the numeric `reset`.
  - Telegram (upstream) now sends nothing while it is not configured; before, each alert was tried three times against api.telegram.org with the placeholder token. Its boot message comes through this layer, with the reset reason.
- WhatsApp alerts via [CallMeBot](https://www.callmebot.com/blog/free-api-whatsapp-messages/) (`main/admin/whatsapp.c`), the usual free route for an ESP32: an HTTPS GET to `api.callmebot.com/whatsapp.php` with the phone number, the URL-encoded text and an apikey.
  - Sends the boot message and incidents (opened, acknowledged, closed), not the event log. Messages are short plain text built from device data only (incident number, attack type, source IP, event count), never attacker text.
  - CallMeBot documents no rate limit, so the sender stays well clear: one message every 10 s at most, 20 an hour, anything over the cap dropped and counted. The free API is for personal use and only sends to the number that registered the key.
  - Set it up: follow the activation steps on CallMeBot's page to get an apikey for your number, then enter the number (international format, country code first, e.g. `+34123123123`) and the apikey in Settings, WhatsApp (or set `WHATSAPP_PHONE` and `WHATSAPP_APIKEY` in `main/config.h`), Save, then Send test. Both set means on; it applies at once. "Clear apikey" turns it off.
  - The apikey is a secret: it is never logged or returned by the API (only `whatsapp_apikey_set`), and the request URL that carries it is never logged.
  - Not implemented: Meta's official [WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api), the heavier alternative (a Meta business account, a registered sender number, approved message templates for business-initiated messages, and access tokens to manage).
- Panel-press camera: the OV2640 faces whoever stands at the screen. A press on the panel's ACKNOWLEDGE button (action `ack`) or RE-ARM button (action `clear`) takes a photo (640x480 JPEG, Elecrow's sensor settings; 320x240 if the sensor will only start at Elecrow's own size) at the moment the press starts, not when the hold completes, so a press let go early is photographed too. It is saved as `/sd/snap/YYYY-MM-DD_HH-MM-SS_<action>.jpg` (through the SD writer task) with a `snap` line in the day log (shown on the Logs page, kind "snap"), and the last one is kept in PSRAM for the dashboard's "Last panel action" card (thumbnail, action, time; refreshed on every alarm state change and every 30 s). At most one photo a second. Without a camera the board logs it once and runs as before. On the board as of 2026-10-31 the sensor is detected but its first register write fails, so snapshots are off until that is fixed. The camera's SCCB runs on the new `i2c_master` driver and attaches to the bus touch already owns (touch polling pauses for the second or so the sensor takes to start, and both run at 100 kHz), so the legacy I2C driver (which would abort IDF 5.4 at boot) is never linked.
- OTA updates: two 6 MB app slots and `POST /api/ota` on the admin panel (same Basic auth). A new image has to reach Wi-Fi to confirm itself, otherwise the bootloader rolls back.
- Memory: the large buffers, Wi-Fi/lwIP and mbedTLS allocate from PSRAM, keeping internal RAM free for the display.

### Fork API (admin port, Basic auth)

Every `POST` needs an `X-ShadowSentry: 1` header (any value), including upstream's `/api/clear` and `/api/ack`. A page on another site can't add a custom header without a CORS preflight, which the device never grants, so a browser that holds the login can't be driven into cross-site POSTs. Example: `curl -u admin -X POST -H 'X-ShadowSentry: 1' http://<ip>:9999/api/ack`.

| Method | Path | |
|---|---|---|
| `GET` | `/api/settings` | settings; secrets only as `*_set` flags; also `alert_mask` (bit per type), `scan_ports`, `scan_window_s`, `arp_targets`, `arp_window_s`, `admin_allow` (array) and `client_ip` |
| `POST` | `/api/settings` | JSON body, fields present are applied; blank secrets are left alone (`"discord_webhook_clear":true` clears the webhook, `"whatsapp_apikey_clear":true` the WhatsApp apikey); `{"ok":true,"reboot":bool}` or 400 `{"error":...}` |
| `POST` | `/api/reboot` | 204, restart after 500 ms |
| `GET` | `/api/ignore` | `{"max":32,"entries":[{"index","ip","mac","vendor","note","ts"}]}` |
| `POST` | `/api/ignore` | `{"action":"add","ip":"..","mac":"..","note":".."}` (one of ip, mac) or `{"action":"remove","index":N,"ip":"..","mac":".."}` (ip and mac as listed; 409 if the list changed); answers with the list |
| `POST` | `/api/buzzer/test` | the alarm siren, even with the sound off; 204 at once, the siren plays after |
| `GET` | `/api/summary` | card status and summary metrics |
| `GET` | `/api/logs` | day files, newest first |
| `GET` | `/api/logs/file?f=NAME[&tail=1][&dl=1]` | one day file as NDJSON; `tail=1` sends the last 256 KB |
| `POST` | `/api/discord/test` | queue a test embed; `{"queued":true,"test":N}`, 409 with no webhook |
| `GET` | `/api/discord/status` | `test_done`, `test_ok`, `test_status` (HTTP status, -1 no connection), post and drop counters |
| `POST` | `/api/whatsapp/test` | queue a test message; `{"queued":true,"test":N}`, 409 without a phone number and apikey |
| `GET` | `/api/whatsapp/status` | `test_done`, `test_ok`, `test_status` (HTTP status, -1 no connection), `sent`, `failed`, `dropped` |
| `POST` | `/api/ack` | acknowledge the incident |
| `POST` | `/api/alarm/clear` | re-arm: end an acknowledged incident, 204; 409 `{"error":"acknowledge first"}` while unacknowledged; logs untouched |
| `GET` | `/api/devices` | the LAN discovery table: `listeners` (name, port, open, packets, error), `devices` newest first (`mac`, `random_mac`, `vendor`, `ip`, `label`, `label_src`, `host`, `protos` {name: packets}, `total`, `first_ts`, `last_ts`, `first_ago_s`, `last_ago_s`, `queries` newest first), `count`, `truncated` |
| `GET` | `/api/snap/last` | last panel-press photo, `image/jpeg`; 404 if none since boot |
| `GET` | `/api/snap/last.json` | `{camera, seq, ts, action, file, size, width, height}`; `seq` 0 if none |
| `POST` | `/api/ota` | raw app image |

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
