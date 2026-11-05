# ShadowSentry S3 Terminal 1.0.0: Elecrow CrowPanel 3.5 and Waveshare 4.3B

Tag: `terminal-1.0.0-crowpanel35-waveshare43`

The first release of this fork of [Rdx1S/ShadowSentryS3](https://github.com/Rdx1S/ShadowSentryS3) v1.0.0. It turns the honeypot into a desk terminal with a touch screen and adds detection, router and Pi-hole integration, notifications and a larger dashboard. Upstream's traps and monitors behave as before.

There are no firmware images to download: an image carries your Wi-Fi and admin passwords, so you build your own. The README's "Build and flash" section takes you from a fresh computer to a running board, on Windows, macOS or Linux.

Everything below is described in full in the README, section "This fork".

## Boards

- Two boards, chosen at build time: the Elecrow CrowPanel ESP32 Terminal 3.5" (ER-DLC35020S, 480 x 320 SPI, FT6236 touch, OV2640 camera, buzzer) and the Waveshare ESP32-S3-Touch-LCD-4.3B (800 x 480 RGB, GT911 touch, CH422G expander).
- PlatformIO envs `crowpanel35`, `crowpanel35_ota`, `waveshare43`, `waveshare43_ota`; `BOARD_CROWPANEL35` or `BOARD_WAVESHARE43` in `main/config.h` for `idf.py`.
- Everything board-specific behind `main/board/board.h` and one board file each; a new board is a board file, a display driver and two envs.
- On the 4.3B: an RGB panel driver with two PSRAM frame buffers and bounce buffers, code running from PSRAM so flash writes do not disturb the picture, the console on USB-Serial/JTAG, a buzzer you can add as a piezo on the CAN terminal pair, no camera.
- The panel layouts are drawn on a 480 x 320 grid and scaled to the screen, with larger fonts on the 4.3B.
- A partition table with two 6 MB OTA app slots and a 2 MB file system on the 16 MB flash.

## Front panel

- Three styles, switched live from the Settings page: LCARS (the CrowPanel's default), clan (the 4.3B's default) and the dashboard (CrowPanel only).
- LCARS: a frame and rail with OPS, TRAPS, WIRES, NET and DEV pages, AUTO rotation (Page rotation setting, default 30 s), a port table of every listener, traps and tripwires with their hits today, network gauges, the busiest LAN devices with a BLOCK DEVICE button, and motion driven by real activity.
- Clan: gunmetal plates on a tiled metal texture, a holo radar with a blip per LAN device, TACTICAL, BAIT, PERIMETER, SYSTEMS, CONTACTS and INFO pages, and a configurable panel title.
- Dashboard style: tiles, top offenders and LAN talkers in a bright palette, with a running light that shows the UI is alive.
- RED and YELLOW alert screens in every style, with a Starfleet-style emblem on LCARS and the dashboard: the code, source, headline and counts, ACKNOWLEDGE (a 2 s hold), IGNORE ERROR and IGNORE DEVICE (each asks first).
- The SYS about screen (subsystem info, the build's git hash and date, IP, admin port, uptime), a boot splash on LCARS, and a panel logo you can upload as a PNG.
- 12-hour or 24-hour clock.

## Alarm and alerts

- Incidents with three conditions, the same on the panel, the dashboard and every alert: RED (an unacknowledged SEV1 incident), YELLOW (acknowledged, or opened by SEV2 events), GREEN.
- A red alert klaxon every minute until acknowledged, a soft call for YELLOW, TNG-style boot beeps and LCARS-style console chirps, with UI and alarm volume settings and a sound player on the Settings page.
- Alert codes ("Code CC-NN") and a one-line headline for every event, 56 codes in three tiers, listed by `GET /api/codes`.
- Acknowledge, resolve and ignore from the panel and the dashboard; an incident survives a reboot.
- An ignore list of IP and/or MAC entries, for one code or a whole device; ignored events are still logged.
- An Alert on switch per attack type.

## Detection

- Port scan, probe and ARP sweep detection through an lwIP IPv4 input hook and an ARP tap, with thresholds in Settings.
- Log-only LAN discovery listeners (SSDP, WS-Discovery, LLMNR, NBNS, Kasa, LIFX, PlayStation, DHCP, and mDNS queries copied from the Wi-Fi input), a seen-devices table with labels, and a 30-minute Discord digest when Discord is set to post everything.
- A MAC vendor database on the microSD card, built from the IEEE registry with `tools/make_oui.py`.
- Hidden admin ports: with an admin allowlist, scans see the dashboard ports as filtered.

## Traps and tripwires

- ADB on 5555 (a fake Android TV box, ported from Glutton), Telnet on 2323 and SSH on 2222 next to upstream's ports.
- One HTTP engine on 80, 8080, 8000 and 9000 with request labels (login POST, dotfile, traversal, scanner and library User-Agents, ...) and the full request on the card.
- Tripwires on RDP 3389, VNC 5900, SMB 445, Redis 6379, MySQL 3306, MSSQL 1433 and JetDirect 9100: any connection alerts, with its first bytes.
- MikroTik decoys: Winbox 8291, the RouterOS API 8728 (command and user name only, never the password), bandwidth test 2000, MNDP on UDP 5678 and MAC-Telnet on UDP 20561, with a whitelist for the real router.
- Sturdier fake shell input: idle and session limits, Ctrl-C, escape sequences and bare-LF clients handled.

## Router and Pi-hole

- An optional, read-only Pi-hole v6 client: names, query and blocked counts and top domains per device (allowed, blocked or mixed), and Pi-hole's DNS log matched against the router's connections ("no lookup seen" for an address nobody looked up).
- An optional, read-only MikroTik RouterOS REST client: DHCP leases, ARP, switch port or access point per device, connection tracking on demand, new devices on the network (Code 60-02), and router integrity checks against an armed baseline (Codes 55-01 to 55-11).
- Router feeds with no sockets on the board: the router's syslog as tripwires (failed logins, logins, configuration changes, the router's own port scan detector, management ports, DNS bypass; Codes 55-21 to 55-28), its IPFIX or NetFlow v9 flows per device, and a block list the router pulls every minute. The board never writes to the router.
- The RouterOS side in `tools/routeros/` (tripwires, flow export, block list), and a worked set-up and rollback in `docs/router-setup.md` and `docs/router-rollback.md`.

## Notifications

- Discord webhook alerts: incident embeds (opened, escalated, reminders, acknowledged, closed) and a deduplicated event log, SEV1 and SEV2 by default (the "Post to Discord" setting).
- WhatsApp through CallMeBot: boot and incident messages.
- One notification layer over Discord, Telegram and WhatsApp, with a boot message that gives the reset reason (and the crash, if there was one).
- Telegram sends nothing while it is not configured, and each message starts with the code and headline.

## Dashboard and API

- A condition banner on every tab, with ACKNOWLEDGE, RESOLVE, IGNORE ERROR, IGNORE DEVICE and OPEN ON DEVICE PAGE.
- Logs, Devices and Settings tabs; larger, readable text; codes and headlines in every table; copy buttons that work over plain http.
- A device page (`/device`) for every device: identity, analysis, an issue summary and activity chart over its whole log, its messages, the router's view (connections and flows, flags such as beaconing, DNS bypass or upload-heavy), Pi-hole's view, Block buttons, and a "Get AI advice" prompt.
- Login attempts named by the trap they hit ("Hikvision login (port 8080)", "Telnet (2323)", ...), and all-days log views by type or user name.
- Gzip-compressed pages with ETags, an admin port that holds four connections at once, and a heartbeat on the header shield.
- Every POST needs an `X-ShadowSentry` header, against cross-site requests from a browser that holds the login.
- New routes for settings, logs, codes, the alarm, ignores, devices, Pi-hole, the router, the block list, crashes, tasks, the logo, the vendor database, the camera and debug toggles (the README's Fork API table).

## Storage

- A microSD JSONL event log, one file per day, written by its own task so traps never touch FAT, with summary metrics in `/sd/stats.bin` (per type, per hour and day, top sources and credential pairs).
- Runtime settings in NVS over the `config.h` defaults, edited on the Settings page, kept across updates.
- Camera photos (CrowPanel), pushed ADB files, crash reports and the vendor database on the card.

## Reliability

- Over-the-air updates (`POST /api/ota`, `tools/ota_upload.py`), with rollback when a new image never reaches Wi-Fi.
- Crash records: a panic wrapper writes the cause, registers and backtrace into RTC memory; the next boot reports it on the dashboard, the card and the boot message, and `tools/decode_crash.py` turns it into function and line with the archived ELF.
- Wi-Fi joins the strongest access point, accepts 802.11k/v steering, and moves to a stronger one after a minute below -75 dBm.
- PSRAM first: buffers, LVGL, cJSON, the static data of lwIP and the Wi-Fi libraries and most task stacks in PSRAM, which keeps about 58 KB of internal RAM free after boot on the CrowPanel.
- A single JSON escaper with UTF-8 checks, so attacker bytes never break the API's JSON.
- `GET /api/tasks` (CPU share and stack high-water per task) for a board without a console.
- A CI workflow builds both boards from `main/config.h.example` on every push and tag.

## Known open items

- Camera: on the development CrowPanel the OV2640 was not detected in the last tests after the SCCB fixes, so the panel photo is untested with a working sensor.
- Waveshare 4.3B: the panel's pixel clock is 14 MHz because Waveshare's 16 MHz shifted the picture with the clan style; frame time under heavy Wi-Fi and flash traffic, touch coordinates and the scaled layout on the glass have had little testing. The plain ESP32-S3-Touch-LCD-4.3 (not the B) has not been tested at all.
- RouterOS scripts (`tools/routeros/*.rsc`): written against the RouterOS 7.24 manual and applied by hand on one RouterOS 7.25 router. Other versions are unchecked; read each file before pasting. The block list's end-to-end test with the router's scheduler was not finished on that router.
- IPFIX: the RouterOS manual does not say whether FastTracked connections reach traffic-flow; compare `ipfix.records` in `GET /api/router/status` with a download you start.
- The first Wi-Fi join after a boot can pick a weak access point until the re-roam (after 60 s below -75 dBm) moves it. Ping times to the board are higher than on some earlier development builds (50 to 60 ms on average at a good signal).
- GeoIP owner names: upstream's lookup goes to ip-api.com, which some Pi-hole block lists block; allow it in Pi-hole or the device page's Owner column stays empty. Upstream's cache holds 24 addresses with no cache of failures.
- Pi-hole's DNS log matching needs query logging on in Pi-hole (Settings, DNS, Log DNS queries).
- A `.local` Pi-hole name may not resolve from the board; use the Pi-hole's IP address.
- `stats.bin` is version 3. Older firmware reading it starts the summary metrics from zero, so going back to an older build loses them.
- The LCARS NET page's sockets gauge shows "-" (lwIP has no public count).
- Upstream's Telnet reader skips one byte too many after a 2-byte IAC command (a client's Ctrl-C in line mode); the trap never negotiates options, so clients rarely send one.
- Basic auth on the admin port has no rate limit (upstream), and the admin port answers one request at a time, so a long log scan or an OTA holds the others while it runs.
