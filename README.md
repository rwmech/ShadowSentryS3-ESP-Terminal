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

This repository is a fork of [Rdx1S/ShadowSentryS3](https://github.com/Rdx1S/ShadowSentryS3) that runs on the Elecrow ESP Terminal 3.5" (sold as CrowPanel ESP32 Terminal, model ER-DLC35020S: "ESP Terminal 3.5 inch 320*480 SPI TFT Capacitive Touch Display with OV2640 Camera"). It adds a local front panel, an audible incident alarm, a microSD event log with summary metrics, runtime settings and over-the-air updates. Every upstream trap and monitor is unchanged.

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

### What this fork adds

- Front panel (LVGL 8 + LovyanGFX, using Elecrow's own panel config), laid out for status and control rather than a scrolling log, in a bright palette (white and light grey text, saturated accents, slate cards) because the ILI9488 has no gamma tuning:
  - status bar: name, IP : port, clock, and an ARMED / ALARM / ACKED pill (the only place the state is spelled out)
  - running light: a 3 px bar under the status bar with a bright segment sweeping left to right every 2 s, green when armed, amber when acknowledged, red and bouncing every 0.7 s during an alarm. The UI task drives it, so if the panel ever freezes the light stops: moving means alive
  - armed: only the key figures (all-time events, distinct sources, microSD free space or "no card", Wi-Fi RSSI) and one muted line on the last incident, if there was one
  - during an incident: the incident card (number, how long it has been open, source IP in large type, attack type, event count, MAC, vendor, first and last seen) and the incident's last 3 events (its source, or anything since it opened; tap a row for details)
  - hold to confirm: ACKNOWLEDGE (unacknowledged) and RE-ARM (acknowledged) take a 2 s hold. A fill grows across the button as you hold; letting go or sliding off early empties it with no action, and completing it gives two short rising pips
  - while an incident is unacknowledged, two 40 px light bars at the screen edges flash a police pattern (left red, then right blue, two flashes each, 2 cycles a second) with the backlight forced to 100 %. Only the bars repaint, so the flash stays crisp over the SPI link, and the small burst-flash area stays clear of photosensitivity limits. Acknowledging stops them and restores the brightness setting
  - backlight brightness is a setting
- Sounds: at every boot, the opening of Grieg's "In the Hall of the Mountain King" (public domain), in the score's rhythm at its marked tempo (crotchet = 138), short and detached as written, about 3.7 s, played from its own task so boot does not wait; and a click on every touch of the screen. The boot sound and the click can each be switched off in Settings.
- Incident alarm: the first attack sounds a 3.2 s siren on the buzzer (a sweep from 2300 to 3100 Hz and back, across the piezo's 2.7 kHz resonance, four times), then the same siren every minute until someone acknowledges it, by holding the button on the panel or clicking Acknowledge on the web dashboard. Acknowledging cuts a siren short. After acknowledgement the same source stays quiet; a new source, or the same one after 10 quiet minutes, alarms again. Re-arm (hold RE-ARM on the panel, or Re-arm on the dashboard) ends an acknowledged incident at once, so the next event alarms again; it deletes nothing, the logs, metrics and the panel's last-incident summary all stay. An unacknowledged incident survives a reboot. The reminder interval (default 60 s), quiet time and alarm sound are settings.
- microSD event log: every attack, alarm transition and boot is appended as one JSON line to `/sd/log/YYYY-MM-DD.jsonl` (device local date; `nosync.jsonl` before the clock is set). A writer task drains a queue, so the traps never touch FAT. The card must be FAT32 or exFAT; the firmware never formats it.
- Summary metrics, kept from every attack and saved to `/sd/stats.bin` once a minute (and before a reboot or OTA): total and per-type counts, 24 hourly and 30 daily buckets, the top 64 sources and top 32 credential pairs. Top-N counts are upper bounds for entries that were evicted and came back.
- Dashboard tabs: Dashboard (upstream, plus the incident banner: Acknowledge while unacknowledged, Re-arm once acknowledged), Logs and Settings.
  - Heartbeat: the shield in the header gives one soft pulse (a slight glow and scale, under 1 s) each time the 5 s status poll gets an answer. After two missed polls in a row it stops and fades to grey until the device answers again. The ACTIVE pill is unchanged.
  - Logs: summary cards, 24 h, daily and by-type charts, top sources and top credentials, card status, and a day picker that loads a day file (the last 256 KB, or the whole file) into a filterable table, newest first, with a download link.
  - Settings: admin password, Wi-Fi, Telegram, timezone (POSIX TZ, with presets), alarm timings, brightness and the three sounds, plus Save, Reboot and Test buzzer. Settings live in NVS over the `config.h` defaults and survive OTA. Wi-Fi and Telegram apply after a reboot, the rest at once. If a Wi-Fi network saved here gets no IP within 90 s at boot, the board drops it and comes back on the `config.h` network.
- Discord alerts, to a channel webhook (`main/admin/discord.c`):
  - Incidents: an embed when one opens (red: incident number, source IP, MAC and vendor, attack type, the first event's username and payload, the device's IP and name), a reminder every alarm reminder interval while it is unacknowledged (orange: events so far, how long it has been open), one when it is acknowledged (amber, saying whether from the panel or the dashboard) and one when it closes (green: event count and duration, and whether it was re-armed or closed by the quiet time). Count-only updates never post.
  - Event log (the Discord twin of the microSD log), on by default: events are folded by source IP, attack type and a short summary (shell: the command's first word, so 110 runs of `ls` post once as `ran ls x110`; credential traps: user:pass; HTTP: method and path; otherwise the first 40 characters), and posted every 15 s as lines in a code block. A line that has posted waits 5 minutes before its next post, which shows only the new count (`+40 more`); a line idle for 10 minutes is forgotten. At most 32 lines per post, the rest follow in the next one.
  - Set it up: in Discord, channel settings, Integrations, Webhooks, New Webhook, Copy Webhook URL. Paste the URL into Settings, Discord (or set `DISCORD_WEBHOOK_URL` in `main/config.h` as the default), Save, then Send test. It applies at once, no reboot. "Clear webhook" turns Discord off; "Post the event log" turns the log off while incident alerts stay on.
  - The URL is a secret: it is never logged or returned by the API, only reported as set. Every post has `allowed_mentions` empty, attacker text is cut to printable ASCII with backticks replaced, so it can't ping anyone or break out of its code formatting. Posts are paced for Discord's webhook limit and honour HTTP 429 `retry_after`.
- Panel-press camera: the OV2640 faces whoever stands at the screen. A press on the panel's ACKNOWLEDGE button (action `ack`) or RE-ARM button (action `clear`) takes a photo (640x480 JPEG, Elecrow's sensor settings; 320x240 if the sensor will only start at Elecrow's own size) at the moment the press starts, not when the hold completes, so a press let go early is photographed too. It is saved as `/sd/snap/YYYY-MM-DD_HH-MM-SS_<action>.jpg` (through the SD writer task) with a `snap` line in the day log (shown on the Logs page, kind "snap"), and the last one is kept in PSRAM for the dashboard's "Last panel action" card (thumbnail, action, time; refreshed on every alarm state change and every 30 s). At most one photo a second. Without a camera the board logs it once and runs as before. On the board as of 2026-10-31 the sensor is detected but its first register write fails, so snapshots are off until that is fixed. The camera's SCCB runs on the new `i2c_master` driver and attaches to the bus touch already owns (touch polling pauses for the second or so the sensor takes to start, and both run at 100 kHz), so the legacy I2C driver (which would abort IDF 5.4 at boot) is never linked.
- OTA updates: two 6 MB app slots and `POST /api/ota` on the admin panel (same Basic auth). A new image has to reach Wi-Fi to confirm itself, otherwise the bootloader rolls back.
- Memory: the large buffers, Wi-Fi/lwIP and mbedTLS allocate from PSRAM, keeping internal RAM free for the display.

### Fork API (admin port, Basic auth)

Every `POST` needs an `X-ShadowSentry: 1` header (any value), including upstream's `/api/clear` and `/api/ack`. A page on another site can't add a custom header without a CORS preflight, which the device never grants, so a browser that holds the login can't be driven into cross-site POSTs. Example: `curl -u admin -X POST -H 'X-ShadowSentry: 1' http://<ip>:9999/api/ack`.

| Method | Path | |
|---|---|---|
| `GET` | `/api/settings` | settings; secrets only as `*_set` flags |
| `POST` | `/api/settings` | JSON body, fields present are applied; blank secrets are left alone (`"discord_webhook_clear":true` clears the webhook); `{"ok":true,"reboot":bool}` or 400 `{"error":...}` |
| `POST` | `/api/reboot` | 204, restart after 500 ms |
| `POST` | `/api/buzzer/test` | the alarm siren, even with the sound off; 204 at once, the siren plays after |
| `GET` | `/api/summary` | card status and summary metrics |
| `GET` | `/api/logs` | day files, newest first |
| `GET` | `/api/logs/file?f=NAME[&tail=1][&dl=1]` | one day file as NDJSON; `tail=1` sends the last 256 KB |
| `POST` | `/api/discord/test` | queue a test embed; `{"queued":true,"test":N}`, 409 with no webhook |
| `GET` | `/api/discord/status` | `test_done`, `test_ok`, `test_status` (HTTP status, -1 no connection), post and drop counters |
| `POST` | `/api/ack` | acknowledge the incident |
| `POST` | `/api/alarm/clear` | re-arm: end an acknowledged incident, 204; 409 `{"error":"acknowledge first"}` while unacknowledged; logs untouched |
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
