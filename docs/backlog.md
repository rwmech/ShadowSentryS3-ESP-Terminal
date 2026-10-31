# Backlog: ShadowSentry S3, Elecrow ESP Terminal 3.5" fork

Applies to: main at 022634e plus the lanes in flight (discord, camera; alarm-ux in merge), 2026-10-31.

Everything Rob has asked for, or that came out of testing and research, that is not yet built. Nothing here is started without Rob's go. Research behind it:
- C:\Users\rwmec\Documents\Development\Honeypot\research\lan-discovery-scans.md (TVs and LAN discovery, 41 sources)
- C:\Users\rwmec\Documents\Development\Honeypot\research\honeypot-traps.md (trap catalogue, attack telemetry, sources to port from and their licences)

## In the current merge

- Dashboard heartbeat on the header shield (soft pulse per successful status poll, grey after two misses, ACTIVE pill unchanged). Being added by the merge lane with alarm-ux.

## Approved, starts when alarm-ux is on main

- Hold-to-confirm progress fill. Rob, 2026-10-31: "on the hold to acknowledge can we have it fill the button as we hold to ack. meaning if it takes 2 seconds spend 2 seconds filling the button like a progress bar, this is a common ui trait."
  - ACKNOWLEDGE and RE-ARM both take a 2 s hold (Rob's choice).
  - A solid fill grows left to right over the hold, with the label readable on top. Releasing early drains it back with no action; completing it fires the action with a short confirm tone.
  - Applies on the incident card and on the strobing overlay, in main\ui\ui.c.
  - The camera snapshot hook stays on the press start, not the completion.
- Startup melody timing from the score. Rob, 2026-10-31, after hearing the 260 ms version: "now the melody sounds too slow. use the legit song timings".
  - Read the tempo marking and the note values for the opening theme from the public-domain score: Grieg, Peer Gynt Suite No. 1, Op. 46 No. 4, on IMSLP.
  - Set main\alarm\melody.c to match: eighths and quarters as written, at the marked tempo, staccato articulation.
  - Keep our added cadence (F#, then the held B6), in the same tempo.
  - Record the source edition and the metronome mark in melody.c's comment.
- Tighter panel layout. Rob, 2026-10-31: "the new on screen layout is using a bit too much space". Keep the structure; cut paddings, margins and card height, and keep the headline and source readable.
- Ignore-source button on the panel, plus the ignore list it needs. Rob, 2026-10-31: "an ignore ip button on the display. Make sure the back end can always undo it. Id also make sure it gets an are you sure dialog over it."
  - On the incident card: IGNORE SOURCE opens a confirmation dialog showing the IP, MAC and vendor, with Ignore and Cancel buttons.
  - Confirming adds the source to the ignore list (NVS). If the open incident is from that source, it is closed (acknowledged and re-armed), so the siren and strobe stop.
  - Ignored sources are still logged, flagged "ignored", and never open an incident. This settles the open question under Detection.
  - The dashboard Settings page gets an Ignore list: view, add and remove entries, with an API under the X-ShadowSentry check.
  - The panel can only add; removal is dashboard-only, so the panel can never undo what only the backend should, and the backend can always undo the panel.
  - It is built so the later "Alert on" page reuses it.

## Proposed build order

The TA's recommendation, by value against effort. Rob picks.

- 1. Scan and probe detection, the Alert-on page and the ignore list (the Detection section below). This fixes the zero-alerts nmap result, and every later trap reuses the new event types and the per-type alert switch.
- 2. Hide the admin ports (Stealth). This uses the same lwIP input hook as item 1.
- 3. Cheap listener breadth. Telnet on 2323 and SSH on 2222 reuse the existing shells. ADB on 5555 is the top internal-LAN threat (infected Android TV boxes).
- 4. LAN discovery, log-only, plus the ARP sweep detector and device labels. This is what catches the LG TV.
- 5. The HTTP persona engine with extra ports and fake pages.
- 6. Protocol traps: RDP, VNC, SMB, Redis, MySQL, printers.
- 7. Fake-shell refresh from Cowrie data.
- 8. Discovery baits (the DLNA MediaServer first).

## Detection and alerting

- Port scan detection. Rob, 2026-10-31: "Add port scans and probes like this fire off an alert". Observed: `nmap -sS` and `nmap -sT` against 192.168.0.118 raised zero alerts, because upstream only logs once a trap gets credentials or an HTTP request.
  - Plan: an lwIP IPv4 input hook sees every inbound TCP SYN and UDP datagram, including to closed ports. It only queues (source, port, protocol).
  - A Core 1 task counts distinct ports per source in a sliding window (default 5 ports in 10 s) and raises one "Port scan" event per scan, carrying the port count and range.
  - It is a new attack type, so the on-flash log, the dashboard type list, the panel, Discord and the metrics all need to know it.
- Probe events. A connection to a trap port that closes without sending credentials or a request (nmap -sT, banner grabs) is logged as a low-level "Probe" event and counts toward the scan threshold.
- "Alert on" page in the dashboard. Rob: "add checkboxes to a 'alert on' page in the back end I can turn on and off".
  - One checkbox per event type: Port scan, Probe, SSH, Telnet, Shell command, FTP, HTTP, RTSP, ARP spoof, Wi-Fi deauth, plus the new trap and discovery types.
  - Each checkbox decides whether that type opens an incident (siren, panel, Discord).
  - Logging to SD and the dashboard stays on for every type regardless. Stored in NVS with the other settings.
- Ignore list. Rob: "OR ignore a specific IP". IPs, and optionally MACs since DHCP moves IPs, that never open an incident.
  - Open question for Rob: should ignored sources still be logged (flagged "ignored"), or dropped entirely? Proposed default: still logged, never alerted.

## Stealth

- Admin ports 9999 (dashboard) and 9998 (WebSocket) are visible in every scan (nmap names them "abyss" and "distinct32") and give the honeypot away.
  - Proposed: an allowlist of admin IPs. The same lwIP input hook drops SYNs to 9998/9999 from anyone else, so those ports read as closed or filtered to an attacker.
  - It needs a safe fallback so Rob can't lock himself out: an empty allowlist means open, and the serial console still works.

## New listeners and protocol traps

Sources, licences and depth for each are in honeypot-traps.md. Licence policy: port MIT, BSD, ISC and Apache code with its notice in a new THIRD_PARTY_NOTICES file. GPL and AGPL projects are reference only: reimplement from the protocol spec.

Ranked for a home LAN:
- Telnet 2323 and SSH 2222 on the existing shells. No new code beyond listeners.
- ADB 5555, the top internal-LAN threat (Kimwolf, BADBOX 2.0 on Android TV boxes). Port from Glutton adb.go (MIT). Answer the connect handshake, log shell and push requests, keep pushed files on SD.
- RDP 3389: X.224 connection request and confirm only, which captures the client cookie or username. From OpenCanary rdp.py (BSD-3) and Glutton (MIT).
- VNC 5900: RFB version and security handshake. From OpenCanary vnc.py (BSD-3).
- SMB 445 (and NBNS 137 logging): negotiate plus session setup, capturing the NTLM user, domain and workstation. From Glutton smb (MIT) and MS-SMB2. Medium to high cost.
- Redis 6379: a RESP parser with canned replies, logging commands. From OpenCanary redis.py (BSD-3).
- MySQL 3306 and MSSQL 1433: greeting and login packet, capturing the username. From mysql-honeypotd (MIT, C) and OpenCanary (BSD-3).
- Printers, JetDirect 9100 and IPP 631: answer status queries and store raw jobs. From Glutton ipp (MIT); PJL reimplemented after reading the Miniprint wiki (GPL, reference only).
  - Conflict with the LAN research: the board must never advertise itself as a printer (mDNS _ipp, WSD), or Windows may auto-install it. Listen on the ports only, with no advertisement.
- SIP 5060, SNMP 161 (log community strings), MQTT 1883: cheap, lower value. From OpenCanary and Glutton.
- Low value inside a LAN, deferred: MongoDB, Elasticsearch, SMTP, TR-069.

Design note: on a LAN any connection is already a signal, so many cheap listeners beat deep emulation. Every listener feeds the Probe and scan logic.

## HTTP trap coverage

- More fake pages and ports. Rob, 2026-10-31: "adding other http pages, I imagine there are some other common ones this is not currently looking at". Today port 80 serves one fake NVR login.
- One HTTP engine: a single socket loop over all HTTP listeners, dispatching on port, Host and path to a persona record (title, Server header, favicon, login form, realistic 404, success or failure behaviour). This is far cheaper than an esp_http_server per port. Keep each port's persona self-consistent.
- Ports: 8080, 8000, 8443 and 9000 (DShield top targets), then 81, 8081 and 8888. TLS on 8443 costs mbedTLS buffers in PSRAM; one TLS session at a time.
- Personas, ranked by what gets exploited:
  - a consumer router admin login
  - a second camera or DVR brand (Dahua)
  - a NAS login
  - a printer web UI
  - a VPN or firewall portal
  - Tomcat manager, Jenkins and Grafana
  - WordPress and phpMyAdmin
  - config and dotfile probes answered with realistic 404s
- Template sources: OpenCanary skins (BSD-3), Wordpot (ISC), StrutsHoneypot and ciscoasa_honeypot (MIT), honeyaml (MIT), Glutton handlers (MIT), and Rapid7 Recog for believable Server headers and cookies (BSD-2).
- Exploit-probe labelling: classify requests on the device against a small compiled table of categories ("router CGI command injection", "JNDI lookup", "dotfile probe"), derived offline from maintained sources rather than hand-written. Sources: ET Open web and scan rules (BSD SID range), Sigma web rules (DRL, attribution), Nuclei http templates (MIT), H0neytr4p traps (Apache-2.0), DShield URL feeds (attribution).

## Fake shell fidelity

- `w` printed nothing (a real Ubuntu prints the uptime header and a user table).
- The session in Rob's test ended with "Connection closed by foreign host" right after `w` and an empty line. Find out whether the shell closed it (a bug) or the client did.
- Refresh the shell from Cowrie's data (BSD-3, copy allowed with notice):
  - txtcmds for canned output, cmdoutput.json for the process list, etc/ files;
  - fs.pickle converted offline into a flat tree in flash (never unpickled on the device).
- Change every Cowrie default (hostname, kernel strings, banners), because scanners fingerprint them.
- Choose which commands to cover using the CyberLab Cowrie dataset (CC BY 4.0). Sessions average about 20 commands and 99 % are non-interactive, so many plausible one-shot replies beat deep state.
- Port the shell fuzzer from C:\Users\rwmec\Documents\Development\Honeypot\ref\ESP32-Honeypot_GUI\test\fuzz_shell.cpp.

## LAN discovery and device emulation

Source: lan-discovery-scans.md. Nothing public names the protocols, ports or rates behind LG's sweep: only a capture on Rob's LAN settles it, and the log-only listeners below are that capture.

Signal ladder: a device announcing itself on multicast only proves it exists. A device fetching the description of something we advertised is indexing the LAN. A connection to a port we never advertised is the strongest signal.

- Log-only listeners: no replies, so nothing in the house is affected. Each records who sent what, rate-limited and deduplicated into a "seen devices" table that also feeds the SD log, the Logs page and Discord at low priority.
  - SSDP M-SEARCH and NOTIFY on UDP 1900 (239.255.255.250)
  - mDNS queries on UDP 5353, sharing the port with the espressif/mdns component (SO_REUSE) or replacing it
  - WS-Discovery on 3702
  - LLMNR 5355 and NBNS 137: log only, never answer
  - vendor discovery broadcasts: Kasa UDP 9999 and 20002, LIFX 56700, PlayStation 987 and 9302. Kasa's 9999 is UDP, the admin panel's is TCP; check lwIP allows both.
  - DHCP 67, for hostnames (for example LGwebOSTV) and request fingerprints
  - Wi-Fi power save is already off (WIFI_PS_NONE), so multicast arrives.
- ARP sweep detector: one MAC asking who-has for many IPs in a short window means a LAN sweep (IoT Inspector, Fing, Avast, probably the LG TV). It needs a netif input wrapper so the board sees broadcast ARP.
- Device labels: match SSDP USER-AGENT and SERVER strings (LG "LGE WebOS TV", Samsung "SEC_HHP_", Roku, Sonos, Hue "IpBridge", Fire TV "Cling"), DHCP hostnames and MAC vendor, so the board says "LG TV (webOS)", not just an IP. The MAC vendor is weak for phones, which randomise their MACs.
- First bait, safe by design: a DLNA MediaServer.
  - It answers only MediaServer:1, upnp:rootdevice and ssdp:all, serves a rootDesc.xml on 8200, and returns empty Browse results.
  - It targets exactly what LG TVs search for (Photo & Video, Home Dashboard), and nothing in the house will try to cast to a media server.
  - Its description fetches and Browse calls are "device indexing" events.
- Later baits, to see whether the TV follows up: a WeMo/Echo-style plug (fauxmo templates), Roku ECP (8060), Kasa.
- Must not:
  - answer as a MediaRenderer, DIAL, _googlecast or _airplay target (it would appear in cast menus and break casting);
  - advertise a UPnP InternetGatewayDevice (consoles would try to map ports on it);
  - answer LLMNR, NBNS or mDNS for other hosts' names (poisoning, MITRE T1557.001);
  - advertise _sleep-proxy, or pose as a WSD or IPP printer;
  - send ARP for other hosts.

  Use unique names and UUIDs, and rate-limit every reply.

## Carried over (from CLAUDE.md "Open")

- Discord: attach the camera's "who pressed it" photo to the acknowledged and re-armed posts (multipart upload). Depends on the camera and discord lanes.
- Logs page "whole file" on a multi-MB day file ties up the single admin task while it streams. Cap it or add an offset.
- Events can drop if more than 32 queue in the first 15 s while the card waits for the display bus.
- Upstream: Basic auth has no rate limit; one slow client can hold the admin port.
- Upstream cosmetic: main\wifi_manager.c prints the gateway as the mask in the "IP acquired" line.
- Commits 5a5f5b0, 631c4d3 and 12533fd carry the wrong author email. Fixing it needs a history rewrite and a force push (Rob's call).
- Panel fonts: 28 pt is the largest built in. Bigger headline text needs LVGL font options in sdkconfig.defaults and a fresh sdkconfig.

## Platform

- Display and board HAL, for later. Rob, 2026-10-31: "at some point you'll need to HAL the display or offer another display but right now we just have the one. I have another board we can add here later."
  - Plan when the second board arrives: board.h selects the board at build time (one PlatformIO env per board), and the UI talks to a small display/touch/buzzer/backlight interface instead of LovyanGFX and the FT6236 directly. Each board supplies its own driver behind that interface.
  - Not started; wait for the board and its pin map.
- The repo is public (Rob, 2026-10-31). Secrets stay in the ignored main\config.h and tools\ota_password; git status is checked before every commit.
