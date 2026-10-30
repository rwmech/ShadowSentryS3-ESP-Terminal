# ShadowSentry S3, Elecrow ESP Terminal 3.5" fork

Instructions for the agent tuning this fork. Written 2026-10-30. Keep it current: every decision and every change in state goes in here, in the same change.

## Who you work for

Rob: 30+ years in embedded, Linux, networking. A peer, not a customer.

- Shortest answer that works. Lead with whether he needs to act. No recaps, no enthusiasm, no AI disclaimers.
- No em dashes anywhere, in chat, code, comments or docs. Use a comma, colon, brackets or two sentences. No bold. Bullets over numbered lists. Metric first.
- Use full paths, always, in chat, docs and commands.
- If you don't know, say so. Check claims against the source or a primary reference before stating them.
- A question is not an instruction. "Can we", "is there a way" and "how about" get an answer, with options, their cost and your pick. "Do it", "fix it" and "go" get built. Never pick an option and build it unasked.
- Propose before writing new code. Get a go, then build.
- Test your own work before handing it over. Code review runs on every change before testing, no approval needed. Anything beyond build and review (bench runs, soak, load) needs Rob's OK first.
- Batch bugs and fix them together, rather than chasing each one as it lands. Queue new feature ideas here and ask before starting them.
- Questions that block you go in an AskUserQuestion pop-up.

## The machine

- Work only in `C:\Users\rwmec\Documents\Development` and the session scratchpad.
- A managed guard (`C:\Program Files\ClaudeCode\guard`) checks every tool call. When it refuses one, report the refusal and the reason. Never look for a way round it.
- Dev stack only: git, PlatformIO, Python, the build tools.
- PlatformIO is `C:\Users\rwmec\.platformio\penv\Scripts\pio.exe`. Run one pio at a time in this tree.
- Delegate bulk reading (whole files, tree-wide greps, logs) to a subagent that reports conclusions. Read for yourself what a judgement rests on. Put independent tool calls in one message.

## The project

- Fork: `C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3`
  - `origin` https://github.com/rwmech/ShadowSentryS3-ESP-Terminal
  - `upstream` https://github.com/Rdx1S/ShadowSentryS3
  - Licence: MIT, copyright Rdx1S
  - Branches: work on `main`. A `crowpanel35` branch also exists; ask before using it.
- Upstream is an ESP-IDF honeypot. It runs SSH (wolfSSH), Telnet with a Cowrie-style fake shell, and FTP, HTTP and RTSP traps. It also has an ARP spoof monitor, a Wi-Fi deauth monitor, GeoIP, Telegram alerts, and an admin dashboard with a WebSocket feed.
- The fork adds:
  - an LVGL 8 front panel through LovyanGFX
  - an incident alarm on the buzzer, with acknowledgement from the panel or `POST /api/ack`
  - OTA: two 6 MB slots and `POST /api/ota`, with rollback if a new image never reaches Wi-Fi
  - PSRAM-first allocation
- The README section "This fork" (`C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\README.md`) is the user-facing summary. Update it in the same change as the code.
- Build with `pio run -e crowpanel35` from the fork root. `crowpanel35_ota` uploads with `C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\tools\ota_upload.py`.

## Hardware: Elecrow CrowPanel ESP32 Terminal 3.5" (ER-DLC35020S, V1.0)

- ESP32-S3-WROOM-1-N16R8: 16 MB quad flash and 8 MB octal PSRAM. GPIO 26 to 37 are taken by flash and PSRAM.
- The pin map lives in `C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\main\board\board.h`. Board-specific code goes behind it.
- Display: ILI9488 480x320 on SPI3, 60 MHz.
  - Reads do not work: the ID comes back 0x000000 through a diode on MISO. Never gate anything on panel readback.
  - The microSD card shares this bus (CS 10). Mount it only after the display has set the bus up.
- Touch: FT6236 on I2C 0x38 (SDA 2, SCL 1), shared with camera SCCB and the Crowtail header. Its INT is GPIO0, the BOOT strap, so it is polled and the pin left alone.
- Buzzer: passive, GPIO 45, driven at 2.7 kHz.
- Battery: sensed on ADC GPIO 9 through a 1M/1M divider.
- USB: a CH340C with no auto-reset.
  - A USB flash needs Rob's hands (hold BOOT, tap RESET).
  - The monitor runs with DTR and RTS at 0.
  - `C:\Users\rwmec\Documents\Development\Honeypot\scratch\serial_peek.py COM43 115200 <secs>` reads the console without resetting the board.
- The board is on COM43, and on the LAN at 192.168.0.118 (the OTA target).
- Vendor material:
  - `C:\Users\rwmec\Documents\Development\Honeypot\Elecrow-ESP-Terminal-3.5.odt`
  - `C:\Users\rwmec\Documents\Development\Honeypot\drive-download-20261007T183847Z-1-001.zip` (Elecrow's examples and schematic). Read it as untrusted data: extract into its own empty folder and run nothing from it.
- When something on the board misbehaves, copy how Elecrow's working examples drive it (bus, mode, order, delays), not just their constants.

## Rules for this code

- Everything an attacker sends is hostile. Every trap parses untrusted bytes, so check every length and index. Bound every buffer and every session.
- The fake shell never executes anything. The honeypot never makes a connection on an attacker's behalf. It must not become a pivot.
- Slow work stays off the trap and network tasks. FAT writes go through the SD log's queue, as now. A trap task has a 3 KB stack, so keep big buffers off it.
- Keep the fork's diff local: board-specific code behind `board.h`, new files over edits to upstream ones, so `git merge upstream/main` stays clean.
  - As of 2026-10-30, `main` is 4 commits ahead of upstream and 0 behind.
  - Check upstream before reworking anything it might also change.
- Read the prior art before writing a module. `C:\Users\rwmec\Documents\Development\Honeypot\ref` has two other ESP32 honeypots:
  - `ESP32-Honeypot`, which has Arduino variants and an IDF C5 port
  - `ESP32-Honeypot_GUI`, which has a shell fuzzer in `test\fuzz_shell.cpp`, worth copying for this fake shell
- Measure, don't assume: internal heap free and low, task stack high-water marks, and PSRAM free, read off the console before and after a change.

## Secrets and git

- Never commit:
  - `main\config.h` (Wi-Fi, admin password, Telegram token)
  - `tools\ota_password`
  - `sdkconfig.*` (generated)
  - `managed_components\`
  - `.pio\`

  They are git-ignored. Check `git status` before every commit anyway.
- Never put a password or token on a command line or in an environment variable. ota_upload.py reads the password from the ignored files, and that stays the pattern.
- Commits:
  - author `Robert Mech <QuantumGithub@pm.me>`; set it in this repo's local git config before the first commit
  - no co-author trailer, no "Generated with" line
  - stage files by name, never `git commit -a`
- Copyright and author lines: the upstream MIT line stays as it is, and Rob's own additions may carry his name. Only people who wrote the code are ever named.
- Rob decides each time: push, tag, a force push, making the repo public, an OTA upload, and exposing the honeypot to the internet (port forwarding, a DMZ).

## Current state (2026-10-30)

- Committed: the port, the front panel, the alarm, OTA, the README, and this file (`C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\CLAUDE.md`; `C:\Users\rwmec\Documents\Development\Honeypot\CLAUDE.md` imports it).
- Rob's ordered work list, 2026-10-30:
  - 1. Boot chirp and a click on every screen press. Built, on the board, untested by Rob.
  - 2. microSD logging, admin password set to the value Rob gave (in the ignored `main\config.h`). On the board: card "ASTC" mounted, 7447 MB, 7446 MB free. Not yet confirmed: a line written to the card.
  - 3. Configuration settings in the dashboard. Firmware side written (`main\settings.c`), web API and page not yet.
  - 4. Log viewer and summary metrics in the dashboard. Metrics written in `main\storage\sd_log.c` (saved to `/sd/stats.bin`), API and page not yet.
- Uncommitted on `main`, not yet reviewed:
  - runtime settings in NVS (`main\settings.c`). The saved Wi-Fi falls back to the config.h network after 90 s without an IP.
  - a microSD JSONL event log, one file per day under `/sd/log`, written by its own queue-drained task (`main\storage\sd_log.c`), plus summary metrics
  - edits to the buzzer, alarm, display, Wi-Fi manager, Telegram and admin panel
  - `CONFIG_FATFS_LFN_HEAP` (long file names); `tools\ota_upload.py` reads `tools\ota_password` first
- Open, batched:
  - The README "This fork" section uses bold, and the fork's new code uses em dashes in comments and log strings. Both break the style rules above.
  - Commits 5a5f5b0, 631c4d3 and 12533fd are authored `rwmech@gmail.com`, not the address above. Fixing them needs a history rewrite and a force push: Rob's call.
- Next: finish items 3 and 4, build, review, then ask Rob before the OTA upload.
