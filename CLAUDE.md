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
  - a startup melody (the opening of Grieg's "In the Hall of the Mountain King", `main\alarm\melody.c`) and a touch click on the buzzer
  - runtime settings in NVS, edited from the dashboard's Settings tab
  - a microSD JSONL event log with summary metrics, shown on the dashboard's Logs tab
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
  - As of 2026-10-30, `main` is 9 commits ahead of upstream and 0 behind (5 ahead of `origin/main`, not pushed).
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

## Current state (2026-10-31)

- Committed: the port, the front panel, the alarm, OTA, the README, and this file (`C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\CLAUDE.md`; `C:\Users\rwmec\Documents\Development\Honeypot\CLAUDE.md` imports it).
- Rob's ordered work list, 2026-10-30, all committed on `main` in f3d4f88:
  - 1. Boot sound and a click on every screen press. Untested by Rob.
  - 2. microSD logging, admin password set to the value Rob gave (in the ignored `main\config.h`).
  - 3. Configuration settings in the dashboard: Settings tab, `GET`/`POST /api/settings`, `POST /api/reboot`, `POST /api/buzzer/test`.
  - 4. Log viewer and summary metrics in the dashboard: Logs tab, `GET /api/summary`, `GET /api/logs`, `GET /api/logs/file`.
- What f3d4f88 holds:
  - runtime settings in NVS (`main\settings.c`): a live copy (running) and a saved copy (next boot), so a second save before the reboot keeps the first. The saved Wi-Fi falls back to the config.h network after 90 s without an IP.
  - a microSD JSONL event log, one file per day under `/sd/log`, written by its own queue-drained task (`main\storage\sd_log.c`), plus summary metrics in `/sd/stats.bin`, flushed before a reboot or OTA
  - the fork's web routes in `main\admin\api_ext.c`, hooked from `handle_client` in `main\admin\admin_panel.c`; Dashboard / Logs / Settings tabs in `main\index.html`
  - CSRF guard: every POST, upstream's included, needs an `X-ShadowSentry` header. The dashboard and `tools\ota_upload.py` send it. An older `ota_upload.py` will get 403 from this firmware on.
  - edits to the buzzer (`buzzer_test`), alarm, display, Wi-Fi manager, Telegram, main and admin panel
  - `CONFIG_FATFS_LFN_HEAP` (long file names); `tools\ota_upload.py` reads `tools\ota_password` first. After changing the admin password on the Settings page, put it in `tools\ota_password`.
- Lanes, 2026-10-30: the dev lane worked on `main` (items 1 to 4 and style fixes, f3d4f88). The startup-melody lane worked on `lane/startup-melody` (4749d3c, branched from 5b7c3b5, worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\startup-melody`, now removed; the branch is kept).
- Merged `lane/startup-melody` into `main` with `--no-ff`. The boot sound is now the 12-note opening of "In the Hall of the Mountain King" (`main\alarm\melody.c`, about 1.8 s) instead of the two-tone chirp. `buzzer_boot()` plays it under the buzzer mutex and still honours the boot sound setting (NVS key `boot_chirp`, kept so saved settings survive). `app_main` runs it from a short-lived task (`melody`, 3 KB stack, priority 1) right after `alarm_init()`, so boot does not wait. The dashboard label is now "Boot sound".
- Open, batched:
  - Upstream cosmetic bug, `main\wifi_manager.c` line 174: "IP acquired" prints the gateway as the mask, because `ip4addr_ntoa()` returns one static buffer and is called twice in one log call. Fix in upstream's file or leave; Rob's call.
  - Commits 5a5f5b0, 631c4d3 and 12533fd are authored `rwmech@gmail.com`, not the address above. Fixing them needs a history rewrite and a force push: Rob's call.
- On the board, 2026-10-30, by OTA (Rob's go): 1cb2e82 (the merge f8bcb60 plus a buzzer fix: stay disabled if the mutex cannot be created), 1780160 bytes into `ota_0`. First boot clean: no panic or reboot, SETTINGS loaded, microSD "ASTC" mounted (7447 MB, 7446 MB free), IP 192.168.0.118 at 2.7 s, image confirmed after Wi-Fi, internal heap free 299351 B at boot and 56707 B after "All tasks spawned" (total 8278332 B), melody task stack high-water 2304 B of 3072. Over HTTP: `/api/summary` shows the card mounted and 1 line written, `/api/logs` lists `2026-10-30.jsonl` (110 B), so a line on the card is confirmed.
- Camera lane, 2026-10-31 (`lane/camera`, worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\camera`, from 022634e; Rob's request: a photo of whoever presses ACK or CLEAR, on the SD, the dashboard and the Discord post). Built, not yet on the board:
  - `espressif/esp32-camera` 2.1.8. Its `sccb-ng.c` (chosen by `CONFIG_SCCB_HARDWARE_I2C_DRIVER_NEW`, IDF 5.4 and up) is built on `i2c_master`. With `pin_sccb_sda = -1` and `sccb_i2c_port = 0` it takes the bus touch created, through `i2c_master_get_bus_handle()`, and only adds a 0x30 device to it. `display_i2c_bus()` (`main\ui\display.cpp`) tells the camera task when that bus exists. nm on the ELF shows no `i2c_driver_install`, `i2c_param_config` or `check_i2c_driver_conflict`, so no boot-loop.
  - `main\camera\cam.c`: Elecrow A-Camera settings (XCLK 20 MHz, JPEG quality 10, one frame buffer, vflip 0, hmirror 1, brightness 0, saturation 1), but JPEG at VGA instead of their RGB565 QVGA. 96 KB frame buffer in PSRAM, `CAMERA_GRAB_WHEN_EMPTY`; each snapshot returns the stale frame and takes a fresh one. Driver task and ours on Core 1. No sensor: logged, task deleted, `cam_snap()` a no-op.
  - Internal RAM, static: 50508 B before, 54092 B after (+3.5 KB: the OV2640 tables and a 2 KB SCCB device table). Every other sensor driver is off in `sdkconfig.defaults`; with them on it was +12 KB, because their register tables are `DRAM_ATTR`. At run time, in JPEG mode, the driver also takes a fixed 16 KB DMA bounce buffer, its 4 KB task and our 4 KB task, all internal: about 25 KB in all, against 56707 B free today. `CONFIG_CAMERA_PSRAM_DMA` would move the 16 KB to PSRAM; untested, not enabled. `cam.c` logs internal free before and after `esp_camera_init()`, but Wi-Fi starts in parallel, so the "All tasks spawned" line is the number to compare.
  - The camera API is `cam_snap_init()`, not `cam_init()`: esp32-camera's `cam_hal.c` already exports `cam_init`, `cam_start` and `cam_config`.
  - SD: `sd_log_write_file()` (the writer task writes `path.tmp`, renames it, frees the PSRAM buffer) and `sd_log_snap()` (a `snap` JSONL line). Routes `GET /api/snap/last` and `/api/snap/last.json` in `main\admin\api_cam.c`; the dashboard card is one block in `main\index.html`.
  - For the merge: call `cam_snap("ack")` and `cam_snap("clear")` from the buttons' `LV_EVENT_PRESSED` handlers in `main\ui\ui.c` (not wired on this branch). Discord: in the discord task, `cam_wait_idle(1500)` then `cam_last_dup()`, check `meta.action` and `meta.ts`, and post multipart/form-data with `payload_json` plus `files[0]`.
  - To check on the board: the camera probe and test-frame log lines, internal heap after "All tasks spawned" against 56707 B, and touch still working while the camera streams.
- Next, on the board: the Settings save and reboot path, the Logs page in a browser, the Wi-Fi fallback, and Rob's ear on the boot sound and click.
