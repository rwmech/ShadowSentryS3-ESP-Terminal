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
  - an LVGL 8 front panel through LovyanGFX: a status and control layout in a bright palette, a running light that shows the UI is alive, and flashing side bars (police pattern) with full backlight while an incident is unacknowledged
  - an incident alarm on the buzzer (a 3.2 s siren, repeated every minute until acknowledged), with acknowledgement from the panel or `POST /api/ack` and re-arm from the panel or `POST /api/alarm/clear`
  - OTA: two 6 MB slots and `POST /api/ota`, with rollback if a new image never reaches Wi-Fi
  - PSRAM-first allocation
  - a startup melody (the opening of Grieg's "In the Hall of the Mountain King", `main\alarm\melody.c`) and a touch click on the buzzer
  - runtime settings in NVS, edited from the dashboard's Settings tab
  - a microSD JSONL event log with summary metrics, shown on the dashboard's Logs tab
  - a heartbeat on the dashboard's header shield, one soft pulse per answered status poll
  - Discord webhook alerts (`main\admin\discord.c`): incident embeds (opened, reminder, acknowledged, closed) and a deduplicated event log
  - an OV2640 photo of whoever presses ACKNOWLEDGE or RE-ARM on the panel (`main\camera\cam.c`), saved to the card and shown on the dashboard
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
  - As of 2026-10-31, `main` is 20 commits ahead of upstream and 0 behind (11 ahead of `origin/main`, not pushed).
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
- Rob decides each time: push, tag, a force push, making the repo public, and exposing the honeypot to the internet (port forwarding, a DMZ).
- Standing authority, Rob, 2026-10-31, while the board is non-production: "You can modify psram all u want and can load to the device anytime its considered non production at this point."
  - OTA uploads to the board no longer need his say-so each time, once a build has built and been reviewed clean (usual serial capture and checks).
  - PSRAM tuning (moving buffers, DMA and caches to or from PSRAM, related sdkconfig options) is allowed; measure internal heap before and after and keep the better one.
- Standing rule, Rob, 2026-10-31: "every push doesnt need crazy testing, fix forward, it should be code review quickly and move to push". Per merge: a quick review of the merge diff, an incremental `crowpanel35_ota` build (delete the generated sdkconfigs only when `sdkconfig.defaults` changed), the OTA, and one look at the serial capture for a panic or reboot loop and the "All tasks spawned" heap line. No HTTP probing or long captures. If something is wrong on the board, fix it forward in the next merge; never roll back.
- Standing authority, Rob, 2026-10-31: "if u need to repartition anything, im fine there too, this device is for this purpose only." Repartitioning is allowed. A partition-table change cannot ship over OTA: it needs a USB flash, which needs Rob's hands (hold BOOT, tap RESET). Ask Rob for that moment; never attempt it unannounced.

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
- Merged `lane/startup-melody` into `main` with `--no-ff`. The boot sound is now the 12-note opening of "In the Hall of the Mountain King" (`main\alarm\melody.c`, then about 1.8 s, 3.56 s since alarm-ux) instead of the two-tone chirp. `buzzer_boot()` plays it under the buzzer mutex and still honours the boot sound setting (NVS key `boot_chirp`, kept so saved settings survive). `app_main` runs it from a short-lived task (`melody`, 3 KB stack, priority 1) right after `alarm_init()`, so boot does not wait. The dashboard label is now "Boot sound".
- Lane `lane/discord`, 2026-10-31 (worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\discord`, from 022634e), Rob's approved option "Incidents, via Settings" plus his scope change (reminders, deduplicated event log):
  - `main\admin\discord.c` / `.h`: one task (`discord`, Core 1, priority 3, 6144 B stack, high-water logged after the first post) and one HTTPS sender, paced 1 s between posts, honouring 429 `retry_after` / `Retry-After` and `X-RateLimit-Remaining` 0, 3 retries on transport errors and 5xx, waits for Wi-Fi. Body, content and key table in PSRAM; event queue 96 deep in PSRAM (`xQueueCreateWithCaps`).
  - Incident embeds from an alarm listener (transitions only, as `sd_log.c`): opened (red; first event's username and payload from a ring of recent events), acknowledged (amber; "dashboard" when `POST /api/ack` called `discord_note_dashboard_ack()` within 5 s, otherwise "front panel"), closed (green; also when a new source supersedes an acked incident), and a reminder (orange) every `alarm_remind_s` (min 30 s) while unacknowledged, timed by the Discord task, not alarm.c. An incident still ACTIVE at boot gets a reminder at once.
  - Event log from a log_store listener: key = source IP, type, summary (shell first token, credential user:pass, HTTP method and path, else payload first 40). Batches every 15 s (early at about 1800 characters, at most every 5 s), 32 lines per post, code block, `+N more` carried to the next batch; a posted key waits 300 s and then shows only the new count; idle keys dropped after 600 s; 64 keys.
  - Safety: `allowed_mentions` parse [] on every post, attacker text cut to printable ASCII, backticks replaced, `@` followed by a zero-width space, everything JSON-escaped, bounded builder. The URL is never logged ("Discord: posted" / "Discord: failed status N") or returned.
  - Settings: `discord_webhook[160]` (NVS `dc_hook`, secret, default `DISCORD_WEBHOOK_URL` from config.h, "" if undefined) and `discord_log_events` (NVS `dc_log`, default on). Live, no reboot. Valid: empty, or `https://discord.com/api/webhooks/` / `https://discordapp.com/api/webhooks/` followed by letters, digits and `-_/?=&.`. `get_str` temp buffer raised from 80 to 168.
  - API: `GET /api/settings` adds `discord_webhook_set`, `discord_enabled`, `discord_log_events`; `POST /api/settings` takes `discord_webhook` (blank = unchanged), `discord_webhook_clear`, `discord_log_events`; `POST /api/discord/test` (queues, 409 without a webhook) and `GET /api/discord/status` (the page polls it for the test result).
  - Merged into `main` with `--no-ff` after alarm-ux (commit 7e93e17; only CLAUDE.md conflicted, both sides kept). Merge-lane fixes: `ALARM_MAX_LISTENERS` raised from 4 to 6 (UI, WebSocket, SD log and Discord use four) and a full table now logs an error instead of dropping silently; a re-arm (`alarm_clear()`, ACKED to IDLE) posts "Closed: re-armed." instead of the quiet-time text, through `alarm_closed_by_rearm()`, which the Discord listener reads on the alarm task. `discord_note_dashboard_ack()` still runs on `POST /api/ack` in `main\admin\admin_panel.c`. log_store listeners: 5 of 6 used (WebSocket, SD log, alarm, UI, Discord).
- Open, batched:
  - Upstream cosmetic bug, `main\wifi_manager.c` line 174: "IP acquired" prints the gateway as the mask, because `ip4addr_ntoa()` returns one static buffer and is called twice in one log call. Fix in upstream's file or leave; Rob's call.
  - Commits 5a5f5b0, 631c4d3 and 12533fd are authored `rwmech@gmail.com`, not the address above. Fixing them needs a history rewrite and a force push: Rob's call.
  - Telegram sends alerts while it is off. SETTINGS logs "Telegram off" (placeholder token and chat id), yet on incident #4 (2026-10-31) the Telegram task tried each alert 3 times against api.telegram.org and got 404, which costs two TLS handshakes a second at the worst moment. The alert path in `main\admin\telegram.c` needs a `settings_telegram_enabled()` gate.
- On the board, 2026-10-30, by OTA (Rob's go): 1cb2e82 (the merge f8bcb60 plus a buzzer fix: stay disabled if the mutex cannot be created), 1780160 bytes into `ota_0`. First boot clean: no panic or reboot, SETTINGS loaded, microSD "ASTC" mounted (7447 MB, 7446 MB free), IP 192.168.0.118 at 2.7 s, image confirmed after Wi-Fi, internal heap free 299351 B at boot and 56707 B after "All tasks spawned" (total 8278332 B), melody task stack high-water 2304 B of 3072. Over HTTP: `/api/summary` shows the card mounted and 1 line written, `/api/logs` lists `2026-10-30.jsonl` (110 B), so a line on the card is confirmed.
- Lane alarm-ux, 2026-10-31 (branch `lane/alarm-ux`, worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\alarm-ux`, from 022634e, commit 0fd27d9), Rob's requests of 2026-10-31. Merged into `main` with `--no-ff` by the merge lane (no conflicts), together with the dashboard heartbeat below.
  - Boot tune at march tempo: 260 ms per note (210 ms sounding, `MELODY_GAP_MS` 50), final B 700 ms, 3560 ms in all. The old 100 ms notes played it about 2.5x fast.
  - Siren (`main\alarm\buzzer.c`): 2300 to 3100 Hz and back in 50 Hz steps of 25 ms, 800 ms a cycle, 4 cycles, 3.2 s, 50 % duty, under the buzzer mutex, timer back to `BOARD_BUZZER_HZ` before the unlock. It replaces the three beeps (incident), the single reminder beep and the test pattern.
  - The siren plays on a new `buzzer` task (3 KB stack, priority 3, core 1) fed by an 8-deep command queue (SIREN, TEST, STOP). `buzzer_alarm()`, `buzzer_remind()` and `buzzer_test()` return at once, so the alarm task never blocks 3 s with its 32-deep event queue filling (a scan would overflow it and could drop an ACK), and `POST /api/buzzer/test` answers at once. `buzzer_stop()` (on acknowledge) cuts a siren short within 25 ms. If the task cannot be created the siren plays on the caller, as before.
  - Reminder: the full siren every `ALARM_REMIND_S`, default now 60 s (`main\config.h.example`, `main\settings.c`, `main\alarm\alarm.h`; validation is 60..3600). A remind_s already saved in NVS from the Settings page wins over the default.
  - Re-arm: `alarm_clear()` takes an ACKED incident to IDLE at once (persisted, listeners notified); ignored in any other state. Nothing is deleted: the flash ring, SD log, metrics and `s_info` (the panel's last-incident summary) stay. `POST /api/alarm/clear` returns 409 "acknowledge first" while ACTIVE. Dashboard banner now shows for ACKED too, with Re-arm in place of Acknowledge. The SD log records the re-arm as a "closed" alarm line, like a quiet-time close.
  - Panel redesign (`main\ui\ui.c`): incident card (ACKNOWLEDGE hold while ACTIVE, RE-ARM hold 1.5 s while ACKED), key figures row (events, distinct sources from the flash ring plus new events, SD free, RSSI), last 3 events. Bright palette: background #0b1220, cards #1e293b with 2 px state borders, text white and #cbd5e1, accents #22ff9a / #ffc400 / #ff3b3b, pill text dark on the fill. Fonts stay 12/14/20/28 (28 for headline and source); larger ones would need `sdkconfig.defaults` changes and a fresh sdkconfig.
  - Strobe: while ACTIVE the overlay background alternates #e00000 and black every 500 ms (an lv_timer on the UI task); labels and the white button keep their colours. `display_set_backlight_override(bool)` in `main\ui\display.cpp` forces the backlight to 100 % and restores `settings_get()->brightness` on ACKED or IDLE; the override and the duty write share a mutex with the settings-change callback.
  - To measure on the board: the UI logs internal heap before and after building the panel ("Panel built, internal heap ..."); the `buzzer` task logs its stack high-water after the first siren ("First siren done, stack high-water ...").
- Dashboard heartbeat (`main\index.html`, Rob 2026-10-31, from `docs\backlog.md`): the header `.logo-mark` shield pulses once (scale 1.07 and a stronger green glow, 0.9 s ease-in-out) on each answered `/api/status` poll (every 5 s). A poll that errors, returns non-2xx or takes over 4 s is a miss; after two misses in a row the shield fades to grey (grayscale, 45 % opacity) until a poll is answered. No colour flashing; `prefers-reduced-motion` drops the pulse. The ACTIVE pill is unchanged.
- On the board, 2026-10-31, by OTA (Rob's go): f843faf (alarm-ux merge 1522ded plus the heartbeat), 1775264 bytes into `ota_1`. Boot clean: SETTINGS loaded, microSD "ASTC" mounted (summary metrics restored, 29 events), internal heap 298703 B at boot, panel build 151627 B before and 143675 B after (7952 B for the panel), 50547 B after "All tasks spawned", melody task stack high-water 2168 B of 3072 (melody done at 4.8 s). `/api/settings` shows `alarm_remind_s` 60. No incident, so no siren yet and no buzzer task high-water. About 11 s into the first boot the board took one `rst:0x1 (POWERON)` with no panic, abort or brownout line before it, and came back on `ota_1` (so the image had been confirmed). It was stable for the rest of the 300 s capture. Most likely an external power cycle; worth asking Rob whether he touched the power.
- On the board, 2026-10-31, by OTA (Rob's go, "OTA + test post"): 2daff51 (discord merge 58ec1cf plus the listener and re-arm fixes), 1788432 bytes into `ota_0`. Boot clean, no reset other than the OTA restart in 300 s. "Discord alerts: enabled", "DISCORD: Ready (webhook set, event log on)". Internal heap 297863 B at boot, panel 150779 B before and 144395 B after, 44119 B after "All tasks spawned" (the baseline for the camera). One `POST /api/discord/test`: test_ok true, test_status 204, in 3 s; Discord task stack high-water 2372 B of 6144. The webhook URL never appears in the log. A browser at 192.168.0.75 on the port 80 trap then opened incident #4: the siren played (buzzer task high-water 2176 B of 3072) and Discord posted the incident and the event log.
- Camera lane, 2026-10-31 (`lane/camera`, worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\camera`, from 022634e; Rob's request: a photo of whoever presses ACK or CLEAR, on the SD, the dashboard and the Discord post), commit 499177f. Merged into `main` with `--no-ff` after discord (conflicts in admin_panel.c includes, display.h, README and this file: both sides kept):
  - `espressif/esp32-camera` 2.1.8. Its `sccb-ng.c` (chosen by `CONFIG_SCCB_HARDWARE_I2C_DRIVER_NEW`, IDF 5.4 and up) is built on `i2c_master`. With `pin_sccb_sda = -1` and `sccb_i2c_port = 0` it takes the bus touch created, through `i2c_master_get_bus_handle()`, and only adds a 0x30 device to it. `display_i2c_bus()` (`main\ui\display.cpp`) tells the camera task when that bus exists. nm on the ELF shows no `i2c_driver_install`, `i2c_param_config` or `check_i2c_driver_conflict`, so no boot-loop.
  - `main\camera\cam.c`: Elecrow A-Camera settings (XCLK 20 MHz, JPEG quality 10, one frame buffer, vflip 0, hmirror 1, brightness 0, saturation 1), but JPEG at VGA instead of their RGB565 QVGA. 96 KB frame buffer in PSRAM, `CAMERA_GRAB_WHEN_EMPTY`; each snapshot returns the stale frame and takes a fresh one. Driver task and ours on Core 1. No sensor: logged, task deleted, `cam_snap()` a no-op.
  - Internal RAM, static: 50508 B before, 54092 B after (+3.5 KB: the OV2640 tables and a 2 KB SCCB device table). Every other sensor driver is off in `sdkconfig.defaults`; with them on it was +12 KB, because their register tables are `DRAM_ATTR`. At run time, in JPEG mode, the driver also takes a fixed 16 KB DMA bounce buffer, its 4 KB task and our 4 KB task, all internal: about 25 KB in all, against 56707 B free on 2026-10-30 and 44119 B after "All tasks spawned" on the discord build (2026-10-31). `CONFIG_CAMERA_PSRAM_DMA` would move the 16 KB to PSRAM; untested, not enabled. `cam.c` logs internal free before and after `esp_camera_init()`, but Wi-Fi starts in parallel, so the "All tasks spawned" line is the number to compare.
  - The camera API is `cam_snap_init()`, not `cam_init()`: esp32-camera's `cam_hal.c` already exports `cam_init`, `cam_start` and `cam_config`.
  - SD: `sd_log_write_file()` (the writer task writes `path.tmp`, renames it, frees the PSRAM buffer) and `sd_log_snap()` (a `snap` JSONL line). Routes `GET /api/snap/last` and `/api/snap/last.json` in `main\admin\api_cam.c`; the dashboard card is one block in `main\index.html`.
  - Wired in the merge: `cam_snap("ack")` in `ack_press_start_cb` and `cam_snap("clear")` in `rearm_press_start_cb`, the LV_EVENT_PRESSED handlers of the two buttons on the incident card (panel-polish removed the strobing overlay and its button), in `main\ui\ui.c`: the press start, not the hold completion. The dashboard's camera card wraps `renderAlarm`, which still exists under that name after alarm-ux. The Logs page shows `snap` lines (logRow branch, and "snap" in the kind filter).
  - Still open (backlog): attach the photo to Discord's acknowledged and re-armed posts. In the discord task, `cam_wait_idle(1500)` then `cam_last_dup()`, check `meta.action` and `meta.ts`, and post multipart/form-data with `payload_json` plus `files[0]`.
  - On the board, 2026-10-31, by OTA (standing approval): 1d328b1, 1818448 bytes into `ota_1`. Boot clean, no panic or reboot. The sensor probes (OV2640, PID 0x26 VER 0x42, address 0x30, "cam init ok", 96 KB frame buffer in PSRAM, PSRAM DMA off), then the first register write NACKs: "sccb-ng: SCCB_Write Failed addr:0x30, reg:0x37, data:0xc3", "camera: Failed to set frame size", "CAM: no camera (ERROR), snapshots disabled; internal heap free 142487 -> 133907 B". Touch still came up (FT6236). Internal heap after "All tasks spawned": 38675 B, against 44119 B on the discord build, so 5.4 KB less with the camera failed (static tables, plus 8.6 KB the failed init did not give back). Not measured with a working camera, so `CONFIG_CAMERA_PSRAM_DMA` is still off. Fix forward: find why SCCB writes NACK after reads succeed (bus speed, a settle delay after the sensor reset, or touch polling in between), then measure the heap with the camera running.
- Lane panel-polish, 2026-10-31 (branch `lane/panel-polish`, worktree `C:\Users\rwmec\Documents\Development\Honeypot\lanes\panel-polish`, from 5aa4dbe), Rob's requests of 2026-10-31. Not merged, not on the board.
  - Hold to confirm (`main\ui\ui.c`): ACKNOWLEDGE and RE-ARM take a 2 s hold (`HOLD_MS`). LV_EVENT_PRESSED (`ack_press_start_cb`, `rearm_press_start_cb`) starts an lv_anim that widens a fill child of the button over HOLD_MS; its ready callback runs the action (`ack_done`, `rearm_done`) and `buzzer_confirm()`. RELEASED, PRESS_LOST, or a PRESSING point off the button (LVGL's PRESS_LOCK keeps the press otherwise) drains the fill in up to 250 ms with no action. LVGL's long press is no longer used. lane/camera's `cam_snap()` calls go in the two press-start callbacks.
  - `buzzer_confirm()` (`main\alarm\buzzer.c`): CMD_CONFIRM on the buzzer task, two pips (2700 Hz 40 ms, 30 ms gap, 3400 Hz 40 ms) under the mutex with a 0 timeout, so skipped during the boot tune; follows the touch click setting; nothing if there is no buzzer task. `buzzer_stop()` now sends STOP to the front of the queue: `stop_requested()` only peeks the head, and a CONFIRM queued behind the playing siren would have hidden it.
  - Boot tune from the score: Grieg's piano arrangement of Op. 46 No. 4 (The University Society, 1918; Mutopia piece 1888, read from its LilyPond source) marks "Alla marcia molto marcato", crotchet = 138, pp "e sempre staccato". `melody_note_t` gained `slot` (the written value); `ms` is the sounding part. Quaver slot 217 ms, crotchet 435 ms, every staccato note sounds 110 ms; cadence F# quaver, then B held a minim (870 ms). 3693 ms in all. `MELODY_GAP_MS` is gone. The IMSLP orchestral score was not read: its download sits behind a JavaScript bot check, which was not worked around.
  - Layout: armed shows the status bar, the running light, the key figures (y 150) and one muted last-incident line; no card, no event list, no second "ARMED". An incident shows the card (x 44..435, y 33..204: "Incident #N" and age, source in 28 px, type and count, MAC, vendor, first to last, buttons 184 x 56, with a free 184 x 56 slot at the bottom right for IGNORE SOURCE) and the incident's last 3 events (its source, or since it opened; 20 px rows, 34 px tall). The key figures are hidden during an incident. The pill is 104 x 24 with 20 px text.
  - Running light: 3 px (`RUNLIGHT_H`) at y 28 on the top layer, a 120 px gradient segment (72 px head, 48 px trail), an lv_timer every 33 ms with the position taken from the tick. 2 s sweep green or amber, 0.7 s bounce red during an alarm.
  - Side bars replace the full-screen strobe and its overlay: 40 x 289 px at each edge from y 31, left double-flash red, then right blue (80 on, 60 off, 80 on per side, 250 ms a side), an lv_timer every 10 ms reading the pattern off the tick and recolouring a bar only on a change. Off is the background colour (still opaque), so a flash repaints one bar rectangle. The incident view is inset 44 px each side. Backlight still forced to 100 % while unacknowledged.
  - To read on the board: "UI loop, lv_timer_handler: without the running light ... with it ..." (the first 10 s after the panel is built run with the light paused, the next 10 s with it), and "Side bars: N refreshes in 2000 ms, flush start to done avg ... max ..." 2 s after the bars start (a wrapper on the driver's flush plus LVGL's monitor callback, both set from ui.c). "Panel built, internal heap ..." as before.
- Lanes still in flight, 2026-10-31: `lane/detect-core` (from 5aa4dbe), merged next. `docs\backlog.md` is the TA's backlog, committed as it stands with each merge. Merged lane branches are kept; the alarm-ux worktree is removed, the discord, camera and panel-polish worktrees are left for their lanes.
- Next, on the board: the Settings save and reboot path, the Logs page in a browser, the Wi-Fi fallback, and Rob's ear on the boot sound, click and siren; the panel's look and the strobe.
