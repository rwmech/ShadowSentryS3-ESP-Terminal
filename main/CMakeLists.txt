# ── ShadowSentry S3 — main component ─────────────────────────────────────────
#
# Single ESP-IDF component that contains the entire firmware.
# Source layout:
#
#   main.c                  — app_main(), task spawn
#   wifi_manager.c          — WiFi STA + SNTP
#   honeypot/rtsp_trap.c    — port 554, fake Hikvision camera (Core 0)
#   honeypot/http_trap.c    — port 80,  fake NVR login page  (Core 0)
#   honeypot/telnet_trap.c  — port 23,  fake Ubuntu banner   (Core 0)
#   admin/admin_panel.c     — port 9999, HTTP dashboard       (Core 1)
#   admin/telegram.c        — HTTPS alert sender              (Core 1)
#   storage/log_store.c     — ring buffer + SPIFFS persistence
#
# EMBED_TXTFILES "index.html"
#   CMake embeds the dashboard HTML into the firmware binary and exposes it
#   as two linker symbols accessed in admin_panel.c:
#     extern const uint8_t index_html_start[] asm("_binary_index_html_start");
#     extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
#   The file is embedded as text (null-terminated); use EMBED_FILES for binary.

idf_component_register(
    SRCS
        "main.c"
        "wifi_manager.c"
        "arp_monitor.c"
        "geoip.c"
        "wifi_monitor.c"
        "honeypot/rtsp_trap.c"
        "honeypot/http_trap.c"
        "honeypot/telnet_trap.c"
        "honeypot/fake_shell.c"
        "honeypot/ssh_trap.c"
        "honeypot/ftp_trap.c"
        "admin/admin_panel.c"
        "admin/api_ext.c"
        "admin/ws_server.c"
        "admin/telegram.c"
        "admin/discord.c"
        "admin/notify.c"
        "admin/whatsapp.c"
        "storage/log_store.c"
        "storage/sd_log.c"
        "settings.c"
        "alarm/alarm.c"
        "alarm/buzzer.c"
        "alarm/melody.c"
        "ui/display.cpp"
        "ui/ui.c"
        "camera/cam.c"
        "admin/api_cam.c"
        "detect/detect.c"
        "detect/ignore.c"

    INCLUDE_DIRS
        "."            # config.h, wifi_manager.h
        "honeypot"     # rtsp_trap.h, http_trap.h, telnet_trap.h
        "admin"        # admin_panel.h, telegram.h
        "storage"      # log_store.h
        "board"        # board.h, CrowPanel 3.5" pin map
        "alarm"        # alarm.h, buzzer.h
        "ui"           # display.h, ui.h
        "camera"       # cam.h, OV2640 panel-press snapshots
        "detect"       # detect.h, ignore.h (recon detection, ignore list)

    EMBED_TXTFILES
        "index.html"   # dashboard → _binary_index_html_{start,end}

    REQUIRES
        # Core system
        nvs_flash           # nvs_flash_init() — required by WiFi driver
        esp_wifi            # esp_wifi_*
        esp_netif           # esp_netif_*, esp_netif_sntp_init()
        esp_event           # esp_event_loop_create_default()
        mdns                # managed component espressif/mdns (see idf_component.yml)
                            # — .local name resolution in wifi_manager.c

        # Network stack
        lwip                # BSD sockets (socket/bind/listen/accept/recv/send),
                            # lwip/inet.h, lwip/sockets.h

        # Storage
        spiffs              # esp_vfs_spiffs_register(), SPIFFS on flash
                            # (maps to the "storage" partition in partitions.csv)

        # Crypto / TLS
        mbedtls             # mbedtls_base64_decode() — used by RTSP and admin auth
                            # esp_crt_bundle.h — Mozilla CA bundle for Telegram SSL
        esp-tls             # esp_crt_bundle_attach() — wires cert bundle into
                            # esp_http_client for api.telegram.org validation

        # Timer
        esp_timer           # esp_timer_get_time() — device uptime in /api/status

        # HTTP client
        esp_http_client     # telegram.c — HTTPS POST to Telegram Bot API

        # HTTP server (WebSocket)
        esp_http_server     # ws_server.c — live WebSocket push to the dashboard

        # Front panel and buzzer (LVGL + LovyanGFX come from idf_component.yml)
        driver              # LEDC (buzzer), I2C (touch), GPIO (backlight)

        # OTA
        app_update          # esp_ota_* — POST /api/ota, rollback confirmation

        # microSD log + settings API
        fatfs               # esp_vfs_fat_sdspi_mount, FAT on the card
        sdmmc               # sdmmc_card_t, SD protocol
        json                # cJSON: /api/settings body
)

# wolfSSL ships include/config.h, and PlatformIO's include order lets it shadow
# main/config.h. -iquote dirs are searched before every -I dir, so ours wins
# (joined form: SCons would read a separate path token as a library).
target_compile_options(${COMPONENT_LIB} PRIVATE "-iquote${CMAKE_CURRENT_SOURCE_DIR}")
# GCC 13+ (IDF 5.4) flags fake_shell.c's bounded snprintf as possible truncation;
# the truncation is intended, keep it a warning.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=format-truncation)
