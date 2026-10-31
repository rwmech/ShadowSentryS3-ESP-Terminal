cmake_minimum_required(VERSION 3.16)

# ── IDF_PATH guard ────────────────────────────────────────────────────────────
# Catches the most common mistake: running cmake before sourcing export.sh
if(NOT DEFINED ENV{IDF_PATH})
    message(FATAL_ERROR
        "\n"
        "  IDF_PATH is not set.\n"
        "  Activate ESP-IDF first:\n"
        "\n"
        "    . ~/esp/esp-idf/export.sh\n"
        "\n"
        "  Then re-run:  idf.py build\n")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# ── ESP-IDF version check ─────────────────────────────────────────────────────
# esp_netif_sntp_init() and WPA3 SAE PWE support require ESP-IDF v5.2 or later.
# IDF_VERSION is set by project.cmake; may be empty on non-git installations
# (e.g. PlatformIO package manager) — skip the check in that case.
if(IDF_VERSION AND IDF_VERSION VERSION_LESS "5.2.0")
    message(FATAL_ERROR
        "\n"
        "  ShadowSentry S3 requires ESP-IDF v5.2.0 or later.\n"
        "  Detected version: ${IDF_VERSION}\n"
        "\n"
        "  Update your ESP-IDF installation:\n"
        "    cd ~/esp/esp-idf && git checkout v5.2.1 && ./install.sh esp32s3\n")
endif()

# ── Project ───────────────────────────────────────────────────────────────────
project(shadow_sentry_s3)

# ── lwIP IPv4 input hook (main/detect) ────────────────────────────────────────
# IDF 5.4 has no Kconfig switch for LWIP_HOOK_IP4_INPUT. Its lwipopts.h makes
# lwip_default_hooks.h the hook file, and that includes ESP_IDF_LWIP_HOOK_FILENAME
# when defined: define it for the lwip target only, as IDF's
# examples/network/vlan_support does. The hook itself is in main/detect/detect.c.
idf_component_get_property(lwip lwip COMPONENT_LIB)
target_include_directories(${lwip} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/main/detect")
target_compile_definitions(${lwip} PRIVATE "ESP_IDF_LWIP_HOOK_FILENAME=\"ss_lwip_hooks.h\"")
