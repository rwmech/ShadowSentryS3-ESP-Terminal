#pragma once

/*
 * Board selection: the hardware abstraction for the front panel, touch,
 * buzzer, camera, battery sense and microSD.
 *
 * Exactly one board is built. Choose it in main/config.h:
 *
 *   #define BOARD_CROWPANEL35     // Elecrow CrowPanel ESP32 Terminal 3.5" (default)
 *   #define BOARD_WAVESHARE43     // Waveshare ESP32-S3-Touch-LCD-4.3B
 *
 * The PlatformIO envs also define it (build_src_flags), so one config.h
 * serves every env; a config.h that names a different board than the env
 * fails the build here. With neither defined, the CrowPanel is built.
 *
 * Every board file defines the same set of BOARD_* names; code outside the
 * board files and the board-specific drivers (ui/display*.c*, camera/cam.c)
 * uses only these:
 *
 *   BOARD_NAME                 the board's name on the SUBSYS screen
 *   BOARD_LCD_HRES, _VRES      the panel in pixels, landscape
 *   BOARD_HAS_CAMERA           1: a camera may be fitted (camera/cam.c)
 *   BOARD_BACKLIGHT_DIM        1: the backlight takes a PWM level, 0: on or off
 *   BOARD_BUZZER_GPIO          passive buzzer pin, -1: none (sounds compiled out)
 *   BOARD_BUZZER_HZ            the buzzer's idle LEDC frequency
 *   BOARD_BUZZER_INVERT        1: the pin idles high, the duty is its low part
 *   BOARD_BUZZER_LOW_MAX_US    > 0: no low part longer than this (duty capped per tone)
 *   BOARD_VBAT_ADC             battery sense ADC pin, -1: none
 *   BOARD_SD_SPI_HOST          SPI host of the microSD
 *   BOARD_SD_MOSI, _MISO, _SCLK, _CS   its pins (CS -1: held selected by the board)
 *   BOARD_SD_SHARES_LCD_BUS    1: the display brings the SD's SPI bus up
 *   BOARD_I2C_PORT             the I2C port touch (and the camera) use
 *   BOARD_PANEL_DASHBOARD      1: the dashboard panel style (ui.c) is offered
 *   BOARD_PANEL_STYLE          the default panel_style (1 LCARS, 2 clan) unless config.h sets DISPLAY_PANEL_STYLE
 */

#include "sdkconfig.h"

// config.h's checks are C11 _Static_assert; display.cpp is C++.
#if defined(__cplusplus) && !defined(_Static_assert)
#define _Static_assert static_assert
#endif
#include "config.h"

#if !defined(BOARD_CROWPANEL35) && !defined(BOARD_WAVESHARE43)
#define BOARD_CROWPANEL35   1
#endif

#if defined(BOARD_CROWPANEL35)
#define BOARD_IS_CROWPANEL35    1
#else
#define BOARD_IS_CROWPANEL35    0
#endif
#if defined(BOARD_WAVESHARE43)
#define BOARD_IS_WAVESHARE43    1
#else
#define BOARD_IS_WAVESHARE43    0
#endif

_Static_assert(BOARD_IS_CROWPANEL35 + BOARD_IS_WAVESHARE43 == 1,
               "Define exactly one of BOARD_CROWPANEL35 and BOARD_WAVESHARE43 "
               "(main/config.h, or the PlatformIO env's build_src_flags)");

#if BOARD_IS_WAVESHARE43
#include "board_waveshare43.h"
#else
#include "board_crowpanel35.h"
#endif

_Static_assert(BOARD_LCD_HRES >= 480 && BOARD_LCD_VRES >= 320,
               "the panel layout needs at least 480 x 320");
_Static_assert(BOARD_BUZZER_GPIO >= -1 && BOARD_BUZZER_GPIO <= 48,
               "BOARD_BUZZER_GPIO must be -1 (none) or a GPIO");
_Static_assert(BOARD_HAS_CAMERA == 0 || BOARD_HAS_CAMERA == 1, "BOARD_HAS_CAMERA must be 0 or 1");

#define BOARD_HAS_BUZZER    (BOARD_BUZZER_GPIO >= 0)
