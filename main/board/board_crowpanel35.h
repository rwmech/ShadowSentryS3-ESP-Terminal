#pragma once

/*
 * Elecrow CrowPanel ESP32 Terminal 3.5" (ER-DLC35020S), hardware V1.0
 *
 * ESP32-S3-WROOM-1-N16R8 (16 MB quad flash, 8 MB octal PSRAM; GPIO 26-37 are
 * spent on flash/PSRAM). Pins from Elecrow's V1.0 schematic and their working
 * Arduino examples (LVGL_SPI_, A-BUZZER, A-TOUCH, A-Camera).
 *
 * Display and microSD share one SPI bus (12/13/14) with separate chip selects.
 * Touch, camera SCCB and the Crowtail I2C header share one I2C bus (2/1).
 *
 * Included by board.h only (BOARD_CROWPANEL35).
 */

// The board's name on the panel's SUBSYS screen (upper case, ASCII)
#define BOARD_NAME          "ELECROW CROWPANEL ESP32-S3 3.5 IN"

// ── ILI9488 480x320 over SPI (SPI3_HOST) ──────────────────────────────────────
#define BOARD_LCD_SCLK      12
#define BOARD_LCD_MOSI      13
#define BOARD_LCD_MISO      14
#define BOARD_LCD_CS        3
#define BOARD_LCD_DC        42
#define BOARD_LCD_RST       (-1)    // tied to module EN
#define BOARD_LCD_BL        46      // S8050 low-side switch, active high
#define BOARD_LCD_HRES      480     // landscape, rotation 3 (Elecrow default)
#define BOARD_LCD_VRES      320
// Elecrow example freq_write; confirmed on the bench (self-test red fill shows).
// Reads do NOT work: MISO reaches the panel through a 1N4148 and the ID reads
// 0x000000, so never gate anything on panel readback.
#define BOARD_LCD_SPI_HZ    60000000
#define BOARD_BACKLIGHT_DIM 1       // LEDC PWM on BOARD_LCD_BL

// ── microSD (shares the LCD SPI bus) ──────────────────────────────────────────
#define BOARD_SD_SPI_HOST       SPI3_HOST
#define BOARD_SD_MOSI           BOARD_LCD_MOSI
#define BOARD_SD_MISO           BOARD_LCD_MISO
#define BOARD_SD_SCLK           BOARD_LCD_SCLK
#define BOARD_SD_CS             10
#define BOARD_SD_SHARES_LCD_BUS 1   // mount only after the display set the bus up

// ── FT6236 capacitive touch, I2C 0x38 ─────────────────────────────────────────
// INT is on GPIO0 (BOOT strap). It is left unconfigured and the controller is
// polled, so a touch held during reset can't be driven into download mode.
#define BOARD_TOUCH_SDA     2
#define BOARD_TOUCH_SCL     1
#define BOARD_TOUCH_ADDR    0x38
#define BOARD_I2C_PORT      0       // I2C_NUM_0, new i2c_master driver only

// ── OV2640 camera on J5 (24-pin FPC), DVP 8-bit ───────────────────────────────
// From Elecrow's A-Camera example (camera_pins.h, CAMERA_MODEL_ELECROW) and the
// V1.0 schematic. PWDN and RESET are tied off (no power FET), so the sensor is
// powered whenever the board is. SCCB is the touch I2C bus above (SDA 2, SCL 1),
// address 0x30: the camera attaches to the bus touch creates, never a second one.
#define BOARD_HAS_CAMERA    1
#define BOARD_CAM_XCLK      7
#define BOARD_CAM_PCLK      17
#define BOARD_CAM_VSYNC     4
#define BOARD_CAM_HREF      5
#define BOARD_CAM_D0        8
#define BOARD_CAM_D1        47
#define BOARD_CAM_D2        48
#define BOARD_CAM_D3        21
#define BOARD_CAM_D4        18
#define BOARD_CAM_D5        16
#define BOARD_CAM_D6        15
#define BOARD_CAM_D7        6
#define BOARD_CAM_PWDN      (-1)
#define BOARD_CAM_RESET     (-1)
#define BOARD_CAM_XCLK_HZ   20000000    // Elecrow example; LCD_CAM divides 160 MHz by 8

// ── Passive buzzer (MLT-8530 via S9013), needs a driven tone ──────────────────
#define BOARD_BUZZER_GPIO   45
#define BOARD_BUZZER_HZ     2700    // MLT-8530 resonant frequency
#define BOARD_BUZZER_INVERT 0       // high drives the transistor; idles low
#define BOARD_BUZZER_LOW_MAX_US 0   // no cap on the duty

// ── Battery sense: VBAT through 1M/1M divider on ADC1_CH8 ─────────────────────
#define BOARD_VBAT_ADC      9

// ── Front panel styles ────────────────────────────────────────────────────────
#define BOARD_PANEL_DASHBOARD 1     // the dashboard (ui.c) as well as LCARS
#define BOARD_PANEL_STYLE     1     // the default panel_style: LCARS
