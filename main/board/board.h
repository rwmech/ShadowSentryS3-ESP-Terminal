#pragma once

/*
 * Elecrow CrowPanel ESP32 Terminal 3.5" (ER-DLC35020S), hardware V1.0
 *
 * ESP32-S3-WROOM-1-N16R8 (16 MB quad flash, 8 MB octal PSRAM; GPIO 26-37 are
 * spent on flash/PSRAM). Pins from Elecrow's V1.0 schematic and their working
 * Arduino examples (LVGL_SPI_, A-BUZZER, A-TOUCH).
 *
 * Display and microSD share one SPI bus (12/13/14) with separate chip selects.
 * Touch, camera SCCB and the Crowtail I2C header share one I2C bus (2/1).
 */

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
#define BOARD_LCD_SPI_HZ    60000000  // Elecrow example freq_write

// ── microSD (shares the LCD SPI bus) ──────────────────────────────────────────
#define BOARD_SD_CS         10

// ── FT6236 capacitive touch, I2C 0x38 ─────────────────────────────────────────
// INT is on GPIO0 (BOOT strap). It is left unconfigured and the controller is
// polled, so a touch held during reset can't be driven into download mode.
#define BOARD_TOUCH_SDA     2
#define BOARD_TOUCH_SCL     1
#define BOARD_TOUCH_ADDR    0x38

// ── Passive buzzer (MLT-8530 via S9013), needs a driven tone ──────────────────
#define BOARD_BUZZER        45
#define BOARD_BUZZER_HZ     2700    // MLT-8530 resonant frequency

// ── Battery sense: VBAT through 1M/1M divider on ADC1_CH8 ─────────────────────
#define BOARD_VBAT_ADC      9
