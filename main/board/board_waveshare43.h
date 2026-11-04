#pragma once

/*
 * Waveshare ESP32-S3-Touch-LCD-4.3B (silkscreen "ESP32-S3-Touch-LCD-4.3-B")
 *
 * ESP32-S3-WROOM-1-N16R8 (16 MB quad flash, 8 MB octal PSRAM; GPIO 26-37 are
 * spent on flash/PSRAM), one USB-C to the chip's own USB-Serial/JTAG.
 * Pins from Waveshare's 4.3B schematic (ESP32-S3-Touch-LCD-4.3B-Sch.pdf) and
 * their working demo (ESP32-S3-Touch-LCD-4.3B-BOX-Demo.zip: ESP-IDF
 * 08_lvgl_Porting, 03_SD_Test, 05_IO_Test; ESP32_Display_Panel's
 * BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_4_3_B.h). The plain 4.3 has the same
 * LCD, touch, expander and SD pins.
 *
 * 800 x 480 RGB565 panel on a 16-bit parallel bus (no SPI init); GT911 touch,
 * a CH422G I/O expander (backlight, LCD and touch resets, SD chip select,
 * the isolated DI/DO) and a PCF85063 RTC share one I2C bus (8/9).
 * microSD alone on its own SPI bus (11/12/13). No camera, no battery sense.
 *
 * Included by board.h only (BOARD_WAVESHARE43).
 */

// The board's name on the panel's SUBSYS screen (upper case, ASCII)
#define BOARD_NAME          "WAVESHARE ESP32-S3-TOUCH-LCD-4.3B"

// ── RGB LCD 800x480, 16-bit RGB565 (esp_lcd_panel_rgb) ────────────────────────
// Timings from the demo (waveshare_rgb_lcd_port.c/.h): 16 MHz pixel clock on
// the falling edge, about 39 frames a second.
#define BOARD_LCD_HRES          800
#define BOARD_LCD_VRES          480
#define BOARD_LCD_PCLK_HZ       (16 * 1000 * 1000)
#define BOARD_LCD_HSYNC_PW      4
#define BOARD_LCD_HSYNC_BP      8
#define BOARD_LCD_HSYNC_FP      8
#define BOARD_LCD_VSYNC_PW      4
#define BOARD_LCD_VSYNC_BP      8
#define BOARD_LCD_VSYNC_FP      8
#define BOARD_LCD_PCLK_NEG      1
#define BOARD_LCD_BOUNCE_LINES  10      // 800 x 10 px bounce buffers, internal DMA
#define BOARD_LCD_HSYNC         46
#define BOARD_LCD_VSYNC         3
#define BOARD_LCD_DE            5
#define BOARD_LCD_PCLK          7
// Data bits D0..D15 = B3..B7, G2..G7, R3..R7
#define BOARD_LCD_DATA          { 14, 38, 18, 17, 10, 39, 0, 45, 48, 47, 21, 1, 2, 42, 41, 40 }
#define BOARD_BACKLIGHT_DIM     0       // CH422G EXIO2 enables the boost: on or off

// ── I2C: GT911, CH422G, PCF85063 and the terminal's SDA/SCL ───────────────────
#define BOARD_I2C_PORT          0       // I2C_NUM_0, new i2c_master driver only
#define BOARD_I2C_SDA           8
#define BOARD_I2C_SCL           9
#define BOARD_I2C_HZ            400000  // the demo's bus speed

// GT911: address 0x5D when INT is held low through the reset (backup 0x14).
#define BOARD_TOUCH_INT         4
#define BOARD_TOUCH_ADDR        0x5D
#define BOARD_TOUCH_ADDR_ALT    0x14

// CH422G: each register is its own I2C address.
#define BOARD_EXP_ADDR_MODE     0x24    // system: 0x01 IO0..7 outputs
#define BOARD_EXP_ADDR_OC       0x23    // OC0..3 outputs (DO0 = OC0, DO1 = OC1, low = on)
#define BOARD_EXP_ADDR_IO       0x38    // IO0..7 outputs
// EXIO bits. EXIO0 and EXIO5 are the isolated inputs DI0 and DI1: the bank is
// all output (the touch and LCD resets need it), so they are driven low,
// which their 100 R and 4.7 k pull-ups make safe (high would fight an active
// optocoupler).
#define BOARD_EXP_TP_RST        (1u << 1)
#define BOARD_EXP_DISP          (1u << 2)
#define BOARD_EXP_LCD_RST       (1u << 3)
#define BOARD_EXP_SD_CS         (1u << 4)   // low selects the card

// PCF85063A RTC (its INT is GPIO6, unused)
#define BOARD_RTC_ADDR          0x51

// ── microSD, alone on SPI2; CS on the expander, held low (the SD demo) ───────
#define BOARD_SD_SPI_HOST       SPI2_HOST
#define BOARD_SD_MOSI           11
#define BOARD_SD_MISO           13
#define BOARD_SD_SCLK           12
#define BOARD_SD_CS             (-1)
#define BOARD_SD_SHARES_LCD_BUS 0

// ── No camera, no battery sense ───────────────────────────────────────────────
#define BOARD_HAS_CAMERA        0
#define BOARD_VBAT_ADC          (-1)

// ── Buzzer: a passive piezo across the CAN pair ───────────────────────────────
// No free GPIO reaches a connector on the 4.3B, so the piezo sits on the
// terminal block across CAN-H (P1 pin 8) and CAN-L (P1 pin 7), with the CAN
// termination switch (SW2) on, and LEDC drives the TJA1051T/3's TXD (GPIO15;
// the TWAI peripheral is not used). Schematic: TXD pin 1 = IO15, RXD pin 4 =
// IO16 (left as an input), S pin 8 to GND through R96 0 R (Normal mode, never
// silent), VCC 5 V, VIO 3V3; R61 120 R across CANH and CANL through SW2. TXD
// high is recessive (both lines at about 2.5 V, 0 V across the piezo, which
// the 120 R drains), low dominant (about 2 V across, CANH up and CANL down).
// So the pin idles high (BOARD_BUZZER_INVERT: the duty is the low part), and
// no low part lasts over BOARD_BUZZER_LOW_MAX_US: the TJA1051's TXD dominant
// time-out t_to(dom)TXD is 0.3 ms at the least (1 typical, 5 most; NXP
// TJA1051 data sheet rev. 9, table 8), after which it would drop the driver.
// The duty is capped per tone (buzzer.c), so the lowest tone, 1600 Hz, gets at
// most 24 %, and from 3400 Hz up the full 50 %. TXD has an internal pull-up,
// so the line is recessive before the buzzer starts and after a reset.
// main/config.h may set BOARD_BUZZER_GPIO to another pin, or -1 for none
// (every sound compiled out).
#ifndef BOARD_BUZZER_GPIO
#define BOARD_BUZZER_GPIO       15
#endif
#define BOARD_BUZZER_HZ         2700
#if BOARD_BUZZER_GPIO == 15
#define BOARD_BUZZER_INVERT     1       // idle high: CAN recessive
#define BOARD_BUZZER_LOW_MAX_US 150     // half the TJA1051's shortest TXD time-out
_Static_assert(BOARD_BUZZER_LOW_MAX_US < 300, "the low part must stay under the TJA1051's 0.3 ms TXD time-out");
#endif

// ── Front panel styles ────────────────────────────────────────────────────────
#define BOARD_PANEL_DASHBOARD   0       // LCARS or clan (the dashboard is 480 x 320)
#define BOARD_PANEL_STYLE       2       // the default panel_style: clan

// The drift fix for an RGB panel next to flash writes: XIP from PSRAM keeps
// the cache on while SPIFFS and NVS write, so the bounce buffers keep filling.
#if !CONFIG_SPIRAM_XIP_FROM_PSRAM
#error "BOARD_WAVESHARE43 needs sdkconfig.defaults.waveshare43: build the waveshare43 env, or add it to SDKCONFIG_DEFAULTS"
#endif
