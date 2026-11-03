#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lvgl.h"

/*
 * Panel logo (fork addition, subsys): the image on the LCARS boot splash and
 * the SUBSYS screen.
 *
 * The built-in logo is a 200 x 200 PNG embedded in flash
 * (docs/mockups/shadowsentry-logo-200.png). It is decoded once, on the UI task,
 * with the lodepng that LVGL's PNG decoder uses (CONFIG_LV_USE_PNG), into a
 * PSRAM buffer in LVGL's true colour with alpha (3 bytes a pixel), and drawn
 * from there; the PNG is never decoded again.
 */

#define UI_LOGO_MAX_PX     240                  // either side, for any logo
#define UI_LOGO_MAX_BYTES  (200 * 1024)         // the PNG file

// A PNG's signature and IHDR, bounded by len: true if it is a PNG whose width
// and height are 1..UI_LOGO_MAX_PX, and len is at most UI_LOGO_MAX_BYTES.
// w and h (either may be NULL) get the size.
bool ui_logo_png_ok(const uint8_t *p, size_t len, uint16_t *w, uint16_t *h);

// The built-in PNG, in flash.
const uint8_t *ui_logo_builtin(size_t *len);

// The decoded logo, for lv_img_set_src() (UI task only). Decodes on the first
// call; NULL if that failed.
const lv_img_dsc_t *ui_logo_get(void);
