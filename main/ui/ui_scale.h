#pragma once

/*
 * The LCARS layout's scale: every LCARS page, alert view, the SUBSYS screen
 * and the boot splash are laid out on a 480 x 320 grid (the CrowPanel's
 * screen) and placed on the board's screen through these.
 *
 *   UI_SX(x), UI_SY(y)      a grid position, x or y, in screen pixels
 *   UI_SW(x, w), UI_SH(y, h) the width / height of what starts at x / y:
 *                           its far edge's position less its own, so pieces
 *                           that meet on the grid meet on the screen
 *   UI_SS(v)                a length that keeps its shape (radii, line and
 *                           border widths, dots, letter spacing): the smaller
 *                           of the two scales
 *   UI_F12 .. UI_F48        the font for each grid size, the next size up
 *
 * On a 480 x 320 board (the CrowPanel) every one is the identity at compile
 * time, so its layout is pixel for pixel the same as before. Rounding is to
 * the nearest pixel, half away from zero.
 */

#include "board.h"
#include "lvgl.h"

#define UI_GRID_W   480
#define UI_GRID_H   320

#if BOARD_LCD_HRES == UI_GRID_W && BOARD_LCD_VRES == UI_GRID_H

#define UI_SCALED   0
#define UI_SX(v)    ((lv_coord_t)(v))
#define UI_SY(v)    ((lv_coord_t)(v))
#define UI_SS(v)    ((lv_coord_t)(v))

#define UI_F12      (&lv_font_montserrat_12)
#define UI_F14      (&lv_font_montserrat_14)
#define UI_F20      (&lv_font_montserrat_20)
#define UI_F28      (&lv_font_montserrat_28)
#define UI_F48      (&lv_font_montserrat_48)

#else

#define UI_SCALED   1
static inline lv_coord_t ui_scale_(int32_t v, int32_t to, int32_t from)
{
    int32_t n = v * to;
    return (lv_coord_t)(n >= 0 ? (n + from / 2) / from : -((-n + from / 2) / from));
}
#define UI_SX(v)    ui_scale_((int32_t)(v), BOARD_LCD_HRES, UI_GRID_W)
#define UI_SY(v)    ui_scale_((int32_t)(v), BOARD_LCD_VRES, UI_GRID_H)
// The smaller scale (800 x 480: 1.5, the vertical one)
#if BOARD_LCD_HRES * UI_GRID_H < BOARD_LCD_VRES * UI_GRID_W
#define UI_SS(v)    UI_SX(v)
#else
#define UI_SS(v)    UI_SY(v)
#endif

// 800 x 480: 1.5 the height and 1.67 the width of the grid. Each font about
// 1.5 times its grid size (Montserrat comes in even sizes; 48 is LVGL 8's
// largest), so text keeps its rows and gains a little room in its boxes.
#define UI_F12      (&lv_font_montserrat_18)
#define UI_F14      (&lv_font_montserrat_20)
#define UI_F20      (&lv_font_montserrat_30)
#define UI_F28      (&lv_font_montserrat_42)
#define UI_F48      (&lv_font_montserrat_48)

#endif

#define UI_SW(x, w) ((lv_coord_t)(UI_SX((x) + (w)) - UI_SX(x)))
#define UI_SH(y, h) ((lv_coord_t)(UI_SY((y) + (h)) - UI_SY(y)))
