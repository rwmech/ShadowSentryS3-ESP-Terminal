#pragma once

/*
 * LCARS front panel (fork addition, Robert Mech)
 *
 * The panel style DISPLAY_PANEL_STYLE / settings panel_style 1: an LCARS
 * frame (top and bottom elbows, segmented bars, title, clock) around a
 * 400 x 282 content box, and a rail of six buttons on the left: 01 OPS,
 * 02 TRAPS, 03 WIRES, 04 NET, 05 DEV and 06 AUTO. In AUTO the pages rotate
 * every settings panel_rotate_s (DISPLAY_ROTATE_S, read live); touching
 * 01 to 05 turns AUTO off and holds that page.
 * During an incident the rail and pages are hidden and ui.c fills the alert
 * box (lcars_alert_box()) with the emblem, the details and the buttons.
 * Layout and colours follow docs/mockups/lcars-panel.html. Every coordinate
 * here and in ui_lcars.c is on the 480 x 320 grid, placed on the board's
 * screen through ui_scale.h (the identity on a 480 x 320 board).
 *
 * UI task only, like every lv_* call. ui.c owns the alarm state and calls in.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lvgl.h"
#include "alarm.h"
#include "log_store.h"

// One palette per theme; only Cerritos (Lower Decks) ships.
typedef struct {
    uint32_t c1, c2, c3, c4, c5, c6;    // frame and rail colours
    uint32_t txt, dim, track, accent;   // text, dim text, gauge track, hits and danger
    uint32_t hi;                        // near-white warm: the selection mark and the flashes
    uint32_t red, yellow;               // the alert emblems
} lcars_palette_t;

extern const lcars_palette_t LCARS_CERRITOS;
#define LCARS_PAL (&LCARS_CERRITOS)
#define LCARS_COL(f) lv_color_hex(LCARS_PAL->f)

#define LCARS_CONTENT_X 76
#define LCARS_CONTENT_Y 20
#define LCARS_CONTENT_W 400
#define LCARS_CONTENT_H 282

// Build the frame and pages under scr, hidden.
void lcars_build(lv_obj_t *scr);

// Show the LCARS panel for condition c (on), or hide it all (dashboard style).
// GREEN shows the rail and the current page; RED or YELLOW hides them, names
// the alert in the title and shows the alert box.
void lcars_view(alarm_cond_t c, bool on);

// The 400 x 282 alert box in the content area, for ui.c to fill. Black.
lv_obj_t *lcars_alert_box(void);

// One event (today's counts, port and trap hits, the last events), and a
// reset before the boot seed from the flash ring replays today's.
void lcars_event(const attack_log_t *e);
void lcars_reset(void);

// A message box in the palette: black, a c4 border, c2 text, c4 buttons.
void lcars_style_msgbox(lv_obj_t *mb);

// Upper-case ASCII in place.
void lcars_upper(char *s);

// From ui.c: a time in the clock setting's format (secs false: no seconds in
// 12-hour form); the refresh measurement after a page change; the UI loop's
// slowest lv_timer_handler() in the last second, in microseconds.
void     ui_fmt_time(uint32_t ts, bool secs, char *buf, size_t len);
void     ui_refr_measure(const char *what);
uint32_t ui_loop_max_us(void);
