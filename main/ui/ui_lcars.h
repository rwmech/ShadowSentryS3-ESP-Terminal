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
#include "describe.h"
#include "discovery.h"

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

// ── For other skins (ui_clan.c): the same data and the same motion ───────────
//
// Today's figures, the ports, the tripwire states, the busiest devices and
// the NET lines, as the LCARS pages read them, and the motion engine (Motion
// in ui_lcars.c) bound to another skin's objects. UI task only.

#define LCARS_TRAPS     8
#define LCARS_WIRES     18
#define LCARS_LAST      3
#define LCARS_TALK_MAX  8               // lcars_talkers(): at most this many
#define LCARS_NET_LINES 9               // lcars_net_text(): ACCESS POINT .. DISCORD

typedef struct { char name[24]; uint32_t n, ts, ip; char what[64]; } lcars_hit_t;
typedef struct { char code[DESCRIBE_CODE_LEN]; char name[24]; uint32_t ip, ts; } lcars_last_t;
typedef struct {
    uint32_t     day;                   // local YYYY*1000+yday, 0 = clock not set
    uint32_t     alerts, probes, scans, new_dev;
    lcars_hit_t  trap[LCARS_TRAPS];     // HIKVISION 80, WEB ALT, RTSP, TELNET, SHELL, SSH, FTP, ADB
    lcars_hit_t  wire[LCARS_WIRES];     // 7 LAN tripwires, 5 MikroTik decoys, 6 router
    lcars_last_t last[LCARS_LAST];      // newest first, any day
    int          last_n;
} lcars_today_t;

// Port groups: the trap, tripwire and listener ports
enum { LCARS_GRP_TRAP, LCARS_GRP_WIRE, LCARS_GRP_NET };
// The LCARS pages, also the senses and watch passes a skin borrows
enum { LCARS_PG_NONE = -1, LCARS_PG_OPS, LCARS_PG_TRAPS, LCARS_PG_WIRES, LCARS_PG_NET, LCARS_PG_DEV };
// A tripwire cell's state
enum { LCARS_WS_ARMED, LCARS_WS_HIT, LCARS_WS_OFF };

const lcars_today_t *lcars_today(void);                 // rolled over to today first
int         lcars_port_count(void);
uint16_t    lcars_port(int i, uint8_t *grp, bool *hit); // grp: LCARS_GRP_*
uint8_t     lcars_wire_state(int i);                    // LCARS_WS_*
const char *lcars_wire_off(int i);                      // why cell i is off, NULL if armed
int         lcars_talkers(int max);                     // load the busiest devices; how many
const discovery_talker_t *lcars_talker(int i);
bool        lcars_pihole_share(uint32_t ip, const uint8_t *mac, uint32_t *tot, uint32_t *blk);
void        lcars_net_text(int i, char *b, size_t len); // NET line i (0..8), upper case

// The motion engine on another skin. Items are numbered as on the LCARS page
// whose senses run (page): OPS the port index; TRAPS row * 4 + part (0 marker,
// 1 name, 2 bar fill, 3 bar track); WIRES cell * 2 + part (0 bar, 1 name); NET
// 0..8 values, 9..17 names; DEV the row. obj returns the item's object and
// whether its text or its background is painted (NULL: none); rest puts its
// normal colours back. Tones: hi (watch, pulse, scan), decay (hits), glow
// (packets), ripple (several ports), tick (NET updates).
enum { LCARS_FX_TEXT, LCARS_FX_BG };
typedef struct {
    lv_obj_t *(*obj)(int item, uint8_t *part);
    void      (*rest)(int item);
    uint32_t    hi, decay, glow, ripple, tick;
} lcars_fx_skin_t;

// Bind the engine to skin, sensing page (LCARS_PG_NONE: nothing runs), or
// back to the LCARS pages (skin NULL). Every bind stops what is playing and
// the next sense only records. lcars_view() with the panel shown unbinds.
void lcars_fx_bind(const lcars_fx_skin_t *skin, int page);
const lcars_fx_skin_t *lcars_fx_skin(void);            // the bound skin, NULL the LCARS pages
bool lcars_fx_busy(lv_obj_t *o);

// Shorten s in place for w screen px in font f, ending "..." (at a word if
// that keeps at least half of what fits).
void lcars_fit(char *s, const lv_font_t *f, lv_coord_t w);

// From ui.c: a time in the clock setting's format (secs false: no seconds in
// 12-hour form); the refresh measurement after a page change; the UI loop's
// slowest lv_timer_handler() in the last second, in microseconds.
void     ui_fmt_time(uint32_t ts, bool secs, char *buf, size_t len);
void     ui_refr_measure(const char *what);
uint32_t ui_loop_max_us(void);
