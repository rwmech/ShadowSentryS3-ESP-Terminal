#pragma once

/*
 * Clan front panel (fork addition, Robert Mech)
 *
 * The panel style settings panel_style 2, a clan-command look after two
 * reference images Rob gave: weathered gunmetal plates on a tiled metal
 * texture, crimson accents and glow strips, the gold panel_title on a red
 * angled banner, a STATUS plate (NOMINAL, CAUTION, HOSTILE), an icon nav
 * column (TACTICAL, BAIT, PERIMETER, SYSTEMS, CONTACTS, INFO) with an AUTO
 * plate under it, cyan holo panels and segmented red and gold bars. The
 * emblem is an original sigil drawn with LVGL lines; no Mandalorian crest,
 * mythosaur or helmet art. Spec: docs/mockups/clan-panel.html.
 *
 * Laid out on the 480 x 320 grid and placed through ui_scale.h, like LCARS.
 * The data, the port list and the motion engine are the LCARS code's
 * (ui_lcars.h, "For other skins"); this file only draws them.
 *
 * During an incident the nav and pages are hidden and the alert view shows:
 * the HOSTILE CONTACT or CAUTION banner, the code, source and headline, and
 * the buttons, whose actions ui.c attaches (clan_alert()).
 *
 * UI task only, like every lv_* call. ui.c owns the alarm state and calls in.
 */

#include <stdbool.h>
#include "lvgl.h"
#include "alarm.h"
#include "log_store.h"

// Build the frame, pages and alert view under scr, hidden.
void clan_build(lv_obj_t *scr);

// Show the clan panel for condition c (on), or hide it all.
void clan_view(alarm_cond_t c, bool on);

// One event (HOSTILE contacts: today's SEV1 and SEV2 sources), and a reset
// before the boot seed replays today's.
void clan_event(const attack_log_t *e);
void clan_reset(void);

// A message box in the palette: a dark plate, a red edge, gold title.
void clan_style_msgbox(lv_obj_t *mb);

// The alert view's widgets, for ui.c to fill and to attach the actions to.
typedef struct {
    lv_obj_t *code, *src, *head, *stat;     // labels, centred, clipped at clan_alert_text_w()
    lv_obj_t *ack, *ack_fill, *ack_lbl;     // ACKNOWLEDGE: the hold fill (width 0 to the button's)
    lv_obj_t *ign_err, *ign_dev;
} clan_alert_t;
const clan_alert_t *clan_alert(void);

// Show and place the buttons for condition c (dev: IGNORE DEVICE too).
// Returns the button row's top, screen px.
lv_coord_t clan_alert_layout(alarm_cond_t c, bool dev);
lv_coord_t clan_alert_text_w(void);         // screen px
