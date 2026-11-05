#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "lvgl.h"
#include "log_store.h"

/*
 * 07 SUBSYS: the LCARS panel's about screen (fork addition, subsys), after the
 * First Contact manual-input panel: red on black (#e8261c, a #7a1410 band,
 * #ff6a5e highlights), a header bar, the logo at 96 px, "SUBSYSTEM INFO",
 * terminal lines with live values (unit, base project, fork, build, node,
 * access code) and a blinking cursor, then RETURN and six decorative code
 * buttons with the newest codes seen. Spec: docs/mockups/about-boot.html.
 *
 * ui_lcars.c opens it from the bottom-left elbow, hides its frame while it is
 * up and closes it on any alert. UI task only.
 */

// Build it under root (480 x 320), hidden. back runs when RETURN is touched.
void subsys_build(lv_obj_t *root, void (*back)(void));

// Show (values refreshed at once, then every second) or hide it.
void subsys_show(bool on);
bool subsys_shown(void);

// The terminal lines (the clan skin's INFO page shows them too): key i
// (UNIT, BASE, FORK, BUILD, NODE, ACCESS CODE) and its value, upper case.
#define SUBSYS_LINES 6
const char *subsys_key(int i);
void        subsys_value(int i, char *b, size_t len);

// One event: its code goes to the front of the code buttons (newest first,
// each code once).
void subsys_note(const attack_log_t *e);
