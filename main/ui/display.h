#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Front panel bring-up: ILI9488 via LovyanGFX (Elecrow's own panel config),
 * FT6236 touch (polled), backlight, and the LVGL 8 display + input drivers.
 *
 * LVGL is not thread-safe: call this, and every lv_* function afterwards, from
 * the UI task only. Returns false if the panel failed to initialise.
 */
bool display_init(void);

#ifdef __cplusplus
}
#endif
