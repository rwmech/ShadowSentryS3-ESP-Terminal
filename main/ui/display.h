#pragma once
#include <stdbool.h>
#include "driver/i2c_types.h"

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

// true: backlight full on regardless of the brightness setting (incident
// strobe). false: back to settings_get()->brightness. Any task, after
// display_init(); a no-op if the backlight PWM is not running.
void display_set_backlight_override(bool full);

/*
 * The I2C master bus touch creates on BOARD_I2C_PORT (SDA 2 / SCL 1), shared
 * with the camera SCCB and the Crowtail header. NULL until display_init() has
 * created it, and stays NULL if that failed. Any task may call this.
 */
i2c_master_bus_handle_t display_i2c_bus(void);

// true: stop polling the touch controller, so another device (the camera's
// SCCB init) has the bus to itself; touch reads as released meanwhile.
// false: resume. Any task.
void display_touch_hold(bool hold);

#ifdef __cplusplus
}
#endif
