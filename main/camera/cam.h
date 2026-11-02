#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * OV2640 snapshot of whoever presses the panel's ACK or CLEAR button, Core 1.
 *
 * The sensor runs from boot (JPEG, VGA, one frame buffer in PSRAM). A panel
 * press calls cam_snap(), which only queues a request; the camera task grabs a
 * fresh frame, keeps it in PSRAM as "the last snapshot" (dashboard, Discord),
 * and hands a copy to the SD writer as /sd/snap/YYYY-MM-DD_HH-MM-SS_<action>.jpg
 * plus a "snap" line in the day log. No sensor: logged once, everything here
 * becomes a no-op, and the rest of the firmware runs as before.
 *
 * SCCB shares the touch I2C bus (new i2c_master driver, attached by port), so
 * the legacy I2C driver is never linked.
 */

// Light the face for a panel photo (config.h.example). Defaults for a
// config.h written before these options.
#ifndef CAM_FLASH_ENABLE
#define CAM_FLASH_ENABLE      0
#endif
#ifndef CAM_FLASH_SETTLE_MS
#define CAM_FLASH_SETTLE_MS   500
#endif

// 0: the camera is never started (no XCLK, no DMA); cam_snap() is a no-op.
#ifndef CAM_ENABLE
#define CAM_ENABLE            1
#endif

#define CAM_ACTION_MAX  12      // incl. NUL; [a-z0-9_-] only, else "press"
#define CAM_FILE_MAX    64

typedef struct {
    uint32_t seq;               // 1, 2, ... per snapshot since boot; 0 = none yet
    uint32_t ts;                // unix time of the press (uptime s if no SNTP yet)
    uint32_t size;              // JPEG bytes
    uint16_t width, height;
    char     action[CAM_ACTION_MAX];
    char     file[CAM_FILE_MAX];   // path on the card, "" if it was not saved
} cam_meta_t;

// Start the camera task (Core 1). Returns at once: the task waits for the
// display to create the I2C bus, then probes the sensor. Call after ui_start().
void cam_snap_init(void);

// Sensor found and streaming.
bool cam_ready(void);

/*
 * Take a snapshot for a panel action, e.g. cam_snap("ack") / cam_snap("clear").
 * Non-blocking and safe from the UI (LVGL) task or any other task: it copies
 * the action and the press time into a queue and returns. Call it from the
 * button's LV_EVENT_PRESSED handler, not after a hold completes, so the photo
 * is of the person still at the glass:
 *
 *     static void ack_pressed_cb(lv_event_t *e) { cam_snap("ack"); }
 *     lv_obj_add_event_cb(btn_ack, ack_pressed_cb, LV_EVENT_PRESSED, NULL);
 *
 * At most one snapshot per second is taken; extra presses are dropped.
 * Returns false if the camera is off or the request was dropped.
 */
bool cam_snap(const char *action);

/*
 * cam_snap() for a lit face: the caller has just turned the panel white (and
 * the backlight up). The camera task drops frames for settle_ms (0 to 2000)
 * while the sensor's auto exposure adjusts to the light, then captures, and
 * calls done(true) as soon as the frame is taken, or done(false) if no frame
 * came. done runs on the camera task: copy and queue, never block, no LVGL.
 * Returns false, and done is never called, if the request was not queued
 * (camera off, a snapshot under a second ago, or the queue full).
 */
typedef void (*cam_done_cb_t)(bool ok);
bool cam_snap_lit(const char *action, int settle_ms, cam_done_cb_t done);

// Metadata of the last snapshot. False (and *out zeroed) if there is none yet.
bool cam_last_meta(cam_meta_t *out);

/*
 * A private copy of the last snapshot's JPEG, in PSRAM: the caller owns it and
 * must free() it. NULL if there is none or out of memory. meta may be NULL.
 * The copy is taken under the camera's lock, so it never tears while a new
 * snapshot replaces the old one, and the caller can then take its time
 * (HTTP send, Discord multipart upload) without holding anything.
 */
uint8_t *cam_last_dup(size_t *len, cam_meta_t *meta);

/*
 * Wait until no snapshot is queued or being captured, at most timeout_ms.
 * For a sender that wants the photo of the press that triggered it, e.g. the
 * Discord "acknowledged" post: cam_wait_idle(1500), then cam_last_dup(), and
 * check meta.action and meta.ts. True if idle. Never call from the UI task.
 */
bool cam_wait_idle(int timeout_ms);

#ifdef __cplusplus
}
#endif
