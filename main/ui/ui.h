#pragma once

/*
 * Front panel UI — Core 1, low priority
 *
 * Status bar (network, state pill), counters, a live attack feed (tap a row
 * for details) and a full-screen incident overlay with a hold-to-acknowledge
 * button. Owns LVGL: every lv_* call happens on the UI task; other tasks reach
 * it through ui_set_net() and the log_store / alarm listeners, all queued.
 *
 * Call ui_start() after log_store_init() and alarm_init(), before Wi-Fi, so
 * the panel shows connection progress.
 */

void ui_start(void);

// Network line in the status bar ("Connecting to X…", "192.168.1.20"). Any task.
void ui_set_net(const char *text);
