#include "ui.h"
#include "display.h"
#include "alarm.h"
#include "log_store.h"
#include "wifi_manager.h"
#include "lvgl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static const char *TAG = "UI";

#define UI_TASK_STACK   8192
#define UI_TASK_PRIO    2
#define UI_QUEUE_DEPTH  16
#define UI_FEED_ROWS    30

typedef enum { UMSG_EVENT, UMSG_ALARM, UMSG_NET } umsg_kind_t;

typedef struct {
    umsg_kind_t kind;
    union {
        attack_log_t e;
        alarm_info_t a;
        char         net[48];
    };
} umsg_t;

static QueueHandle_t s_q;

static const char *TYPE_NAME[] = {
    "RTSP", "HTTP", "Telnet", "SSH", "FTP", "ARP spoof", "WiFi deauth", "Shell",
};
static const char *TYPE_HEX[] = {   // same palette as the web dashboard
    "a78bfa", "fbbf24", "f87171", "38bdf8", "34d399", "f472b6", "fb923c", "a3e635",
};

#define COL_BG      lv_color_hex(0x03080f)
#define COL_BAR     lv_color_hex(0x0a1a2a)
#define COL_TEXT    lv_color_hex(0xe2e8f0)
#define COL_MUTED   lv_color_hex(0x64748b)
#define COL_GREEN   lv_color_hex(0x00d2a0)
#define COL_AMBER   lv_color_hex(0xfbbf24)
#define COL_RED     lv_color_hex(0xf87171)
#define COL_ALARM   lv_color_hex(0x7f1d1d)

static lv_obj_t *s_net, *s_clock, *s_pill, *s_pill_lbl;
static lv_obj_t *s_total, *s_sources, *s_incident;
static lv_obj_t *s_feed, *s_feed_empty;
static lv_obj_t *s_overlay, *s_ov_title, *s_ov_src, *s_ov_info, *s_ov_btn_lbl;

// ── Listeners (run on other tasks: copy and queue only) ───────────────────────

static void on_event(const attack_log_t *e)
{
    umsg_t m = { .kind = UMSG_EVENT };
    m.e = *e;
    xQueueSend(s_q, &m, 0);          // dropped row is cosmetic; the log keeps it
}

static void on_alarm(const alarm_info_t *a)
{
    umsg_t m = { .kind = UMSG_ALARM };
    m.a = *a;
    xQueueSend(s_q, &m, 0);
}

void ui_set_net(const char *text)
{
    if (!s_q) return;
    umsg_t m = { .kind = UMSG_NET };
    strlcpy(m.net, text, sizeof(m.net));
    xQueueSend(s_q, &m, pdMS_TO_TICKS(100));
}

// ── Formatting helpers ────────────────────────────────────────────────────────

static void fmt_ip(uint32_t ip_net, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip_net };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

static void fmt_time(uint32_t ts, char *buf, size_t len)
{
    if (ts < 1600000000) { strlcpy(buf, "--:--:--", len); return; }   // pre-SNTP
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, len, "%H:%M:%S", &tm);
}

static const char *type_name(uint8_t t) { return t < 8 ? TYPE_NAME[t] : "?"; }
static const char *type_hex(uint8_t t)  { return t < 8 ? TYPE_HEX[t]  : "e2e8f0"; }

// ── Feed ──────────────────────────────────────────────────────────────────────

static void row_deleted_cb(lv_event_t *ev)
{
    heap_caps_free(lv_event_get_user_data(ev));
}

static void row_clicked_cb(lv_event_t *ev)
{
    const attack_log_t *e = (const attack_log_t *)lv_event_get_user_data(ev);
    char ip[16], mac[WIFI_MAC_STR_LEN], t[12];
    fmt_ip(e->src_ip, ip, sizeof(ip));
    wifi_manager_format_mac(e->src_mac, mac, sizeof(mac));
    fmt_time(e->timestamp, t, sizeof(t));

    static char body[512];
    snprintf(body, sizeof(body),
             "Time:  %s\nSource:  %s\nMAC:  %s  (%s)\nUser:  %s\nPass:  %s\n\n%s",
             t, ip, mac, wifi_manager_mac_vendor(e->src_mac),
             e->username[0] ? e->username : "-",
             e->password[0] ? e->password : "-",
             e->payload);
    lv_obj_t *mb = lv_msgbox_create(NULL, type_name((uint8_t)e->type), body, NULL, true);
    lv_obj_set_width(mb, 440);
    lv_obj_center(mb);
}

static void feed_add(const attack_log_t *src)
{
    attack_log_t *e = heap_caps_malloc(sizeof(*e), MALLOC_CAP_SPIRAM);
    if (!e) return;
    *e = *src;

    char ip[16], t[12], text[128];
    fmt_ip(e->src_ip, ip, sizeof(ip));
    fmt_time(e->timestamp, t, sizeof(t));
    const char *who = e->username[0] ? e->username : e->payload;
    snprintf(text, sizeof(text), "%s  #%s %s#  %s  %.24s",
             t, type_hex((uint8_t)e->type), type_name((uint8_t)e->type), ip, who);

    lv_obj_t *btn = lv_list_add_btn(s_feed, NULL, text);
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    lv_label_set_recolor(lbl, true);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_bg_color(btn, COL_BG, 0);
    lv_obj_set_style_text_color(btn, COL_TEXT, 0);
    lv_obj_set_style_text_font(btn, &lv_font_montserrat_14, 0);
    lv_obj_set_style_pad_ver(btn, 6, 0);
    lv_obj_add_event_cb(btn, row_clicked_cb, LV_EVENT_CLICKED, e);
    lv_obj_add_event_cb(btn, row_deleted_cb, LV_EVENT_DELETE, e);
    lv_obj_move_to_index(btn, 0);            // newest on top

    while (lv_obj_get_child_cnt(s_feed) > UI_FEED_ROWS)
        lv_obj_del(lv_obj_get_child(s_feed, -1));
    lv_obj_add_flag(s_feed_empty, LV_OBJ_FLAG_HIDDEN);
}

static void refresh_counters(void)
{
    lv_label_set_text_fmt(s_total, "%lu", (unsigned long)log_store_total_count());

    uint32_t seen[UI_FEED_ROWS];
    int n = 0;
    uint32_t rows = lv_obj_get_child_cnt(s_feed);
    for (uint32_t i = 0; i < rows; i++) {
        lv_obj_t *btn = lv_obj_get_child(s_feed, (int32_t)i);
        if (!lv_obj_has_class(btn, &lv_list_btn_class)) continue;
        const attack_log_t *e = lv_obj_get_event_user_data(btn, row_clicked_cb);
        if (!e) continue;
        bool dup = false;
        for (int j = 0; j < n; j++) if (seen[j] == e->src_ip) { dup = true; break; }
        if (!dup && n < UI_FEED_ROWS) seen[n++] = e->src_ip;
    }
    lv_label_set_text_fmt(s_sources, "%d", n);
}

// ── Alarm ─────────────────────────────────────────────────────────────────────

static void ack_cb(lv_event_t *ev)
{
    (void)ev;
    lv_label_set_text(s_ov_btn_lbl, "Acknowledging...");
    alarm_ack();
}

static void apply_alarm(const alarm_info_t *a)
{
    char ip[16], mac[WIFI_MAC_STR_LEN], t0[12], t1[12];
    fmt_ip(a->src_ip, ip, sizeof(ip));
    wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
    fmt_time(a->first_ts, t0, sizeof(t0));
    fmt_time(a->last_ts, t1, sizeof(t1));

    switch (a->state) {
    case ALARM_ACTIVE:
        lv_obj_set_style_bg_color(s_pill, COL_RED, 0);
        lv_label_set_text(s_pill_lbl, "ALARM");
        lv_label_set_text_fmt(s_incident, "#%lu OPEN", (unsigned long)a->id);
        lv_obj_set_style_text_color(s_incident, COL_RED, 0);
        lv_label_set_text_fmt(s_ov_title, "ATTACK IN PROGRESS  #%lu", (unsigned long)a->id);
        lv_label_set_text_fmt(s_ov_src, "%s   %s  %s",
                              ip, mac, wifi_manager_mac_vendor(a->src_mac));
        lv_label_set_text_fmt(s_ov_info, "%s  -  %lu event%s\nFirst %s   Last %s",
                              type_name(a->type), (unsigned long)a->count,
                              a->count == 1 ? "" : "s", t0, t1);
        lv_label_set_text(s_ov_btn_lbl, "HOLD TO ACKNOWLEDGE");
        lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        break;
    case ALARM_ACKED:
        lv_obj_set_style_bg_color(s_pill, COL_AMBER, 0);
        lv_label_set_text(s_pill_lbl, "ACKED");
        lv_label_set_text_fmt(s_incident, "#%lu acked, %lu ev",
                              (unsigned long)a->id, (unsigned long)a->count);
        lv_obj_set_style_text_color(s_incident, COL_AMBER, 0);
        lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        break;
    default:
        lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
        lv_label_set_text(s_pill_lbl, "ARMED");
        lv_label_set_text(s_incident, "None");
        lv_obj_set_style_text_color(s_incident, COL_GREEN, 0);
        lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        break;
    }
}

// ── Layout ────────────────────────────────────────────────────────────────────

static lv_obj_t *stat_tile(lv_obj_t *parent, const char *caption, lv_obj_t **value)
{
    lv_obj_t *tile = lv_obj_create(parent);
    lv_obj_set_size(tile, 150, 52);
    lv_obj_set_style_bg_color(tile, COL_BAR, 0);
    lv_obj_set_style_border_width(tile, 0, 0);
    lv_obj_set_style_radius(tile, 6, 0);
    lv_obj_set_style_pad_all(tile, 4, 0);
    lv_obj_clear_flag(tile, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *cap = lv_label_create(tile);
    lv_label_set_text(cap, caption);
    lv_obj_set_style_text_color(cap, COL_MUTED, 0);
    lv_obj_set_style_text_font(cap, &lv_font_montserrat_12, 0);
    lv_obj_align(cap, LV_ALIGN_TOP_LEFT, 4, 0);

    *value = lv_label_create(tile);
    lv_label_set_text(*value, "0");
    lv_obj_set_style_text_color(*value, COL_TEXT, 0);
    lv_obj_set_style_text_font(*value, &lv_font_montserrat_20, 0);
    lv_obj_align(*value, LV_ALIGN_BOTTOM_LEFT, 4, 0);
    return tile;
}

static void clock_cb(lv_timer_t *t)
{
    (void)t;
    char buf[12];
    fmt_time((uint32_t)time(NULL), buf, sizeof(buf));
    lv_label_set_text(s_clock, buf);
}

static void build_ui(void)
{
    lv_obj_t *scr = lv_scr_act();
    lv_obj_set_style_bg_color(scr, COL_BG, 0);
    lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

    // Status bar
    lv_obj_t *bar = lv_obj_create(scr);
    lv_obj_set_size(bar, 480, 36);
    lv_obj_align(bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(bar, COL_BAR, 0);
    lv_obj_set_style_border_width(bar, 0, 0);
    lv_obj_set_style_radius(bar, 0, 0);
    lv_obj_set_style_pad_all(bar, 0, 0);
    lv_obj_clear_flag(bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *brand = lv_label_create(bar);
    lv_label_set_text(brand, "ShadowSentry");
    lv_obj_set_style_text_color(brand, COL_GREEN, 0);
    lv_obj_set_style_text_font(brand, &lv_font_montserrat_20, 0);
    lv_obj_align(brand, LV_ALIGN_LEFT_MID, 8, 0);

    s_net = lv_label_create(bar);
    lv_label_set_text(s_net, "Starting...");
    lv_obj_set_style_text_color(s_net, COL_MUTED, 0);
    lv_obj_align(s_net, LV_ALIGN_LEFT_MID, 160, 0);

    s_clock = lv_label_create(bar);
    lv_label_set_text(s_clock, "--:--:--");
    lv_obj_set_style_text_color(s_clock, COL_MUTED, 0);
    lv_obj_align(s_clock, LV_ALIGN_RIGHT_MID, -92, 0);

    s_pill = lv_obj_create(bar);
    lv_obj_set_size(s_pill, 78, 24);
    lv_obj_align(s_pill, LV_ALIGN_RIGHT_MID, -6, 0);
    lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
    lv_obj_set_style_border_width(s_pill, 0, 0);
    lv_obj_set_style_radius(s_pill, 12, 0);
    lv_obj_set_style_pad_all(s_pill, 0, 0);
    lv_obj_clear_flag(s_pill, LV_OBJ_FLAG_SCROLLABLE);
    s_pill_lbl = lv_label_create(s_pill);
    lv_label_set_text(s_pill_lbl, "ARMED");
    lv_obj_set_style_text_color(s_pill_lbl, COL_BG, 0);
    lv_obj_center(s_pill_lbl);

    // Counters
    lv_obj_t *row = lv_obj_create(scr);
    lv_obj_set_size(row, 480, 60);
    lv_obj_align(row, LV_ALIGN_TOP_MID, 0, 38);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 4, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    stat_tile(row, "Events (all time)", &s_total);
    stat_tile(row, "Sources (recent)", &s_sources);
    stat_tile(row, "Incident", &s_incident);

    // Feed
    s_feed = lv_list_create(scr);
    lv_obj_set_size(s_feed, 472, 216);
    lv_obj_align(s_feed, LV_ALIGN_BOTTOM_MID, 0, -2);
    lv_obj_set_style_bg_color(s_feed, COL_BG, 0);
    lv_obj_set_style_border_color(s_feed, COL_BAR, 0);
    lv_obj_set_style_pad_all(s_feed, 2, 0);

    s_feed_empty = lv_label_create(scr);
    lv_label_set_text(s_feed_empty, "Waiting for attackers...");
    lv_obj_set_style_text_color(s_feed_empty, COL_MUTED, 0);
    lv_obj_align(s_feed_empty, LV_ALIGN_CENTER, 0, 50);

    // Incident overlay, above everything
    s_overlay = lv_obj_create(lv_layer_top());
    lv_obj_set_size(s_overlay, 480, 320);
    lv_obj_center(s_overlay);
    lv_obj_set_style_bg_color(s_overlay, COL_ALARM, 0);
    lv_obj_set_style_bg_opa(s_overlay, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_overlay, 0, 0);
    lv_obj_set_style_radius(s_overlay, 0, 0);
    lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_SCROLLABLE);

    s_ov_title = lv_label_create(s_overlay);
    lv_obj_set_style_text_font(s_ov_title, &lv_font_montserrat_28, 0);
    lv_obj_set_style_text_color(s_ov_title, lv_color_white(), 0);
    lv_obj_align(s_ov_title, LV_ALIGN_TOP_MID, 0, 12);

    s_ov_src = lv_label_create(s_overlay);
    lv_obj_set_style_text_font(s_ov_src, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_ov_src, lv_color_white(), 0);
    lv_obj_align(s_ov_src, LV_ALIGN_TOP_MID, 0, 64);

    s_ov_info = lv_label_create(s_overlay);
    lv_obj_set_style_text_font(s_ov_info, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_ov_info, lv_color_hex(0xfecaca), 0);
    lv_obj_set_style_text_align(s_ov_info, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_ov_info, LV_ALIGN_TOP_MID, 0, 104);

    lv_obj_t *btn = lv_btn_create(s_overlay);
    lv_obj_set_size(btn, 400, 80);
    lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, -12);
    lv_obj_set_style_bg_color(btn, lv_color_white(), 0);
    lv_obj_add_event_cb(btn, ack_cb, LV_EVENT_LONG_PRESSED, NULL);
    s_ov_btn_lbl = lv_label_create(btn);
    lv_obj_set_style_text_font(s_ov_btn_lbl, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_ov_btn_lbl, COL_ALARM, 0);
    lv_label_set_text(s_ov_btn_lbl, "HOLD TO ACKNOWLEDGE");
    lv_obj_center(s_ov_btn_lbl);

    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);

    lv_timer_create(clock_cb, 1000, NULL);
}

// ── Task ──────────────────────────────────────────────────────────────────────

static void ui_task(void *arg)
{
    (void)arg;
    if (!display_init()) {
        ESP_LOGE(TAG, "No display — UI task exiting, honeypot keeps running");
        vTaskDelete(NULL);
        return;
    }
    build_ui();

    // Seed the feed from the persisted log, oldest first so newest ends on top.
    attack_log_t *recent = heap_caps_malloc(sizeof(attack_log_t) * UI_FEED_ROWS,
                                            MALLOC_CAP_SPIRAM);
    if (recent) {
        int n = log_store_get_recent(recent, UI_FEED_ROWS);
        for (int i = n - 1; i >= 0; i--) feed_add(&recent[i]);
        heap_caps_free(recent);
    }
    refresh_counters();

    alarm_info_t a;
    alarm_get(&a);
    apply_alarm(&a);

    int64_t last_us = esp_timer_get_time();
    for (;;) {
        umsg_t m;
        bool events = false;
        while (xQueueReceive(s_q, &m, 0) == pdTRUE) {
            switch (m.kind) {
            case UMSG_EVENT: feed_add(&m.e); events = true; break;
            case UMSG_ALARM: apply_alarm(&m.a);              break;
            case UMSG_NET:   lv_label_set_text(s_net, m.net); break;
            }
        }
        if (events) refresh_counters();

        uint32_t ms = (uint32_t)((esp_timer_get_time() - last_us) / 1000);
        lv_tick_inc(ms);
        last_us += (int64_t)ms * 1000;      // carry the sub-ms remainder
        lv_timer_handler();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void ui_start(void)
{
    s_q = xQueueCreate(UI_QUEUE_DEPTH, sizeof(umsg_t));
    log_store_add_listener(on_event);
    alarm_add_listener(on_alarm);
    xTaskCreatePinnedToCore(ui_task, "ui", UI_TASK_STACK, NULL, UI_TASK_PRIO, NULL, 1);
}
