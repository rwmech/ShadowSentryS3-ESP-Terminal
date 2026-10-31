#include "ui.h"
#include "display.h"
#include "alarm.h"
#include "log_store.h"
#include "sd_log.h"
#include "wifi_manager.h"
#include "ignore.h"
#include "lvgl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static const char *TAG = "UI";

#define UI_TASK_STACK   8192
#define UI_TASK_PRIO    2
#define UI_QUEUE_DEPTH  16
#define UI_FEED_ROWS    3       // the panel is for status and control, not a log
#define UI_SEED_ROWS    200     // the whole flash ring, to count sources at boot
#define UI_SRC_MAX      64      // distinct sources counted; more shows "64+"
#define STROBE_MS       500
#define REARM_HOLD_MS   1500    // a brush must not re-arm

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
    "Port scan", "Probe", "ARP sweep", "ADB",
};
static const char *TYPE_HEX[] = {   // same palette as the web dashboard
    "a78bfa", "fbbf24", "f87171", "38bdf8", "34d399", "f472b6", "fb923c", "a3e635",
    "22d3ee", "94a3b8", "e879f9", "3ddc84",
};
_Static_assert(sizeof(TYPE_NAME) / sizeof(TYPE_NAME[0]) == ATTACK_TYPE_COUNT, "TYPE_NAME: one per attack_type_t");
_Static_assert(sizeof(TYPE_HEX) / sizeof(TYPE_HEX[0]) == ATTACK_TYPE_COUNT, "TYPE_HEX: one per attack_type_t");

// Bright palette: the ILI9488 has no gamma tuning, and dark greys on near
// black read as dim, so text is white or light grey and accents are saturated.
#define COL_BG      lv_color_hex(0x0b1220)
#define COL_CARD    lv_color_hex(0x1e293b)
#define COL_TEXT    lv_color_white()
#define COL_SUB     lv_color_hex(0xcbd5e1)
#define COL_GREEN   lv_color_hex(0x22ff9a)
#define COL_AMBER   lv_color_hex(0xffc400)
#define COL_RED     lv_color_hex(0xff3b3b)
#define COL_DARK    lv_color_hex(0x0b1220)   // text on a bright fill
#define COL_STROBE  lv_color_hex(0xe00000)   // white text stays readable on it
#define COL_BLACK   lv_color_black()
#define COL_ACK_TXT lv_color_hex(0x7f1d1d)   // on the white overlay button
#define HEX_SUB     "cbd5e1"                 // COL_SUB for label recolor

#define TXT_REARM   "RE-ARM  (hold)"
#define TXT_ACK     "ACKNOWLEDGE  (hold)"
#define TXT_OV_ACK  "HOLD TO ACKNOWLEDGE"

// Status bar
static lv_obj_t *s_net, *s_clock, *s_pill, *s_pill_lbl;
// Incident card
static lv_obj_t *s_card, *s_c_head, *s_c_age, *s_c_src, *s_c_info, *s_c_times;
static lv_obj_t *s_c_ack, *s_c_ack_lbl, *s_c_rearm, *s_c_rearm_lbl;
// Key figures
static lv_obj_t *s_f_events, *s_f_sources, *s_f_sd, *s_f_wifi;
// Last events
static lv_obj_t *s_feed, *s_feed_empty;
// Full-screen strobing overlay while unacknowledged
static lv_obj_t *s_overlay, *s_ov_title, *s_ov_src, *s_ov_info, *s_ov_btn_lbl;
static lv_timer_t *s_strobe;
static bool        s_strobe_red;
static bool        s_strobing;

static alarm_info_t s_alarm;            // last state applied, for the age line
static uint32_t     s_src[UI_SRC_MAX];  // distinct sources seen
static int          s_src_n;
static bool         s_src_more;
static uint32_t     s_rearm_t0;
static bool         s_rearm_fired;

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

// How long the incident has been open, from its first event. Empty before SNTP.
static void fmt_age(uint32_t first, char *buf, size_t len)
{
    time_t now = time(NULL);
    if (first < 1600000000 || now < (time_t)first) { buf[0] = '\0'; return; }
    unsigned long d = (unsigned long)(now - (time_t)first);
    if (d < 60)        snprintf(buf, len, "open %lus", d);
    else if (d < 3600) snprintf(buf, len, "open %lum %02lus", d / 60, d % 60);
    else               snprintf(buf, len, "open %luh %02lum", d / 3600, d % 3600 / 60);
}

static const char *type_name(uint8_t t) { return t < ATTACK_TYPE_COUNT ? TYPE_NAME[t] : "?"; }
static const char *type_hex(uint8_t t)  { return t < ATTACK_TYPE_COUNT ? TYPE_HEX[t]  : "ffffff"; }

// ── Sources ───────────────────────────────────────────────────────────────────

static void source_add(uint32_t ip)
{
    for (int i = 0; i < s_src_n; i++) if (s_src[i] == ip) return;
    if (s_src_n < UI_SRC_MAX) s_src[s_src_n++] = ip;
    else s_src_more = true;
}

// ── Last events ───────────────────────────────────────────────────────────────

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

    char ip[16], t[12], who[25], text[128];
    fmt_ip(e->src_ip, ip, sizeof(ip));
    fmt_time(e->timestamp, t, sizeof(t));
    // Attacker text: a '#' would be read as a recolor command, so drop it.
    strlcpy(who, e->username[0] ? e->username : e->payload, sizeof(who));
    for (char *c = who; *c; c++) if (*c == '#') *c = ' ';
    snprintf(text, sizeof(text), "#" HEX_SUB " %s#  #%s %s#  %s  %s",
             t, type_hex((uint8_t)e->type), type_name((uint8_t)e->type), ip, who);

    lv_obj_t *btn = lv_list_add_btn(s_feed, NULL, text);
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    lv_label_set_recolor(lbl, true);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_bg_color(btn, COL_CARD, 0);
    lv_obj_set_style_text_color(btn, COL_TEXT, 0);
    lv_obj_set_style_text_font(btn, &lv_font_montserrat_14, 0);
    lv_obj_set_style_pad_ver(btn, 3, 0);
    lv_obj_set_style_pad_hor(btn, 6, 0);
    lv_obj_set_style_radius(btn, 4, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_add_event_cb(btn, row_clicked_cb, LV_EVENT_CLICKED, e);
    lv_obj_add_event_cb(btn, row_deleted_cb, LV_EVENT_DELETE, e);
    lv_obj_move_to_index(btn, 0);            // newest on top

    while (lv_obj_get_child_cnt(s_feed) > UI_FEED_ROWS)
        lv_obj_del(lv_obj_get_child(s_feed, -1));
    lv_obj_add_flag(s_feed_empty, LV_OBJ_FLAG_HIDDEN);
}

// ── Key figures ───────────────────────────────────────────────────────────────

// On every batch of events: cheap, in RAM.
static void refresh_counts(void)
{
    lv_label_set_text_fmt(s_f_events, "#" HEX_SUB " Events#  %lu",
                          (unsigned long)log_store_total_count());
    lv_label_set_text_fmt(s_f_sources, "#" HEX_SUB " Sources#  %d%s",
                          s_src_n, s_src_more ? "+" : "");
}

// Every 2 s: the counts plus the microSD and Wi-Fi state.
static void refresh_figures(void)
{
    refresh_counts();

    sd_status_t sd;
    sd_log_status(&sd);
    if (sd.mounted) {
        unsigned long tenths = (unsigned long)(sd.free_bytes / 100000000ULL);   // 0.1 GB
        lv_label_set_text_fmt(s_f_sd, "#" HEX_SUB " SD#  %lu.%lu GB free",
                              tenths / 10, tenths % 10);
    } else {
        lv_label_set_text(s_f_sd, "#" HEX_SUB " SD#  no card");
    }

    wifi_ap_record_t ap;
    if (wifi_manager_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        lv_label_set_text_fmt(s_f_wifi, "#" HEX_SUB " Wi-Fi#  %d dBm", (int)ap.rssi);
    else
        lv_label_set_text(s_f_wifi, "#" HEX_SUB " Wi-Fi#  --");
}

static void figures_cb(lv_timer_t *t)
{
    (void)t;
    refresh_figures();
}

// ── Alarm ─────────────────────────────────────────────────────────────────────

static void ack_cb(lv_event_t *ev)
{
    (void)ev;
    lv_label_set_text(s_ov_btn_lbl, "Acknowledging...");
    lv_label_set_text(s_c_ack_lbl, "Acknowledging...");
    alarm_ack();
}

// Re-arm needs REARM_HOLD_MS of continuous press; LVGL's long press (400 ms)
// is too easy to hit by accident.
static void rearm_cb(lv_event_t *ev)
{
    lv_event_code_t c = lv_event_get_code(ev);
    if (c == LV_EVENT_PRESSED) {
        s_rearm_t0    = lv_tick_get();
        s_rearm_fired = false;
        lv_label_set_text(s_c_rearm_lbl, "KEEP HOLDING...");
    } else if (c == LV_EVENT_PRESSING) {
        if (!s_rearm_fired && lv_tick_elaps(s_rearm_t0) >= REARM_HOLD_MS) {
            s_rearm_fired = true;
            lv_label_set_text(s_c_rearm_lbl, "Re-arming...");
            alarm_clear();
        }
    } else if (c == LV_EVENT_RELEASED || c == LV_EVENT_PRESS_LOST) {
        if (!s_rearm_fired) lv_label_set_text(s_c_rearm_lbl, TXT_REARM);
    }
}

// ── Ignore source (detect-core) ───────────────────────────────────────────────
//
// IGNORE SOURCE on the incident card and the overlay. A tap opens a
// confirmation; Ignore adds the source to the ignore list and, if the open
// incident is still from it, acknowledges and re-arms it so the siren and the
// strobe stop. The panel only adds: removal is on the dashboard.

static lv_obj_t *s_c_ignore, *s_ov_ignore;
static struct { uint32_t ip; uint8_t mac[6]; uint32_t id; } s_ign;   // the source the dialog is about
static const char *IGN_BTNS[] = { "Ignore", "Cancel", "" };

static bool mac_zero(const uint8_t m[6])
{
    for (int i = 0; i < 6; i++) if (m[i]) return false;
    return true;
}

static void ignore_mb_cb(lv_event_t *ev)
{
    lv_obj_t *mb = lv_event_get_current_target(ev);
    const char *b = lv_msgbox_get_active_btn_text(mb);
    bool yes = b && !strcmp(b, "Ignore");
    lv_msgbox_close_async(mb);
    if (!yes) return;

    char note[IGNORE_NOTE_MAX];
    snprintf(note, sizeof(note), "panel, incident #%lu", (unsigned long)s_ign.id);
    esp_err_t r = ignore_add(s_ign.ip, mac_zero(s_ign.mac) ? NULL : s_ign.mac, note);
    if (r != ESP_OK) {
        lv_obj_t *e = lv_msgbox_create(NULL, "Not ignored",
            r == ESP_ERR_NO_MEM ? "The ignore list is full (32). Remove entries on the dashboard Settings page."
                                : "Could not save the ignore list.", NULL, true);
        lv_obj_set_width(e, 400);
        lv_obj_center(e);
        return;
    }
    ESP_LOGW(TAG, "Source of incident #%lu ignored from the panel", (unsigned long)s_ign.id);
    alarm_info_t a;
    alarm_get(&a);
    bool same = (s_ign.ip && a.src_ip == s_ign.ip) ||
                (!mac_zero(s_ign.mac) && !memcmp(a.src_mac, s_ign.mac, 6));
    if (a.state != ALARM_IDLE && same) {
        alarm_ack();        // queued in order: ACTIVE -> ACKED -> IDLE
        alarm_clear();
    }
}

static void ignore_cb(lv_event_t *ev)
{
    (void)ev;
    if (s_alarm.state == ALARM_IDLE) return;
    s_ign.ip = s_alarm.src_ip;
    memcpy(s_ign.mac, s_alarm.src_mac, 6);
    s_ign.id = s_alarm.id;

    char ip[16], mac[WIFI_MAC_STR_LEN], who[96];
    static char body[320];
    fmt_ip(s_ign.ip, ip, sizeof(ip));
    wifi_manager_format_mac(s_ign.mac, mac, sizeof(mac));
    const char *v = wifi_manager_mac_vendor(s_ign.mac);
    if (!s_ign.ip)         snprintf(who, sizeof(who), "MAC %s%s%s%s", mac, v[0] ? " (" : "", v, v[0] ? ")" : "");
    else if (v[0])         snprintf(who, sizeof(who), "%s (%s, %s)", ip, v, mac);
    else                   snprintf(who, sizeof(who), "%s (%s)", ip, mac);
    snprintf(body, sizeof(body), "Ignore %s?\n\nEvents from it will still be logged but will not alarm. "
             "Undo from the dashboard Settings page.", who);

    lv_obj_t *mb = lv_msgbox_create(NULL, "Ignore source", body, IGN_BTNS, false);
    lv_obj_set_width(mb, 440);
    lv_obj_set_style_text_font(mb, &lv_font_montserrat_20, 0);
    lv_obj_t *btns = lv_msgbox_get_btns(mb);
    lv_obj_set_size(btns, 400, 56);
    lv_obj_center(mb);
    lv_obj_add_event_cb(mb, ignore_mb_cb, LV_EVENT_VALUE_CHANGED, NULL);
}

static void ignore_show(bool on)
{
    // Nothing to ignore without a source address.
    on = on && (s_alarm.src_ip || !mac_zero(s_alarm.src_mac));
    if (on) { lv_obj_clear_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN); lv_obj_clear_flag(s_ov_ignore, LV_OBJ_FLAG_HIDDEN); }
    else    { lv_obj_add_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN);   lv_obj_add_flag(s_ov_ignore, LV_OBJ_FLAG_HIDDEN); }
}

// Card: ACKNOWLEDGE / RE-ARM narrowed to the left, IGNORE SOURCE on the right.
// Overlay: a smaller outlined button above HOLD TO ACKNOWLEDGE.
static void build_ignore(lv_obj_t *ov_ack_btn)
{
    lv_obj_set_width(s_c_ack, 290);
    lv_obj_align(s_c_ack, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_width(s_c_rearm, 290);
    lv_obj_align(s_c_rearm, LV_ALIGN_BOTTOM_LEFT, 0, 0);

    lv_obj_t *lbl;
    s_c_ignore = lv_btn_create(s_card);
    lv_obj_set_size(s_c_ignore, 156, 60);
    lv_obj_align(s_c_ignore, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(s_c_ignore, COL_SUB, 0);
    lv_obj_set_style_shadow_width(s_c_ignore, 0, 0);
    lbl = lv_label_create(s_c_ignore);
    lv_label_set_text(lbl, "IGNORE\nSOURCE");
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(lbl, COL_DARK, 0);
    lv_obj_center(lbl);
    lv_obj_add_event_cb(s_c_ignore, ignore_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN);

    s_ov_ignore = lv_btn_create(s_overlay);
    lv_obj_set_size(s_ov_ignore, 240, 44);
    lv_obj_align_to(s_ov_ignore, ov_ack_btn, LV_ALIGN_OUT_TOP_MID, 0, -6);
    lv_obj_set_style_bg_opa(s_ov_ignore, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_color(s_ov_ignore, lv_color_white(), 0);
    lv_obj_set_style_border_width(s_ov_ignore, 2, 0);
    lv_obj_set_style_shadow_width(s_ov_ignore, 0, 0);
    lbl = lv_label_create(s_ov_ignore);
    lv_label_set_text(lbl, "IGNORE SOURCE");
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(lbl, COL_TEXT, 0);
    lv_obj_center(lbl);
    lv_obj_add_event_cb(s_ov_ignore, ignore_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(s_ov_ignore, LV_OBJ_FLAG_HIDDEN);
}

// Background only: the labels and the white button keep their colours, so
// the button stays readable in both phases.
static void strobe_cb(lv_timer_t *t)
{
    (void)t;
    s_strobe_red = !s_strobe_red;
    lv_obj_set_style_bg_color(s_overlay, s_strobe_red ? COL_STROBE : COL_BLACK, 0);
}

static void strobe_set(bool on)
{
    if (on == s_strobing) return;
    s_strobing = on;
    s_strobe_red = true;
    lv_obj_set_style_bg_color(s_overlay, COL_STROBE, 0);
    if (on) { lv_timer_reset(s_strobe); lv_timer_resume(s_strobe); }
    else    lv_timer_pause(s_strobe);
    display_set_backlight_override(on);   // full on while strobing, else the setting
}

static void refresh_age(void)
{
    char age[24] = "";
    if (s_alarm.state != ALARM_IDLE) fmt_age(s_alarm.first_ts, age, sizeof(age));
    lv_label_set_text(s_c_age, age);
}

static void apply_alarm(const alarm_info_t *a)
{
    char ip[16], mac[WIFI_MAC_STR_LEN], t0[12], t1[12];
    fmt_ip(a->src_ip, ip, sizeof(ip));
    wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
    fmt_time(a->first_ts, t0, sizeof(t0));
    fmt_time(a->last_ts, t1, sizeof(t1));
    const char *vendor = wifi_manager_mac_vendor(a->src_mac);
    const char *plural = a->count == 1 ? "" : "s";
    // Count updates (up to 1/s during a scan) must not reset a button label
    // mid-press: the labels go back to their prompts only on a new state.
    bool changed = a->state != s_alarm.state || a->id != s_alarm.id;
    s_alarm = *a;

    if (a->state == ALARM_ACTIVE || a->state == ALARM_ACKED) {
        bool active = a->state == ALARM_ACTIVE;
        lv_color_t acc = active ? COL_RED : COL_AMBER;
        lv_obj_set_style_bg_color(s_pill, acc, 0);
        lv_label_set_text(s_pill_lbl, active ? "ALARM" : "ACKED");
        lv_obj_set_style_border_color(s_card, acc, 0);
        lv_obj_set_style_text_color(s_c_head, acc, 0);
        lv_label_set_text_fmt(s_c_head, "%s  #%lu", active ? "ALARM" : "ACKED",
                              (unsigned long)a->id);
        lv_obj_set_style_text_color(s_c_src, COL_TEXT, 0);
        lv_label_set_text(s_c_src, ip);
        lv_obj_set_style_text_color(s_c_info, COL_TEXT, 0);
        lv_label_set_text_fmt(s_c_info, "%s,  %lu event%s,  %s",
                              type_name(a->type), (unsigned long)a->count, plural, vendor);
        lv_label_set_text_fmt(s_c_times, "MAC %s    First %s    Last %s", mac, t0, t1);
        if (active) {
            if (changed) lv_label_set_text(s_c_ack_lbl, TXT_ACK);
            lv_obj_clear_flag(s_c_ack, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(s_c_rearm, LV_OBJ_FLAG_HIDDEN);
        } else {
            if (changed) lv_label_set_text(s_c_rearm_lbl, TXT_REARM);
            lv_obj_add_flag(s_c_ack, LV_OBJ_FLAG_HIDDEN);
            lv_obj_clear_flag(s_c_rearm, LV_OBJ_FLAG_HIDDEN);
        }
    } else {
        lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
        lv_label_set_text(s_pill_lbl, "ARMED");
        lv_obj_set_style_border_color(s_card, COL_GREEN, 0);
        lv_obj_set_style_text_color(s_c_head, COL_GREEN, 0);
        lv_label_set_text(s_c_head, "ARMED");
        lv_obj_set_style_text_color(s_c_src, COL_SUB, 0);
        lv_label_set_text(s_c_src, "No active incident");
        lv_obj_set_style_text_color(s_c_info, COL_SUB, 0);
        if (a->id) {   // the last incident stays on show after it closes
            lv_label_set_text_fmt(s_c_info, "Last #%lu:  %s from %s,  %lu event%s",
                                  (unsigned long)a->id, type_name(a->type), ip,
                                  (unsigned long)a->count, plural);
            lv_label_set_text_fmt(s_c_times, "%s    First %s    Last %s", vendor, t0, t1);
        } else {
            lv_label_set_text(s_c_info, "");
            lv_label_set_text(s_c_times, "");
        }
        lv_obj_add_flag(s_c_ack, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_c_rearm, LV_OBJ_FLAG_HIDDEN);
    }
    refresh_age();
    ignore_show(a->state == ALARM_ACTIVE || a->state == ALARM_ACKED);

    if (a->state == ALARM_ACTIVE) {
        lv_label_set_text_fmt(s_ov_title, "ATTACK IN PROGRESS  #%lu", (unsigned long)a->id);
        lv_label_set_text(s_ov_src, ip);
        lv_label_set_text_fmt(s_ov_info, "%s  -  %lu event%s  -  %s\nMAC %s\nFirst %s   Last %s",
                              type_name(a->type), (unsigned long)a->count, plural, vendor,
                              mac, t0, t1);
        if (changed) lv_label_set_text(s_ov_btn_lbl, TXT_OV_ACK);
        lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        strobe_set(true);
    } else {
        lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        strobe_set(false);
    }
}

// ── Layout ────────────────────────────────────────────────────────────────────
//
//   y   0..35   status bar: name, IP : port, clock, state pill
//   y  38..217  incident card
//   y 221..246  key figures
//   y 250..319  last 3 events

static lv_obj_t *label(lv_obj_t *parent, const lv_font_t *font, lv_color_t col)
{
    lv_obj_t *l = lv_label_create(parent);
    lv_label_set_text(l, "");
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, col, 0);
    return l;
}

static lv_obj_t *card_button(lv_obj_t *parent, lv_color_t fill, lv_obj_t **lbl)
{
    lv_obj_t *b = lv_btn_create(parent);
    lv_obj_set_size(b, 300, 60);
    lv_obj_align(b, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(b, fill, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    *lbl = label(b, &lv_font_montserrat_20, COL_DARK);
    lv_obj_center(*lbl);
    lv_obj_add_flag(b, LV_OBJ_FLAG_HIDDEN);
    return b;
}

static void clock_cb(lv_timer_t *t)
{
    (void)t;
    char buf[12];
    fmt_time((uint32_t)time(NULL), buf, sizeof(buf));
    lv_label_set_text(s_clock, buf);
    refresh_age();
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
    lv_obj_set_style_bg_color(bar, COL_CARD, 0);
    lv_obj_set_style_border_width(bar, 0, 0);
    lv_obj_set_style_radius(bar, 0, 0);
    lv_obj_set_style_pad_all(bar, 0, 0);
    lv_obj_clear_flag(bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *brand = label(bar, &lv_font_montserrat_20, COL_GREEN);
    lv_label_set_text(brand, "ShadowSentry");
    lv_obj_align(brand, LV_ALIGN_LEFT_MID, 8, 0);

    s_net = label(bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_net, "Starting...");
    lv_obj_align(s_net, LV_ALIGN_LEFT_MID, 160, 0);

    s_clock = label(bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_clock, "--:--:--");
    lv_obj_align(s_clock, LV_ALIGN_RIGHT_MID, -92, 0);

    s_pill = lv_obj_create(bar);
    lv_obj_set_size(s_pill, 78, 24);
    lv_obj_align(s_pill, LV_ALIGN_RIGHT_MID, -6, 0);
    lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
    lv_obj_set_style_border_width(s_pill, 0, 0);
    lv_obj_set_style_radius(s_pill, 12, 0);
    lv_obj_set_style_pad_all(s_pill, 0, 0);
    lv_obj_clear_flag(s_pill, LV_OBJ_FLAG_SCROLLABLE);
    s_pill_lbl = label(s_pill, &lv_font_montserrat_14, COL_DARK);
    lv_label_set_text(s_pill_lbl, "ARMED");
    lv_obj_center(s_pill_lbl);

    // Incident card
    s_card = lv_obj_create(scr);
    lv_obj_set_size(s_card, 472, 180);
    lv_obj_align(s_card, LV_ALIGN_TOP_MID, 0, 38);
    lv_obj_set_style_bg_color(s_card, COL_CARD, 0);
    lv_obj_set_style_border_width(s_card, 2, 0);
    lv_obj_set_style_border_color(s_card, COL_GREEN, 0);
    lv_obj_set_style_radius(s_card, 8, 0);
    lv_obj_set_style_pad_all(s_card, 6, 0);
    lv_obj_clear_flag(s_card, LV_OBJ_FLAG_SCROLLABLE);

    s_c_head = label(s_card, &lv_font_montserrat_28, COL_GREEN);
    lv_obj_align(s_c_head, LV_ALIGN_TOP_LEFT, 0, 0);
    s_c_age = label(s_card, &lv_font_montserrat_20, COL_SUB);
    lv_obj_align(s_c_age, LV_ALIGN_TOP_RIGHT, 0, 4);
    s_c_src = label(s_card, &lv_font_montserrat_28, COL_TEXT);
    lv_obj_align(s_c_src, LV_ALIGN_TOP_LEFT, 0, 32);
    s_c_info = label(s_card, &lv_font_montserrat_20, COL_TEXT);
    lv_label_set_long_mode(s_c_info, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_c_info, 456);
    lv_obj_align(s_c_info, LV_ALIGN_TOP_LEFT, 0, 64);
    s_c_times = label(s_card, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_long_mode(s_c_times, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_c_times, 456);
    lv_obj_align(s_c_times, LV_ALIGN_TOP_LEFT, 0, 87);

    s_c_ack = card_button(s_card, COL_RED, &s_c_ack_lbl);
    lv_label_set_text(s_c_ack_lbl, TXT_ACK);
    lv_obj_add_event_cb(s_c_ack, ack_cb, LV_EVENT_LONG_PRESSED, NULL);
    s_c_rearm = card_button(s_card, COL_GREEN, &s_c_rearm_lbl);
    lv_label_set_text(s_c_rearm_lbl, TXT_REARM);
    lv_obj_add_event_cb(s_c_rearm, rearm_cb, LV_EVENT_ALL, NULL);

    // Key figures
    lv_obj_t *row = lv_obj_create(scr);
    lv_obj_set_size(row, 472, 26);
    lv_obj_align(row, LV_ALIGN_TOP_MID, 0, 221);
    lv_obj_set_style_bg_color(row, COL_CARD, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_t **fig[] = { &s_f_events, &s_f_sources, &s_f_sd, &s_f_wifi };
    for (size_t i = 0; i < sizeof(fig) / sizeof(fig[0]); i++) {
        *fig[i] = label(row, &lv_font_montserrat_14, COL_TEXT);
        lv_label_set_recolor(*fig[i], true);
    }

    // Last events
    s_feed = lv_list_create(scr);
    lv_obj_set_size(s_feed, 472, 70);
    lv_obj_align(s_feed, LV_ALIGN_TOP_MID, 0, 250);
    lv_obj_set_style_bg_color(s_feed, COL_BG, 0);
    lv_obj_set_style_border_width(s_feed, 0, 0);
    lv_obj_set_style_pad_all(s_feed, 0, 0);
    lv_obj_set_style_pad_row(s_feed, 2, 0);
    lv_obj_clear_flag(s_feed, LV_OBJ_FLAG_SCROLLABLE);

    s_feed_empty = label(scr, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(s_feed_empty, "Waiting for attackers...");
    lv_obj_align(s_feed_empty, LV_ALIGN_TOP_MID, 0, 270);

    // Incident overlay, above everything, strobing while unacknowledged
    s_overlay = lv_obj_create(lv_layer_top());
    lv_obj_set_size(s_overlay, 480, 320);
    lv_obj_center(s_overlay);
    lv_obj_set_style_bg_color(s_overlay, COL_STROBE, 0);
    lv_obj_set_style_bg_opa(s_overlay, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_overlay, 0, 0);
    lv_obj_set_style_radius(s_overlay, 0, 0);
    lv_obj_set_style_pad_all(s_overlay, 8, 0);
    lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_SCROLLABLE);

    s_ov_title = label(s_overlay, &lv_font_montserrat_28, COL_TEXT);
    lv_obj_align(s_ov_title, LV_ALIGN_TOP_MID, 0, 8);

    s_ov_src = label(s_overlay, &lv_font_montserrat_28, COL_TEXT);
    lv_obj_align(s_ov_src, LV_ALIGN_TOP_MID, 0, 50);

    s_ov_info = label(s_overlay, &lv_font_montserrat_20, COL_TEXT);
    lv_obj_set_style_text_align(s_ov_info, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(s_ov_info, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(s_ov_info, 464);
    lv_obj_align(s_ov_info, LV_ALIGN_TOP_MID, 0, 92);

    lv_obj_t *btn = lv_btn_create(s_overlay);
    lv_obj_set_size(btn, 400, 80);
    lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, -4);
    lv_obj_set_style_bg_color(btn, lv_color_white(), 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_add_event_cb(btn, ack_cb, LV_EVENT_LONG_PRESSED, NULL);
    s_ov_btn_lbl = label(btn, &lv_font_montserrat_20, COL_ACK_TXT);
    lv_label_set_text(s_ov_btn_lbl, TXT_OV_ACK);
    lv_obj_center(s_ov_btn_lbl);

    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
    build_ignore(btn);

    s_strobe = lv_timer_create(strobe_cb, STROBE_MS, NULL);
    lv_timer_pause(s_strobe);
    lv_timer_create(clock_cb, 1000, NULL);
    lv_timer_create(figures_cb, 2000, NULL);
}

// ── Task ──────────────────────────────────────────────────────────────────────

static void ui_task(void *arg)
{
    (void)arg;
    if (!display_init()) {
        ESP_LOGE(TAG, "No display: UI task exiting, honeypot keeps running");
        vTaskDelete(NULL);
        return;
    }
    size_t heap0 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    build_ui();

    // Count sources over the whole flash ring, and show the newest few events,
    // oldest first so the newest ends on top.
    attack_log_t *recent = heap_caps_malloc(sizeof(attack_log_t) * UI_SEED_ROWS,
                                            MALLOC_CAP_SPIRAM);
    if (recent) {
        int n = log_store_get_recent(recent, UI_SEED_ROWS);
        for (int i = 0; i < n; i++) source_add(recent[i].src_ip);
        for (int i = (n < UI_FEED_ROWS ? n : UI_FEED_ROWS) - 1; i >= 0; i--) feed_add(&recent[i]);
        heap_caps_free(recent);
    }
    refresh_figures();

    alarm_info_t a;
    alarm_get(&a);
    apply_alarm(&a);
    ESP_LOGI(TAG, "Panel built, internal heap %u B before, %u B after",
             (unsigned)heap0, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    int64_t last_us = esp_timer_get_time();
    for (;;) {
        umsg_t m;
        bool events = false;
        while (xQueueReceive(s_q, &m, 0) == pdTRUE) {
            switch (m.kind) {
            case UMSG_EVENT: feed_add(&m.e); source_add(m.e.src_ip); events = true; break;
            case UMSG_ALARM: apply_alarm(&m.a);              break;
            case UMSG_NET:   lv_label_set_text(s_net, m.net); break;
            }
        }
        if (events) refresh_counts();

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
