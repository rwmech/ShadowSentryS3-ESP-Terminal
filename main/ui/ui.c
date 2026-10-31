#include "ui.h"
#include "display.h"
#include "alarm.h"
#include "buzzer.h"
#include "log_store.h"
#include "sd_log.h"
#include "cam.h"
#include "wifi_manager.h"
#include "ignore.h"
#include "describe.h"
#include "discovery.h"
#include "tripwire.h"           // with http_engine.h and trap_listen.h: the port config
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
#define HOLD_MS         2000    // ACKNOWLEDGE and RE-ARM: a brush must not fire them
#define HOLD_DRAIN_MS   250     // an early release empties a full fill in this time

// Running light under the status bar: driven by an lv_timer on this task, so
// it stops moving if the UI task or the display hangs. Moving means alive.
#define RUNLIGHT_H          3       // px. Rob 2026-10-31: 3 to start
#define RUNLIGHT_Y          28      // just under the status bar
#define RUNLIGHT_HEAD_W     72      // bright head, 15 % of the width
#define RUNLIGHT_TRAIL_W    48      // fading trail behind it
#define RUNLIGHT_STEP_MS    33
#define RUNLIGHT_SWEEP_MS   2000    // armed, acknowledged: left to right, repeat
#define RUNLIGHT_ALARM_MS   700     // alarm: one way in 0.7 s, then back
#define UI_MEASURE_MS       10000   // boot: loop cost without, then with the light

// Side light bars while an incident is unacknowledged, in place of a
// full-screen strobe: a full repaint over SPI at 18 bpp is slow, and small
// flashing areas in bursts stay clear of photosensitivity limits. Left
// double-flashes red, then right double-flashes blue, 2 cycles a second.
// Each flash only recolours one bar, which nothing else overlaps, so LVGL
// redraws just that rectangle.
#define FLASH_W         40
#define FLASH_Y         (RUNLIGHT_Y + RUNLIGHT_H)   // full height below the light
#define FLASH_INSET     44      // the incident view keeps this clear of each edge
#define FLASH_TICK_MS   10      // timer period; the pattern is read off the tick
#define FLASH_SIDE_MS   250     // each side's half of the 500 ms cycle
#define FLASH_ON_MS     80      // on 80, off 60, on 80, then dark to the half's end
#define FLASH_OFF_MS    60
#define FLASH_MEASURE_MS 2000   // after the bars start: log their refresh cost

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
    "Port scan", "Probe", "ARP sweep", "ADB", "Tripwire", "Discovery",
};
static const char *TYPE_HEX[] = {   // same palette as the web dashboard
    "a78bfa", "fbbf24", "f87171", "38bdf8", "34d399", "f472b6", "fb923c", "a3e635",
    "22d3ee", "94a3b8", "e879f9", "3ddc84", "ef4444", "818cf8",
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
#define COL_FLASH_L lv_color_hex(0xff0000)   // left bar
#define COL_FLASH_R lv_color_hex(0x0040ff)   // right bar
#define HEX_SUB     "cbd5e1"                 // COL_SUB for label recolor

#define COL_FILL_ACK   lv_color_white()         // hold fill on the red ACKNOWLEDGE
#define COL_FILL_REARM lv_color_hex(0x0e8a4f)   // on the green RE-ARM; dark text stays readable

#define TXT_ACK     "ACKNOWLEDGE\n(hold 2 s)"
#define TXT_REARM   "RE-ARM\n(hold 2 s)"

// Layout
//
// Every state:
//   y   0..27   status bar: name, IP : port, clock, state pill (the only "ARMED")
//   y  28..30   running light (RUNLIGHT_H)
// ALARM or ACKED, x 44..435 (clear of the side bars):
//   y  33..204  incident card: headline and age, source, details, buttons
//   y 209..318  the incident's last 3 events
//   x 0..39 and 440..479, y 31..319: the side bars, while unacknowledged
// Armed (no incident): no card and no event list; under the light:
//   y  34..57   key figures
//   y  66..81   one muted line on the last incident, if there was one
//   y  82..316  the dashboard (build_dash(): today's tiers, 24 h chart,
//               watching panel, the newest alert or probe as a headline)
#define STATUS_H        28
#define INC_X           FLASH_INSET
#define INC_W           (480 - 2 * FLASH_INSET)         // 392
#define CARD_Y          33
#define CARD_H          172
#define CARD_INNER_W    (INC_W - 2 * 2 - 2 * 6)         // 376: border 2, padding 6
#define FEED_Y          209
#define FEED_H          110     // 3 rows of 34 px
#define FIG_Y_IDLE      34
#define FIG_H           24
#define LAST_Y_IDLE     66

// Incident card buttons, along the card's bottom edge. ACKNOWLEDGE and RE-ARM
// share the left slot (one shows at a time); the right slot, CARD_SLOT2_W wide,
// is kept free for a third button.
#define CARD_BTN_W      184
#define CARD_SLOT2_W    184
#define CARD_BTN_H      56

// Status bar
static lv_obj_t *s_net, *s_clock, *s_pill, *s_pill_lbl;
// Incident card
static lv_obj_t *s_card, *s_c_head, *s_c_age, *s_c_src, *s_c_info, *s_c_times;
static lv_obj_t *s_c_ack, *s_c_ack_lbl, *s_c_rearm, *s_c_rearm_lbl;

// A hold-to-confirm button: a fill grows across it over HOLD_MS while held,
// and done() runs when it reaches the end.
typedef struct {
    lv_obj_t *btn, *fill;
    void    (*done)(void);
    bool      holding;      // from press start until done, release or slide-off
} hold_t;
static hold_t s_h_ack, s_h_rearm;
// Key figures, and the armed screen's last-incident line
static lv_obj_t *s_figs, *s_f_events, *s_f_sources, *s_f_sd, *s_f_wifi;
static lv_obj_t *s_last;
// The incident's last events
static lv_obj_t *s_feed;
// Side light bars while unacknowledged
static lv_obj_t   *s_flash_l, *s_flash_r;
static lv_timer_t *s_flash;
static bool        s_flashing, s_flash_l_on, s_flash_r_on;
// Running light
static lv_obj_t   *s_rl_seg;
static lv_timer_t *s_rl;
static bool        s_rl_bounce;     // alarm: back and forth
static bool        s_rl_back;       // moving right to left, trail on the right
static lv_color_t  s_rl_col;        // the state colour

static alarm_info_t s_alarm;            // last state applied, for the age line
static char         s_open_hl[DESCRIBE_MAX];   // the incident's opening event, as a headline
static uint32_t     s_src[UI_SRC_MAX];  // distinct sources seen
static int          s_src_n;
static bool         s_src_more;

// Refresh timing: first flush start to last flush done, per refresh
static void (*s_flush_orig)(lv_disp_drv_t *, const lv_area_t *, lv_color_t *);
static int64_t  s_fl_t0, s_fl_t1;
static bool     s_fm_on;                // measuring, after the bars start
static uint32_t s_fm_start, s_fm_n, s_fm_px_max;
static int64_t  s_fm_sum, s_fm_max;

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

// ── The incident's last events ────────────────────────────────────────────────

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

    // The time, then the headline (describe_event() has no '#', the recolor marker).
    char t[12], hl[DESCRIBE_MAX], text[DESCRIBE_MAX + 24];
    fmt_time(e->timestamp, t, sizeof(t));
    describe_event(e, hl, sizeof(hl));
    snprintf(text, sizeof(text), "#%s %s#  %s", type_hex((uint8_t)e->type), t, hl);   // time in the type's colour

    lv_obj_t *btn = lv_list_add_btn(s_feed, NULL, text);
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    lv_label_set_recolor(lbl, true);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_bg_color(btn, COL_CARD, 0);
    lv_obj_set_style_text_color(btn, COL_TEXT, 0);
    lv_obj_set_style_text_font(btn, &lv_font_montserrat_14, 0);   // a headline fits the row
    lv_obj_set_style_pad_ver(btn, 9, 0);     // 34 px rows: a touch target
    lv_obj_set_style_pad_hor(btn, 6, 0);
    lv_obj_set_style_radius(btn, 4, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_set_user_data(btn, e);
    lv_obj_add_event_cb(btn, row_clicked_cb, LV_EVENT_CLICKED, e);
    lv_obj_add_event_cb(btn, row_deleted_cb, LV_EVENT_DELETE, e);
    lv_obj_move_to_index(btn, 0);            // newest on top

    while (lv_obj_get_child_cnt(s_feed) > UI_FEED_ROWS)
        lv_obj_del(lv_obj_get_child(s_feed, -1));
}

// The list shows only the current incident: its source, or anything since it
// opened (once the clock is set).
static bool feed_match(const attack_log_t *e)
{
    if (s_alarm.state == ALARM_IDLE) return false;
    if (e->src_ip == s_alarm.src_ip) return true;
    return s_alarm.first_ts >= 1600000000 && e->timestamp >= s_alarm.first_ts;
}

// The same event can reach the list twice: from the reseed (the flash ring)
// and from the queue, when the alarm's message overtook the event's.
static bool feed_has(const attack_log_t *e)
{
    for (uint32_t i = 0; i < lv_obj_get_child_cnt(s_feed); i++) {
        const attack_log_t *r = lv_obj_get_user_data(lv_obj_get_child(s_feed, (int32_t)i));
        if (r && r->timestamp == e->timestamp && r->src_ip == e->src_ip && r->type == e->type &&
            !strncmp(r->username, e->username, sizeof(r->username)) &&
            !strncmp(r->payload, e->payload, sizeof(r->payload)))
            return true;
    }
    return false;
}

// New incident, or none: refill the list from the flash ring, newest on top.
static void feed_reseed(void)
{
    lv_obj_clean(s_feed);                    // rows free their copies on delete
    s_open_hl[0] = '\0';
    if (s_alarm.state == ALARM_IDLE) return;
    attack_log_t *r = heap_caps_malloc(sizeof(*r) * UI_SEED_ROWS, MALLOC_CAP_SPIRAM);
    if (!r) return;
    int n = log_store_get_recent(r, UI_SEED_ROWS), pick[UI_FEED_ROWS], k = 0;
    for (int i = 0; i < n && k < UI_FEED_ROWS; i++)
        if (feed_match(&r[i])) pick[k++] = i;
    while (k-- > 0) feed_add(&r[pick[k]]);   // oldest first, so the newest ends on top
    // The opening event: same source and type, its first-seen time, else the
    // oldest such event still in the ring (newest first, so keep going back).
    const attack_log_t *open = NULL;
    for (int i = 0; i < n; i++) {
        if (r[i].src_ip != s_alarm.src_ip || (uint8_t)r[i].type != s_alarm.type) continue;
        open = &r[i];
        if (r[i].timestamp == s_alarm.first_ts) break;
    }
    if (open) describe_event(open, s_open_hl, sizeof(s_open_hl));
    heap_caps_free(r);
}

// ── Key figures ───────────────────────────────────────────────────────────────

// On every batch of events: cheap, in RAM.
static void set_text(lv_obj_t *l, const char *t);

static void refresh_counts(void)
{
    char b[48];
    snprintf(b, sizeof(b), "#" HEX_SUB " Events#  %lu", (unsigned long)log_store_total_count());
    set_text(s_f_events, b);
    snprintf(b, sizeof(b), "#" HEX_SUB " Sources#  %d%s", s_src_n, s_src_more ? "+" : "");
    set_text(s_f_sources, b);
}

// Every 2 s: the counts plus the microSD and Wi-Fi state. Unchanged text is
// not set again, so the row repaints only when a figure moves.
static void refresh_figures(void)
{
    refresh_counts();

    char b[48];
    sd_status_t sd;
    sd_log_status(&sd);
    if (sd.mounted) {
        unsigned long tenths = (unsigned long)(sd.free_bytes / 100000000ULL);   // 0.1 GB
        snprintf(b, sizeof(b), "#" HEX_SUB " SD#  %lu.%lu GB free", tenths / 10, tenths % 10);
    } else {
        strlcpy(b, "#" HEX_SUB " SD#  no card", sizeof(b));
    }
    set_text(s_f_sd, b);

    wifi_ap_record_t ap;
    if (wifi_manager_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        snprintf(b, sizeof(b), "#" HEX_SUB " Wi-Fi#  %d dBm", (int)ap.rssi);
    else
        strlcpy(b, "#" HEX_SUB " Wi-Fi#  --", sizeof(b));
    set_text(s_f_wifi, b);
}

static void dash_refresh(void);
static void kpi_seed_once(void);

static void figures_cb(lv_timer_t *t)
{
    (void)t;
    refresh_figures();
    kpi_seed_once();
    dash_refresh();
}

// ── Hold to confirm ───────────────────────────────────────────────────────────
//
// Press start (LV_EVENT_PRESSED) fires at once and starts the fill, an lv_anim
// on this task that grows a child of the button from 0 to its full width over
// HOLD_MS. Reaching the end runs done() and a confirm tone. Releasing, or
// sliding off the button, before then drains the fill with no action. LVGL's
// own long press is not used.

static void hold_fill_exec(void *var, int32_t w)
{
    lv_obj_set_width(((hold_t *)var)->fill, (lv_coord_t)w);
}

static void hold_full_cb(lv_anim_t *a)
{
    hold_t *h = (hold_t *)a->var;
    h->holding = false;
    buzzer_confirm();               // queued to the buzzer task, returns at once
    h->done();
}

static void hold_begin(hold_t *h)
{
    lv_anim_del(h, NULL);
    lv_obj_set_width(h->fill, 0);
    h->holding = true;

    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, h);
    lv_anim_set_exec_cb(&a, hold_fill_exec);
    lv_anim_set_values(&a, 0, lv_obj_get_width(h->btn));
    lv_anim_set_time(&a, HOLD_MS);
    lv_anim_set_path_cb(&a, lv_anim_path_linear);
    lv_anim_set_ready_cb(&a, hold_full_cb);
    lv_anim_start(&a);
}

static void hold_cancel(hold_t *h)
{
    if (!h->holding) return;
    h->holding = false;
    lv_anim_del(h, NULL);

    lv_coord_t w = lv_obj_get_width(h->fill), full = lv_obj_get_width(h->btn);
    if (w <= 0 || full <= 0) return;
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, h);
    lv_anim_set_exec_cb(&a, hold_fill_exec);
    lv_anim_set_values(&a, w, 0);
    lv_anim_set_time(&a, (uint32_t)HOLD_DRAIN_MS * (uint32_t)w / (uint32_t)full);
    lv_anim_set_path_cb(&a, lv_anim_path_ease_out);
    lv_anim_start(&a);
}

// New incident state: no fill left over from a hold on the old one.
static void hold_reset(hold_t *h)
{
    h->holding = false;
    lv_anim_del(h, NULL);
    lv_obj_set_width(h->fill, 0);
}

// PRESSING, RELEASED and PRESS_LOST on a hold button. LVGL keeps a pressed
// button pressed while the finger slides off it (PRESS_LOCK), so check here.
static void hold_track_cb(lv_event_t *ev)
{
    hold_t *h = (hold_t *)lv_event_get_user_data(ev);
    if (lv_event_get_code(ev) == LV_EVENT_PRESSING) {
        lv_point_t p;
        lv_indev_t *in = lv_indev_get_act();
        if (!h->holding || !in) return;
        lv_indev_get_point(in, &p);
        if (lv_obj_hit_test(h->btn, &p)) return;
    }
    hold_cancel(h);
}

static void ack_done(void)
{
    lv_label_set_text(s_c_ack_lbl, "Acknowledging...");
    alarm_ack();
}

static void rearm_done(void)
{
    lv_label_set_text(s_c_rearm_lbl, "Re-arming...");
    alarm_clear();
}

// ACKNOWLEDGE press start. The photo is taken here, while the person is
// still at the glass; the hold that follows decides whether the action
// fires. cam_snap() only queues, so it is safe on the UI task.
static void ack_press_start_cb(lv_event_t *ev)
{
    cam_snap("ack");
    hold_begin((hold_t *)lv_event_get_user_data(ev));
}

// RE-ARM press start: photo first, as for ACKNOWLEDGE.
static void rearm_press_start_cb(lv_event_t *ev)
{
    cam_snap("clear");
    hold_begin((hold_t *)lv_event_get_user_data(ev));
}

static void hold_attach(hold_t *h, lv_obj_t *btn, lv_obj_t *fill, void (*done)(void),
                        lv_event_cb_t press_start)
{
    h->btn = btn;
    h->fill = fill;
    h->done = done;
    lv_obj_add_event_cb(btn, press_start, LV_EVENT_PRESSED, h);
    lv_obj_add_event_cb(btn, hold_track_cb, LV_EVENT_PRESSING, h);
    lv_obj_add_event_cb(btn, hold_track_cb, LV_EVENT_RELEASED, h);
    lv_obj_add_event_cb(btn, hold_track_cb, LV_EVENT_PRESS_LOST, h);
}

// ── Running light ─────────────────────────────────────────────────────────────

// The segment is one object: a solid head and a trail that fades into the
// track, a horizontal gradient. Moving left, the gradient flips.
static void runlight_dir(bool back)
{
    const lv_color_t c = s_rl_col;
    const int trail = 255 * RUNLIGHT_TRAIL_W / (RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W);
    lv_obj_set_style_bg_color(s_rl_seg, back ? c : COL_BG, 0);
    lv_obj_set_style_bg_grad_color(s_rl_seg, back ? COL_BG : c, 0);
    lv_obj_set_style_bg_main_stop(s_rl_seg, back ? 255 - trail : 0, 0);
    lv_obj_set_style_bg_grad_stop(s_rl_seg, back ? 255 : trail, 0);
}

// Position from the tick, not a step count, so the speed holds if a step is late.
static void runlight_cb(lv_timer_t *t)
{
    (void)t;
    const int32_t w = RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W;
    uint32_t now = lv_tick_get();
    int32_t x;
    bool back = false;
    if (s_rl_bounce) {          // stays on screen, turns at each edge
        uint32_t ph = now % (2 * RUNLIGHT_ALARM_MS);
        back = ph >= RUNLIGHT_ALARM_MS;
        if (back) ph -= RUNLIGHT_ALARM_MS;
        int32_t d = (int32_t)((480 - w) * ph / RUNLIGHT_ALARM_MS);
        x = back ? (480 - w) - d : d;
    } else {                    // enters at the left edge, leaves at the right
        uint32_t ph = now % RUNLIGHT_SWEEP_MS;
        x = -w + (int32_t)((480 + w) * ph / RUNLIGHT_SWEEP_MS);
    }
    if (back != s_rl_back) {
        s_rl_back = back;
        runlight_dir(back);
    }
    lv_obj_set_x(s_rl_seg, (lv_coord_t)x);
}

static void runlight_set(lv_color_t c, bool bounce)
{
    s_rl_col = c;
    s_rl_bounce = bounce;
    if (!bounce) s_rl_back = false;
    runlight_dir(s_rl_back);
}

// ── Side light bars ───────────────────────────────────────────────────────────

// Only a change of state recolours a bar, so each flash edge invalidates one
// 40 x 289 rectangle and nothing else. Off is the background colour rather
// than hidden: the bar stays opaque, so LVGL draws only the bar there.
static void flash_cb(lv_timer_t *t)
{
    (void)t;
    uint32_t ph = lv_tick_get() % (2 * FLASH_SIDE_MS);
    bool right  = ph >= FLASH_SIDE_MS;
    uint32_t p  = ph % FLASH_SIDE_MS;
    bool on = p < FLASH_ON_MS ||
              (p >= FLASH_ON_MS + FLASH_OFF_MS && p < 2 * FLASH_ON_MS + FLASH_OFF_MS);
    bool l = on && !right, r = on && right;
    if (l != s_flash_l_on) {
        s_flash_l_on = l;
        lv_obj_set_style_bg_color(s_flash_l, l ? COL_FLASH_L : COL_BG, 0);
    }
    if (r != s_flash_r_on) {
        s_flash_r_on = r;
        lv_obj_set_style_bg_color(s_flash_r, r ? COL_FLASH_R : COL_BG, 0);
    }
}

// ── Ignore source (detect-core) ───────────────────────────────────────────────
//
// IGNORE SOURCE sits in the incident card's bottom-right slot (CARD_SLOT2_W x
// CARD_BTN_H), beside ACKNOWLEDGE / RE-ARM. A tap opens a confirmation; Ignore
// adds the source to the ignore list and, if the open incident is still from
// it, acknowledges and re-arms it so the siren and the side bars stop. The
// panel only adds: removal is on the dashboard.

static lv_obj_t *s_c_ignore;
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
    if (on) lv_obj_clear_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN);
    else    lv_obj_add_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN);
}

static void build_ignore(void)
{
    s_c_ignore = lv_btn_create(s_card);
    lv_obj_set_size(s_c_ignore, CARD_SLOT2_W, CARD_BTN_H);
    lv_obj_align(s_c_ignore, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(s_c_ignore, COL_SUB, 0);
    lv_obj_set_style_shadow_width(s_c_ignore, 0, 0);
    lv_obj_set_style_radius(s_c_ignore, 8, 0);
    lv_obj_set_style_pad_all(s_c_ignore, 0, 0);
    lv_obj_t *lbl = lv_label_create(s_c_ignore);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(lbl, COL_DARK, 0);
    lv_label_set_text(lbl, "IGNORE\nSOURCE");
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl);
    lv_obj_add_event_cb(s_c_ignore, ignore_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(s_c_ignore, LV_OBJ_FLAG_HIDDEN);
}

static void flash_set(bool on)
{
    if (on == s_flashing) return;
    s_flashing = on;
    s_flash_l_on = s_flash_r_on = false;
    lv_obj_set_style_bg_color(s_flash_l, COL_BG, 0);
    lv_obj_set_style_bg_color(s_flash_r, COL_BG, 0);
    if (on) {
        lv_obj_clear_flag(s_flash_l, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_flash_r, LV_OBJ_FLAG_HIDDEN);
        lv_timer_reset(s_flash);
        lv_timer_resume(s_flash);
        s_fm_on = true;                         // time the refreshes for a while
        s_fm_start = lv_tick_get();
        s_fm_n = s_fm_px_max = 0;
        s_fm_sum = s_fm_max = 0;
    } else {
        lv_timer_pause(s_flash);
        lv_obj_add_flag(s_flash_l, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_flash_r, LV_OBJ_FLAG_HIDDEN);
    }
    display_set_backlight_override(on);   // full on while unacknowledged, else the setting
}

// ── Refresh timing ────────────────────────────────────────────────────────────
//
// Wraps the display driver's flush (synchronous: it returns once the pixels
// are on the wire). A refresh runs from its first flush's start to its last
// flush's end, which the monitor callback closes.

static void flush_timed(lv_disp_drv_t *d, const lv_area_t *a, lv_color_t *px)
{
    if (!s_fl_t0) s_fl_t0 = esp_timer_get_time();
    s_flush_orig(d, a, px);
    s_fl_t1 = esp_timer_get_time();
}

static void refr_monitor_cb(lv_disp_drv_t *d, uint32_t ms, uint32_t px)
{
    (void)d; (void)ms;                      // ms is the LVGL tick, frozen in here
    int64_t us = s_fl_t0 ? s_fl_t1 - s_fl_t0 : 0;
    s_fl_t0 = 0;
    if (!s_fm_on || px == 0) return;
    s_fm_n++;
    s_fm_sum += us;
    if (us > s_fm_max) s_fm_max = us;
    if (px > s_fm_px_max) s_fm_px_max = px;
    if (lv_tick_elaps(s_fm_start) >= FLASH_MEASURE_MS) {
        s_fm_on = false;
        ESP_LOGI(TAG, "Side bars: %lu refreshes in %d ms, flush start to done avg %lld us, "
                 "max %lld us, up to %lu px (one bar is %d px)",
                 (unsigned long)s_fm_n, FLASH_MEASURE_MS, s_fm_sum / s_fm_n, s_fm_max,
                 (unsigned long)s_fm_px_max, FLASH_W * (320 - FLASH_Y));
    }
}

static void refr_timing_init(void)
{
    lv_disp_t *disp = lv_disp_get_default();
    if (!disp || !disp->driver || !disp->driver->flush_cb) return;
    s_flush_orig = disp->driver->flush_cb;
    disp->driver->flush_cb = flush_timed;
    disp->driver->monitor_cb = refr_monitor_cb;
}

// ── Armed dashboard ───────────────────────────────────────────────────────────
//
// What the armed screen shows under the key figures and the last-incident
// line: today's counts per tier and of port scans, attacks per hour over the
// last 24 h (sd_log_stats(), LAN discovery excluded), what the box is
// watching, and the newest alert or probe as a headline. All on this task;
// refreshed from the 2 s figures timer, each label only when its text changes
// and the chart only when a bar changes, so the SPI panel repaints little.

#define DASH_KPI_Y      82
#define DASH_KPI_H      50
#define DASH_MAIN_Y     136
#define DASH_MAIN_H     160
#define CHART_W         284
#define CHART_H         120     // the bars; title above, hour ticks below
#define WATCH_X         292
#define WATCH_W         184
#define DASH_LINE_Y     301
#define KPI_SRC_MAX     32      // sources counted today; more are not ranked
#define CHART_EVERY_MS  60000   // the hour can roll over with no new event
#define COL_CHART       lv_color_hex(0x38bdf8)

static lv_obj_t *s_idle;                    // the armed view: everything below the light
static lv_obj_t *s_kpi_val[4];
static lv_obj_t *s_chart, *s_chart_max, *s_chart_tick[4];
static lv_chart_series_t *s_chart_ser;
static lv_obj_t *s_w_listen, *s_w_up, *s_w_lan, *s_w_lan_new, *s_w_top_lbl, *s_w_top, *s_w_top_who;
static lv_obj_t *s_dash_line;
static sd_stats_t *s_stats;                 // PSRAM copy for the chart
static bool     s_chart_dirty = true;
static uint32_t s_chart_at, s_chart_hour;

// Today's counts, in RAM: seeded from the flash ring at boot, then one per
// event; reset at local midnight.
static struct {
    uint32_t day;                           // local YYYY*1000+yday, 0 = clock not set
    uint32_t tier[3];                       // alerts, probes, discovery
    uint32_t scans;
    struct { uint32_t ip; uint8_t mac[6]; uint32_t n; } src[KPI_SRC_MAX];
    int      src_n;
} s_kpi;
static attack_log_t s_last_atk;             // newest alert or probe; timestamp 0 = none

static uint32_t local_day(uint32_t ts)
{
    if (ts < 1600000000) return 0;
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    return (uint32_t)(tm.tm_year + 1900) * 1000u + (uint32_t)tm.tm_yday;
}

// The label's text, only if it differs: an unchanged label is not repainted.
static void set_text(lv_obj_t *l, const char *t)
{
    const char *o = lv_label_get_text(l);
    if (!o || strcmp(o, t)) lv_label_set_text(l, t);
}

static void kpi_roll(void)
{
    uint32_t today = local_day((uint32_t)time(NULL));
    if (today && today != s_kpi.day) {
        memset(&s_kpi, 0, sizeof(s_kpi));
        s_kpi.day = today;
    }
}

static void kpi_add(const attack_log_t *e)
{
    describe_tier_t t = describe_tier(e);
    if (t != TIER_SEV3 && e->timestamp >= s_last_atk.timestamp) s_last_atk = *e;
    if (t != TIER_SEV3) s_chart_dirty = true;

    kpi_roll();
    if (!s_kpi.day || local_day(e->timestamp) != s_kpi.day) return;   // not today
    s_kpi.tier[t - 1]++;
    if (e->type == ATTACK_SCAN && !strncmp(e->payload, "Port scan:", 10)) s_kpi.scans++;
    if (t == TIER_SEV3 || !e->src_ip) return;
    for (int i = 0; i < s_kpi.src_n; i++) {
        if (s_kpi.src[i].ip == e->src_ip) {
            s_kpi.src[i].n++;
            memcpy(s_kpi.src[i].mac, e->src_mac, 6);
            return;
        }
    }
    if (s_kpi.src_n < KPI_SRC_MAX) {
        s_kpi.src[s_kpi.src_n].ip = e->src_ip;
        memcpy(s_kpi.src[s_kpi.src_n].mac, e->src_mac, 6);
        s_kpi.src[s_kpi.src_n].n = 1;
        s_kpi.src_n++;
    }
}

// Once the clock is set: today's counts from the flash ring (the newest
// UI_SEED_ROWS events; a busier day starts short), oldest first.
static void kpi_seed_once(void)
{
    static bool done;
    if (done || time(NULL) < 1600000000) return;
    done = true;
    attack_log_t *r = heap_caps_malloc(sizeof(*r) * UI_SEED_ROWS, MALLOC_CAP_SPIRAM);
    if (!r) return;
    int n = log_store_get_recent(r, UI_SEED_ROWS);
    memset(&s_kpi, 0, sizeof(s_kpi));
    for (int i = n - 1; i >= 0; i--) kpi_add(&r[i]);
    heap_caps_free(r);
}

// Trap and tripwire ports configured on (a port that failed to bind still counts).
static int listening_ports(void)
{
    static const uint16_t P[] = {
        RTSP_PORT, HTTP_PORT, TELNET_PORT, SSH_PORT, FTP_PORT, TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT,
#if HTTP_ENGINE_ENABLE
        HTTP_ALT_PORT1, HTTP_ALT_PORT2, HTTP_ALT_PORT3,
#endif
#if TRIPWIRE_ENABLE
        TRIPWIRE_RDP_PORT, TRIPWIRE_VNC_PORT, TRIPWIRE_SMB_PORT, TRIPWIRE_REDIS_PORT,
        TRIPWIRE_MYSQL_PORT, TRIPWIRE_MSSQL_PORT, TRIPWIRE_JETDIRECT_PORT,
#endif
    };
    int n = 0;
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) if (P[i]) n++;
    return n;
}

static void fmt_span(uint32_t s, char *buf, size_t len)
{
    if (s >= 86400)     snprintf(buf, len, "%lud %02luh", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600));
    else if (s >= 3600) snprintf(buf, len, "%luh %02lum", (unsigned long)(s / 3600), (unsigned long)(s % 3600 / 60));
    else                snprintf(buf, len, "%lum", (unsigned long)(s / 60));
}

// Attacks per hour, oldest left. Repaints only when a bar or the hour changed.
static void chart_update(void)
{
    if (!s_stats) return;
    uint32_t now = (uint32_t)time(NULL);
    if (now < 1600000000) return;           // no clock, no hours
    sd_log_stats(s_stats);
    uint32_t hour = now / 3600, max = 0;
    bool diff = false;
    lv_coord_t *ys = lv_chart_get_y_array(s_chart, s_chart_ser);
    for (int i = 0; i < 24; i++) {
        uint32_t h = hour - 23 + (uint32_t)i, slot = h % 24;
        uint32_t v = s_stats->hour_key[slot] == h ? s_stats->hour_count[slot] : 0;
        if (v > max) max = v;
        if (v > 30000) v = 30000;
        if (ys[i] != (lv_coord_t)v) { ys[i] = (lv_coord_t)v; diff = true; }
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "max %lu", (unsigned long)max);
    set_text(s_chart_max, buf);
    if (hour != s_chart_hour) {             // the 0, 6, 12, 18 ticks move with the hour
        s_chart_hour = hour;
        lv_obj_update_layout(s_chart);
        lv_coord_t w = lv_obj_get_content_width(s_chart), x0 = lv_obj_get_x(s_chart);
        int k = 0;
        for (int i = 0; i < 24 && k < 4; i++) {
            time_t t = (time_t)(hour - 23 + (uint32_t)i) * 3600;
            struct tm tm;
            localtime_r(&t, &tm);
            if (tm.tm_hour % 6) continue;
            snprintf(buf, sizeof(buf), "%d", tm.tm_hour);
            set_text(s_chart_tick[k], buf);
            lv_obj_set_x(s_chart_tick[k], x0 + (lv_coord_t)(w * (2 * i + 1) / 48) - 6);
            k++;
        }
        diff = true;
    }
    if (diff) {
        lv_chart_set_range(s_chart, LV_CHART_AXIS_PRIMARY_Y, 0, max < 4 ? 4 : (lv_coord_t)(max > 30000 ? 30000 : max));
        lv_chart_refresh(s_chart);
    }
}

static void dash_refresh(void)
{
    if (lv_obj_has_flag(s_idle, LV_OBJ_FLAG_HIDDEN)) return;
    char buf[DESCRIBE_MAX + 32], ago[24];
    kpi_roll();
    for (int i = 0; i < 4; i++) {
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)(i < 3 ? s_kpi.tier[i] : s_kpi.scans));
        set_text(s_kpi_val[i], buf);
    }

    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000LL);
    fmt_span(up, buf, sizeof(buf));
    set_text(s_w_up, buf);

    char lab[40];
    uint32_t first_up = 0;
    int devs = discovery_summary(lab, sizeof(lab), &first_up);
    snprintf(buf, sizeof(buf), "%d", devs);
    set_text(s_w_lan, buf);
    if (devs && lab[0]) {
        fmt_span(up > first_up ? up - first_up : 0, ago, sizeof(ago));
        for (char *c = lab; *c; c++) if (*c == '#') *c = ' ';
        snprintf(buf, sizeof(buf), "newest %s, %s ago", lab, ago);
    } else {
        strlcpy(buf, "none yet", sizeof(buf));
    }
    set_text(s_w_lan_new, buf);

    int top = -1;
    for (int i = 0; i < s_kpi.src_n; i++) if (top < 0 || s_kpi.src[i].n > s_kpi.src[top].n) top = i;
    if (top >= 0) {
        char ip[16];
        fmt_ip(s_kpi.src[top].ip, ip, sizeof(ip));
        snprintf(buf, sizeof(buf), "Top source today, %lu", (unsigned long)s_kpi.src[top].n);
        set_text(s_w_top_lbl, buf);
        set_text(s_w_top, ip);
        const char *v = wifi_manager_mac_vendor(s_kpi.src[top].mac);
        set_text(s_w_top_who, v[0] ? v : "vendor unknown");
    } else {
        set_text(s_w_top_lbl, "Top source today");
        set_text(s_w_top, "none");
        set_text(s_w_top_who, "");
    }

    if (s_last_atk.timestamp) {
        char hl[DESCRIBE_MAX];
        describe_event(&s_last_atk, hl, sizeof(hl));
        time_t now = time(NULL);
        if (s_last_atk.timestamp >= 1600000000 && now >= (time_t)s_last_atk.timestamp) {
            fmt_span((uint32_t)(now - (time_t)s_last_atk.timestamp), ago, sizeof(ago));
            snprintf(buf, sizeof(buf), "%s ago:  %s", ago, hl);
        } else {
            strlcpy(buf, hl, sizeof(buf));
        }
    } else {
        strlcpy(buf, "No attacks yet", sizeof(buf));
    }
    set_text(s_dash_line, buf);

    if (s_chart_dirty || lv_tick_elaps(s_chart_at) >= CHART_EVERY_MS) {
        s_chart_dirty = false;
        s_chart_at = lv_tick_get();
        chart_update();
    }
}

// ── Alarm ─────────────────────────────────────────────────────────────────────

// Every second: the incident's age on the card, or when armed, the line on the
// last incident with how long ago it was last seen (left out before SNTP).
static void refresh_age(void)
{
    char age[24] = "";
    if (s_alarm.state != ALARM_IDLE) {
        fmt_age(s_alarm.first_ts, age, sizeof(age));
        set_text(s_c_age, age);
        return;
    }
    if (!s_alarm.id) { set_text(s_last, ""); return; }
    char ip[16];
    fmt_ip(s_alarm.src_ip, ip, sizeof(ip));
    time_t now = time(NULL);
    if (s_alarm.last_ts >= 1600000000 && now >= (time_t)s_alarm.last_ts) {
        unsigned long d = (unsigned long)(now - (time_t)s_alarm.last_ts);
        if (d < 60)         snprintf(age, sizeof(age), ", %lus ago", d);
        else if (d < 3600)  snprintf(age, sizeof(age), ", %lum ago", d / 60);
        else if (d < 86400) snprintf(age, sizeof(age), ", %luh %02lum ago", d / 3600, d % 3600 / 60);
        else                snprintf(age, sizeof(age), ", %lud ago", d / 86400);
    }
    char buf[DESCRIBE_MAX];
    snprintf(buf, sizeof(buf), "Last incident #%lu, %s from %s%s",
             (unsigned long)s_alarm.id, type_name(s_alarm.type), ip, age);
    set_text(s_last, buf);
}

// The two views. Each sets every widget's visibility and position itself, so
// no path into a state relies on what an earlier one toggled.
static void view_incident(void)
{
    lv_obj_clear_flag(s_card, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_feed, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_idle, LV_OBJ_FLAG_HIDDEN);
}

static void view_armed(bool last)
{
    lv_obj_add_flag(s_card, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_feed, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_c_ack, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_c_rearm, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_idle, LV_OBJ_FLAG_HIDDEN);
    lv_obj_align(s_figs, LV_ALIGN_TOP_MID, 0, FIG_Y_IDLE);
    lv_obj_clear_flag(s_figs, LV_OBJ_FLAG_HIDDEN);
    lv_obj_align(s_last, LV_ALIGN_TOP_MID, 0, LAST_Y_IDLE);
    if (last) lv_obj_clear_flag(s_last, LV_OBJ_FLAG_HIDDEN);
    else      lv_obj_add_flag(s_last, LV_OBJ_FLAG_HIDDEN);
    s_chart_dirty = true;                   // the chart was not kept up while hidden
    dash_refresh();
}

// Once per state change: what the panel now renders, with the figures row's
// placement, so a console capture shows it.
static void log_view(void)
{
    static const char *NAME[] = { "ARMED", "ALARM", "ACKED" };
    lv_obj_update_layout(lv_scr_act());
    lv_area_t f;
    lv_obj_get_coords(s_figs, &f);
    bool dash = !lv_obj_has_flag(s_idle, LV_OBJ_FLAG_HIDDEN);
    ESP_LOGI(TAG, "UI state: %s #%lu, card %s, events %s, dashboard %s, figures %s at y %d..%d, last line %s",
             s_alarm.state <= ALARM_ACKED ? NAME[s_alarm.state] : "?", (unsigned long)s_alarm.id,
             lv_obj_has_flag(s_card, LV_OBJ_FLAG_HIDDEN) ? "hidden" : "shown",
             lv_obj_has_flag(s_feed, LV_OBJ_FLAG_HIDDEN) ? "hidden" : "shown",
             dash ? "shown" : "hidden",
             dash && !lv_obj_has_flag(s_figs, LV_OBJ_FLAG_HIDDEN) ? "shown" : "hidden", f.y1, f.y2,
             dash && !lv_obj_has_flag(s_last, LV_OBJ_FLAG_HIDDEN) ? "shown" : "hidden");
}

static void apply_alarm(const alarm_info_t *a)
{
    char ip[16], mac[WIFI_MAC_STR_LEN], t0[12], t1[12];
    fmt_ip(a->src_ip, ip, sizeof(ip));
    wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
    fmt_time(a->first_ts, t0, sizeof(t0));
    fmt_time(a->last_ts, t1, sizeof(t1));
    // Count updates (up to 1/s during a scan) must not reset a button label or
    // a fill mid-press: those go back to their start only on a new state.
    bool changed = a->state != s_alarm.state || a->id != s_alarm.id;
    bool reseed  = a->id != s_alarm.id || (a->state == ALARM_IDLE) != (s_alarm.state == ALARM_IDLE);
    s_alarm = *a;
    if (changed) {
        hold_reset(&s_h_ack);
        hold_reset(&s_h_rearm);
    }
    if (reseed) feed_reseed();              // also finds the opening event's headline

    if (a->state == ALARM_ACTIVE || a->state == ALARM_ACKED) {
        bool active = a->state == ALARM_ACTIVE;
        lv_color_t acc = active ? COL_RED : COL_AMBER;
        lv_obj_set_style_bg_color(s_pill, acc, 0);
        lv_label_set_text(s_pill_lbl, active ? "ALARM" : "ACKED");
        lv_obj_set_style_border_color(s_card, acc, 0);
        lv_obj_set_style_text_color(s_c_head, acc, 0);
        lv_label_set_text_fmt(s_c_head, "Incident #%lu", (unsigned long)a->id);   // the pill says the state
        lv_label_set_text(s_c_src, ip);
        char info[DESCRIBE_MAX + 48];
        if (s_open_hl[0]) set_text(s_c_info, s_open_hl);
        else {
            snprintf(info, sizeof(info), "%s from %s", type_name(a->type), ip);
            set_text(s_c_info, info);
        }
        snprintf(info, sizeof(info), "%s, %lu event%s,  MAC %s  %s,  %s to %s", type_name(a->type),
                 (unsigned long)a->count, a->count == 1 ? "" : "s",
                 mac, wifi_manager_mac_vendor(a->src_mac), t0, t1);
        set_text(s_c_times, info);
        runlight_set(acc, active);
        view_incident();
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
        // Armed: the pill alone says so. No card and no event list; the key
        // figures, and one muted line on the last incident if there was one.
        lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
        lv_label_set_text(s_pill_lbl, "ARMED");
        runlight_set(COL_GREEN, false);
        view_armed(a->id != 0);
    }
    refresh_age();
    flash_set(a->state == ALARM_ACTIVE);
    ignore_show(a->state == ALARM_ACTIVE || a->state == ALARM_ACKED);
    // A new view repaints the whole screen once (a few hundred ms over SPI, only
    // on a state change), so no area keeps pixels from the old one.
    static bool logged;
    if (changed || !logged) {
        logged = true;
        lv_obj_invalidate(lv_scr_act());
        log_view();
    }
}

// ── Layout ────────────────────────────────────────────────────────────────────

static lv_obj_t *label(lv_obj_t *parent, const lv_font_t *font, lv_color_t col)
{
    lv_obj_t *l = lv_label_create(parent);
    lv_label_set_text(l, "");
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, col, 0);
    return l;
}

// A plain box: no border, padding, scrolling or touch.
static lv_obj_t *box(lv_obj_t *parent, lv_color_t bg)
{
    lv_obj_t *o = lv_obj_create(parent);
    lv_obj_set_style_bg_color(o, bg, 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(o, 0, 0);
    lv_obj_set_style_radius(o, 0, 0);
    lv_obj_set_style_pad_all(o, 0, 0);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    return o;
}

// An incident card hold button: base colour, and a fill (width 0) drawn under
// the label. Hidden until its state.
static lv_obj_t *card_button(lv_obj_t *parent, lv_color_t base, lv_color_t fill_col,
                             lv_obj_t **fill, lv_obj_t **lbl)
{
    lv_obj_t *b = lv_btn_create(parent);
    lv_obj_set_size(b, CARD_BTN_W, CARD_BTN_H);
    lv_obj_align(b, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(b, base, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_pad_all(b, 0, 0);
    *fill = box(b, fill_col);
    lv_obj_set_style_radius(*fill, 8, 0);
    lv_obj_set_size(*fill, 0, LV_PCT(100));
    lv_obj_align(*fill, LV_ALIGN_LEFT_MID, 0, 0);
    *lbl = label(b, &lv_font_montserrat_20, COL_DARK);
    lv_obj_set_style_text_align(*lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(*lbl);
    lv_obj_add_flag(b, LV_OBJ_FLAG_HIDDEN);
    return b;
}

// Every second. Also re-reads the alarm state: its change messages are sent to
// the UI queue without waiting, so one can be dropped behind a burst of
// events, and the panel must not stay on a stale view.
static void clock_cb(lv_timer_t *t)
{
    (void)t;
    char buf[12];
    fmt_time((uint32_t)time(NULL), buf, sizeof(buf));
    lv_label_set_text(s_clock, buf);
    alarm_info_t a;
    alarm_get(&a);
    if (a.state != s_alarm.state || a.id != s_alarm.id) {
        ESP_LOGW(TAG, "Alarm state ahead of the UI queue (message dropped or late), applying it now");
        apply_alarm(&a);
    }
    refresh_age();
}

// A name on the left (14 px, muted) and its value right-aligned (20 px).
static lv_obj_t *watch_row(lv_coord_t y, const char *name)
{
    lv_obj_t *n = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(n, name);
    lv_obj_set_pos(n, WATCH_X + 6, y + 3);
    lv_obj_t *v = label(s_idle, &lv_font_montserrat_20, COL_TEXT);
    lv_obj_set_width(v, 90);
    lv_obj_set_style_text_align(v, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_pos(v, WATCH_X + WATCH_W - 6 - 90, y);
    return v;
}

// The armed dashboard, below the key figures and the last-incident line:
//   y  82..131  today: alerts, probes, discovery, port scans (4 tiles)
//   y 136..295  attacks per hour, 24 h (x 4..287) | watching (x 292..475)
//   y 301..316  the newest alert or probe, as a headline
static void build_dash(void)
{
    static const char *KPI[4] = { "Alerts today", "Probes today", "Discovery today", "Port scans today" };
    for (int i = 0; i < 4; i++) {
        lv_obj_t *t = box(s_idle, COL_CARD);
        lv_obj_set_size(t, 115, DASH_KPI_H);
        lv_obj_set_pos(t, 4 + i * 119, DASH_KPI_Y);
        lv_obj_set_style_radius(t, 6, 0);
        lv_obj_t *n = label(t, &lv_font_montserrat_14, COL_SUB);
        lv_label_set_text(n, KPI[i]);
        lv_obj_set_pos(n, 6, 2);
        s_kpi_val[i] = label(t, &lv_font_montserrat_28, COL_TEXT);
        lv_label_set_text(s_kpi_val[i], "0");
        lv_obj_set_pos(s_kpi_val[i], 6, 18);
    }

    lv_obj_t *cp = box(s_idle, COL_CARD);
    lv_obj_set_size(cp, CHART_W, DASH_MAIN_H);
    lv_obj_set_pos(cp, 4, DASH_MAIN_Y);
    lv_obj_set_style_radius(cp, 6, 0);
    lv_obj_t *title = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(title, "Attacks per hour, 24 h");
    lv_obj_set_pos(title, 10, DASH_MAIN_Y + 3);
    s_chart_max = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_obj_set_width(s_chart_max, 80);
    lv_obj_set_style_text_align(s_chart_max, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_pos(s_chart_max, 4 + CHART_W - 6 - 80, DASH_MAIN_Y + 3);

    s_chart = lv_chart_create(s_idle);
    lv_obj_set_size(s_chart, CHART_W - 12, CHART_H);
    lv_obj_set_pos(s_chart, 10, DASH_MAIN_Y + 20);
    lv_chart_set_type(s_chart, LV_CHART_TYPE_BAR);
    lv_chart_set_point_count(s_chart, 24);
    lv_chart_set_div_line_count(s_chart, 3, 0);
    lv_obj_set_style_bg_opa(s_chart, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_chart, 0, 0);
    lv_obj_set_style_radius(s_chart, 0, 0);
    lv_obj_set_style_pad_all(s_chart, 0, 0);
    lv_obj_set_style_pad_column(s_chart, 2, 0);            // gap between the bars
    lv_obj_set_style_line_color(s_chart, lv_color_hex(0x334155), 0);
    lv_obj_set_style_radius(s_chart, 0, LV_PART_ITEMS);
    lv_obj_clear_flag(s_chart, LV_OBJ_FLAG_CLICKABLE | LV_OBJ_FLAG_SCROLLABLE);
    s_chart_ser = lv_chart_add_series(s_chart, COL_CHART, LV_CHART_AXIS_PRIMARY_Y);
    lv_chart_set_all_value(s_chart, s_chart_ser, 0);
    lv_chart_set_range(s_chart, LV_CHART_AXIS_PRIMARY_Y, 0, 4);
    for (int i = 0; i < 4; i++) {
        s_chart_tick[i] = label(s_idle, &lv_font_montserrat_12, COL_SUB);
        lv_obj_set_pos(s_chart_tick[i], 10, DASH_MAIN_Y + 20 + CHART_H + 2);
    }
    s_stats = heap_caps_malloc(sizeof(*s_stats), MALLOC_CAP_SPIRAM);

    lv_obj_t *wp = box(s_idle, COL_CARD);
    lv_obj_set_size(wp, WATCH_W, DASH_MAIN_H);
    lv_obj_set_pos(wp, WATCH_X, DASH_MAIN_Y);
    lv_obj_set_style_radius(wp, 6, 0);
    char buf[16];
    s_w_listen = watch_row(DASH_MAIN_Y + 4, "Listening");
    snprintf(buf, sizeof(buf), "%d ports", listening_ports());
    lv_label_set_text(s_w_listen, buf);
    s_w_up  = watch_row(DASH_MAIN_Y + 28, "Uptime");
    s_w_lan = watch_row(DASH_MAIN_Y + 52, "LAN devices");
    s_w_lan_new = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_long_mode(s_w_lan_new, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_w_lan_new, WATCH_W - 12);
    lv_obj_set_pos(s_w_lan_new, WATCH_X + 6, DASH_MAIN_Y + 75);
    s_w_top_lbl = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_obj_set_pos(s_w_top_lbl, WATCH_X + 6, DASH_MAIN_Y + 96);
    s_w_top = label(s_idle, &lv_font_montserrat_20, COL_TEXT);
    lv_obj_set_pos(s_w_top, WATCH_X + 6, DASH_MAIN_Y + 113);
    s_w_top_who = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_long_mode(s_w_top_who, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_w_top_who, WATCH_W - 12);
    lv_obj_set_pos(s_w_top_who, WATCH_X + 6, DASH_MAIN_Y + 137);

    s_dash_line = label(s_idle, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_long_mode(s_dash_line, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_dash_line, 468);
    lv_obj_set_pos(s_dash_line, 6, DASH_LINE_Y);
}

static void build_ui(void)
{
    lv_obj_t *scr = lv_scr_act();
    lv_obj_set_style_bg_color(scr, COL_BG, 0);
    lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

    // Status bar
    lv_obj_t *bar = box(scr, COL_CARD);
    lv_obj_set_size(bar, 480, STATUS_H);
    lv_obj_align(bar, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *brand = label(bar, &lv_font_montserrat_20, COL_GREEN);
    lv_label_set_text(brand, "ShadowSentry");
    lv_obj_align(brand, LV_ALIGN_LEFT_MID, 6, 0);

    s_net = label(bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_net, "Starting...");
    lv_obj_align(s_net, LV_ALIGN_LEFT_MID, 160, 0);

    s_clock = label(bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_clock, "--:--:--");
    lv_obj_align(s_clock, LV_ALIGN_RIGHT_MID, -112, 0);

    s_pill = box(bar, COL_GREEN);               // nearly the bar's height, 20 px text
    lv_obj_set_size(s_pill, 104, 24);
    lv_obj_align(s_pill, LV_ALIGN_RIGHT_MID, -2, 0);
    lv_obj_set_style_radius(s_pill, 12, 0);
    // Dark text on every fill (green, red, amber), set on the pill too so
    // nothing inherited can lighten it.
    lv_obj_set_style_text_color(s_pill, COL_DARK, 0);
    s_pill_lbl = label(s_pill, &lv_font_montserrat_20, COL_DARK);
    lv_obj_set_style_text_opa(s_pill_lbl, LV_OPA_COVER, 0);
    lv_label_set_text(s_pill_lbl, "ARMED");
    lv_obj_center(s_pill_lbl);

    // Incident card, clear of the side bars
    s_card = lv_obj_create(scr);
    lv_obj_set_size(s_card, INC_W, CARD_H);
    lv_obj_set_pos(s_card, INC_X, CARD_Y);
    lv_obj_set_style_bg_color(s_card, COL_CARD, 0);
    lv_obj_set_style_border_width(s_card, 2, 0);
    lv_obj_set_style_border_color(s_card, COL_RED, 0);
    lv_obj_set_style_radius(s_card, 8, 0);
    lv_obj_set_style_pad_ver(s_card, 4, 0);
    lv_obj_set_style_pad_hor(s_card, 6, 0);
    lv_obj_clear_flag(s_card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_card, LV_OBJ_FLAG_HIDDEN);   // shown during an incident

    s_c_head = label(s_card, &lv_font_montserrat_28, COL_RED);
    lv_obj_align(s_c_head, LV_ALIGN_TOP_LEFT, 0, 0);
    s_c_age = label(s_card, &lv_font_montserrat_20, COL_SUB);
    lv_obj_align(s_c_age, LV_ALIGN_TOP_RIGHT, 0, 4);
    s_c_src = label(s_card, &lv_font_montserrat_28, COL_TEXT);
    lv_obj_align(s_c_src, LV_ALIGN_TOP_LEFT, 0, 30);
    s_c_info = label(s_card, &lv_font_montserrat_20, COL_TEXT);
    lv_label_set_long_mode(s_c_info, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_c_info, CARD_INNER_W);
    lv_obj_align(s_c_info, LV_ALIGN_TOP_LEFT, 0, 62);
    s_c_times = label(s_card, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_long_mode(s_c_times, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_c_times, CARD_INNER_W);
    lv_obj_align(s_c_times, LV_ALIGN_TOP_LEFT, 0, 85);

    lv_obj_t *fill;
    s_c_ack = card_button(s_card, COL_RED, COL_FILL_ACK, &fill, &s_c_ack_lbl);
    lv_label_set_text(s_c_ack_lbl, TXT_ACK);
    hold_attach(&s_h_ack, s_c_ack, fill, ack_done, ack_press_start_cb);
    s_c_rearm = card_button(s_card, COL_GREEN, COL_FILL_REARM, &fill, &s_c_rearm_lbl);
    lv_label_set_text(s_c_rearm_lbl, TXT_REARM);
    hold_attach(&s_h_rearm, s_c_rearm, fill, rearm_done, rearm_press_start_cb);
    // The bottom-right slot, CARD_SLOT2_W x CARD_BTN_H, is free for a third button.

    // The incident's last events, clear of the side bars
    s_feed = lv_list_create(scr);
    lv_obj_set_size(s_feed, INC_W, FEED_H);
    lv_obj_set_pos(s_feed, INC_X, FEED_Y);
    lv_obj_set_style_bg_color(s_feed, COL_BG, 0);
    lv_obj_set_style_border_width(s_feed, 0, 0);
    lv_obj_set_style_pad_all(s_feed, 0, 0);
    lv_obj_set_style_pad_row(s_feed, 2, 0);
    lv_obj_clear_flag(s_feed, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_feed, LV_OBJ_FLAG_HIDDEN);   // shown during an incident

    // Armed view: one transparent, untouchable container for all of it, so the
    // views switch with one flag.
    s_idle = lv_obj_create(scr);
    lv_obj_remove_style_all(s_idle);
    lv_obj_set_size(s_idle, 480, 320);
    lv_obj_set_pos(s_idle, 0, 0);
    lv_obj_clear_flag(s_idle, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

    // Armed: key figures
    s_figs = box(s_idle, COL_CARD);
    lv_obj_set_size(s_figs, 472, FIG_H);
    lv_obj_align(s_figs, LV_ALIGN_TOP_MID, 0, FIG_Y_IDLE);
    lv_obj_set_style_radius(s_figs, 6, 0);
    lv_obj_set_flex_flow(s_figs, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(s_figs, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t **fig[] = { &s_f_events, &s_f_sources, &s_f_sd, &s_f_wifi };
    for (size_t i = 0; i < sizeof(fig) / sizeof(fig[0]); i++) {
        *fig[i] = label(s_figs, &lv_font_montserrat_14, COL_TEXT);
        lv_label_set_recolor(*fig[i], true);
    }

    // Armed: the last incident, one muted line
    s_last = label(s_idle, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_long_mode(s_last, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_last, 464);
    lv_obj_set_style_text_align(s_last, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_last, LV_ALIGN_TOP_MID, 0, LAST_Y_IDLE);

    build_dash();

    // Running light: a dark track the full width, and the moving segment on it.
    // On the top layer, so a detail box opened from the list cannot stop it.
    lv_obj_t *track = box(lv_layer_top(), COL_BG);
    lv_obj_set_size(track, 480, RUNLIGHT_H);
    lv_obj_set_pos(track, 0, RUNLIGHT_Y);
    s_rl_seg = box(track, COL_BG);
    lv_obj_set_size(s_rl_seg, RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W, RUNLIGHT_H);
    lv_obj_set_style_bg_grad_dir(s_rl_seg, LV_GRAD_DIR_HOR, 0);
    lv_obj_set_pos(s_rl_seg, -(RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W), 0);
    runlight_set(COL_GREEN, false);
    s_rl = lv_timer_create(runlight_cb, RUNLIGHT_STEP_MS, NULL);

    // Side light bars, top layer too, hidden until an incident is unacknowledged
    s_flash_l = box(lv_layer_top(), COL_BG);
    lv_obj_set_size(s_flash_l, FLASH_W, 320 - FLASH_Y);
    lv_obj_set_pos(s_flash_l, 0, FLASH_Y);
    lv_obj_add_flag(s_flash_l, LV_OBJ_FLAG_HIDDEN);
    s_flash_r = box(lv_layer_top(), COL_BG);
    lv_obj_set_size(s_flash_r, FLASH_W, 320 - FLASH_Y);
    lv_obj_set_pos(s_flash_r, 480 - FLASH_W, FLASH_Y);
    lv_obj_add_flag(s_flash_r, LV_OBJ_FLAG_HIDDEN);
    s_flash = lv_timer_create(flash_cb, FLASH_TICK_MS, NULL);
    lv_timer_pause(s_flash);

    build_ignore();
    lv_timer_create(clock_cb, 1000, NULL);
    lv_timer_create(figures_cb, 2000, NULL);
}

// ── Task ──────────────────────────────────────────────────────────────────────

// Boot measurement of the loop's own cost: UI_MEASURE_MS with the running
// light paused, then as long with it running, then one log line. Wall time
// around lv_timer_handler(), so preemption by busier tasks counts in it.
typedef struct { uint32_t n; uint64_t sum; uint32_t max; } loop_stat_t;

static void loop_measure(uint32_t us)
{
    static int phase;                   // 0 light paused, 1 running, 2 done
    static uint32_t t0;
    static loop_stat_t st[2];
    if (phase == 2) return;
    if (!t0) { t0 = lv_tick_get(); lv_timer_pause(s_rl); }
    st[phase].n++;
    st[phase].sum += us;
    if (us > st[phase].max) st[phase].max = us;
    if (lv_tick_elaps(t0) < UI_MEASURE_MS) return;
    t0 = lv_tick_get();
    if (++phase == 1) { lv_timer_resume(s_rl); return; }
    ESP_LOGI(TAG, "UI loop, lv_timer_handler: without the running light %lu calls, avg %lu us, "
             "max %lu us; with it %lu calls, avg %lu us, max %lu us",
             (unsigned long)st[0].n, (unsigned long)(st[0].sum / st[0].n), (unsigned long)st[0].max,
             (unsigned long)st[1].n, (unsigned long)(st[1].sum / st[1].n), (unsigned long)st[1].max);
}

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
    refr_timing_init();

    // Count sources over the whole flash ring. The event list fills when an
    // incident is applied.
    attack_log_t *recent = heap_caps_malloc(sizeof(attack_log_t) * UI_SEED_ROWS,
                                            MALLOC_CAP_SPIRAM);
    if (recent) {
        int n = log_store_get_recent(recent, UI_SEED_ROWS);
        for (int i = 0; i < n; i++) source_add(recent[i].src_ip);
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
            case UMSG_EVENT:
                source_add(m.e.src_ip);
                kpi_add(&m.e);
                events = true;
                if (feed_match(&m.e) && !feed_has(&m.e)) feed_add(&m.e);
                break;
            case UMSG_ALARM: apply_alarm(&m.a);              break;
            case UMSG_NET:   lv_label_set_text(s_net, m.net); break;
            }
        }
        if (events) refresh_counts();

        uint32_t ms = (uint32_t)((esp_timer_get_time() - last_us) / 1000);
        lv_tick_inc(ms);
        last_us += (int64_t)ms * 1000;      // carry the sub-ms remainder
        int64_t t = esp_timer_get_time();
        lv_timer_handler();
        loop_measure((uint32_t)(esp_timer_get_time() - t));
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
