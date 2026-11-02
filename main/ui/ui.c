#include "ui.h"
#include "esp_attr.h"
#include "display.h"
#include "alarm.h"
#include "buzzer.h"
#include "log_store.h"
#include "sd_log.h"
#include "cam.h"
#include "wifi_manager.h"
#include "describe.h"
#include "discovery.h"
#include "tripwire.h"           // with http_engine.h and trap_listen.h: the port config
#include "settings.h"
#include "ui_lcars.h"
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
#define UI_SEED_ROWS    200     // the whole flash ring, to count sources at boot
#define HOLD_MS         2000    // ACKNOWLEDGE: a brush must not fire it
#define HOLD_DRAIN_MS   250     // an early release empties a full fill in this time

// Running light under the status bar: driven by an lv_timer on this task, so
// it stops moving if the UI task or the display hangs. Moving means alive.
#define RUNLIGHT_H          3       // px. Rob 2026-10-31: 3 to start
#define RUNLIGHT_Y          28      // just under the status bar
#define RUNLIGHT_HEAD_W     72      // bright head, 15 % of the width
#define RUNLIGHT_TRAIL_W    48      // fading trail behind it
#define RUNLIGHT_STEP_MS    33
#define RUNLIGHT_SWEEP_MS   2000    // green: left to right, repeat
#define UI_MEASURE_MS       10000   // boot: loop cost without, then with the light

// During an incident the running light is hidden and the only thing that
// moves is the alert emblem's stripes, rolling toward the band inside its
// chevrons (build_emblem()): a stripe from the shoulder to the band in
// EMB_ROLL_RED_MS / _YELLOW_MS, stepped every EMB_ROLL_TICK_MS. A step
// invalidates the two stripe areas and nothing else.
#define EMB_ROLL_TICK_MS     50
#define EMB_ROLL_RED_MS      1000
#define EMB_ROLL_YELLOW_MS   2000
#define SWEEP_MEASURE_DELAY_MS 1500 // after a view change: let its full repaint pass
#define SWEEP_MEASURE_MS     2000   // then log the stripes' refresh cost over this

typedef enum { UMSG_EVENT, UMSG_ALARM, UMSG_NET, UMSG_LIT_DONE } umsg_kind_t;

typedef struct {
    umsg_kind_t kind;
    union {
        attack_log_t e;
        alarm_info_t a;
        char         net[48];
    };
} umsg_t;

static QueueHandle_t s_q;
static volatile bool s_debug_paused;   // POST /api/debug/panel: skip lv_timer_handler()

static const char *TYPE_NAME[] = {
    "RTSP", "HTTP", "Telnet", "SSH", "FTP", "ARP spoof", "WiFi deauth", "Shell",
    "Port scan", "Probe", "ARP sweep", "ADB", "Tripwire", "Discovery", "New device", "Router",
};
_Static_assert(sizeof(TYPE_NAME) / sizeof(TYPE_NAME[0]) == ATTACK_TYPE_COUNT, "TYPE_NAME: one per attack_type_t");

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
#define HEX_SUB     "cbd5e1"                 // COL_SUB for label recolor

// Alert emblem: flat solid fills on black, after the Starfleet alert graphic.
#define COL_EMB_BG     lv_color_black()
#define COL_EMB_RED    lv_color_hex(0xe00000)
#define COL_EMB_YELLOW lv_color_hex(0xf0b000)
#define COL_FILL_ACK   lv_color_white()         // hold fill on the red ACKNOWLEDGE

#define TXT_ACK     "ACKNOWLEDGE\n(hold 2 s)"

// Layout
//
// GREEN (no incident):
//   y   0..27   status bar: name, IP : port, clock, condition pill
//   y  28..30   running light (RUNLIGHT_H)
//   y  34..315  the dashboard (build_dash(), see "GREEN dashboard"): tiles,
//               top offenders and LAN talkers, a footer of figures
// RED (unacknowledged), the whole screen, black, no status bar:
//   y   0..159  the alert emblem, "ALERT / CONDITION: RED"
//   y 163..257  the details (DET_*): code and name; source and vendor; the
//               headline's detail, wrapped at words over up to 2 lines;
//               count, first, last, how long open
//   y 260..315  ACKNOWLEDGE (hold), IGNORE ERROR, IGNORE DEVICE
// YELLOW (acknowledged, or a SEV2 incident):
//   y   0..27   status bar
//   y  30..149  the smaller emblem, "ALERT / CONDITION: YELLOW"
//   y 152..246  the details
//   y 250..299  IGNORE ERROR, IGNORE DEVICE
//   y 303..318  "Resolve from the dashboard", with who acknowledged
#define STATUS_H        28

#define RED_EMB_Y       0
#define RED_EMB_H       160
#define RED_DET_Y       163
#define RED_BTN_Y       260
#define RED_BTN_H       56
#define YEL_EMB_Y       30
#define YEL_EMB_H       120
#define YEL_DET_Y       152
#define YEL_BTN_Y       250
#define YEL_BTN_H       50
#define YEL_NOTE_Y      303
#define DET_SRC_DY      22      // 20 px lines
#define DET_DETAIL_DY   45      // 14 px, 2 lines
#define DET_DETAIL_H    32
#define DET_TIMES_DY    79      // 14 px, ends at +95
#define DET_W           468     // x 6..473

// Status bar
static lv_obj_t *s_bar, *s_net, *s_clock, *s_pill, *s_pill_lbl;

// A hold-to-confirm button: a fill grows across it over HOLD_MS while held,
// and done() runs when it reaches the end.
typedef struct {
    lv_obj_t *btn, *fill;
    void    (*done)(void);
    bool      holding;      // from press start until done, release or slide-off
} hold_t;
static hold_t s_h_ack;
EXT_RAM_BSS_ATTR static hold_t s_h_lc_ack;

// The LCARS alert view, in lcars_alert_box() (content coordinates):
//   y   0..111  the emblem
//   y 114       code and name (20 px, c5), y 139 source (14 px, c2), y 158
//               the headline's detail (12 px, c2)
//   y 178..216  three cells: EVENTS, OPEN FOR, ALSO SEEN
//   y 232..279  ACKNOWLEDGE (RED, hold), IGNORE ERROR, IGNORE DEVICE
#define LC_BTN_Y 232
#define LC_BTN_H 48
EXT_RAM_BSS_ATTR static lv_obj_t *s_lc_code, *s_lc_src, *s_lc_head, *s_lc_stat[3];
EXT_RAM_BSS_ATTR static lv_obj_t *s_lc_ack, *s_lc_ack_lbl, *s_lc_ign_err, *s_lc_ign_dev;

// One alert emblem (see build_emblem()): drawn once, static, but for the
// stripes rolling inside its chevrons.
#define EMB_STRIPES_MAX 5
typedef struct {
    lv_obj_t  *root;
    lv_obj_t  *clip[2];                         // upper and lower stripe areas
    lv_obj_t  *st[2][EMB_STRIPES_MAX + 1];      // n + 1 stripes roll through n slots
    lv_color_t col;
    lv_coord_t n, pitch, stripe_h, yt, yb, top, foot;
    lv_coord_t area_y, area_h, hw_max;          // the upper area; the lower mirrors it
    uint32_t   roll_ms;
    int32_t    off;                             // offset last applied, -1 none
} emblem_t;
static emblem_t s_emb_red, s_emb_yel;
EXT_RAM_BSS_ATTR static emblem_t s_emb_lc_red, s_emb_lc_yel;   // LCARS alert view
static emblem_t *s_emb;             // the one shown, NULL when green

// The incident view: black, under the status bar
static lv_obj_t *s_inc;
static lv_obj_t *s_d_code, *s_d_src, *s_d_detail, *s_d_times, *s_note;
static lv_obj_t *s_b_ack, *s_b_ack_lbl, *s_b_ign_err, *s_b_ign_dev;

// Running light
static lv_obj_t   *s_rl_track, *s_rl_seg;
static lv_timer_t *s_rl;
static lv_color_t  s_rl_col;        // the state colour

static alarm_info_t s_alarm;            // last state applied, for the age line

// Backlight: forced full on while RED, and while the face light is up
static bool s_bl_red, s_bl_lit;

// Face light for the panel photo (CAM_FLASH_ENABLE): a white layer over all
static lv_obj_t *s_white;

// Refresh timing: first flush start to last flush done, per refresh
static void (*s_flush_orig)(lv_disp_drv_t *, const lv_area_t *, lv_color_t *);
static int64_t  s_fl_t0, s_fl_t1;
static bool     s_fm_on;                // measuring the stripes, after a view change
static uint32_t s_fm_start, s_fm_n, s_fm_px_max;
static int64_t  s_fm_sum, s_fm_max;
static bool     s_fm_full;              // the next refresh is a view's full repaint
EXT_RAM_BSS_ATTR static const char *s_fm_what;           // what is measured: NULL the emblem's stripes

// Panel style (settings panel_style): true LCARS (ui_lcars.c), false the dashboard
EXT_RAM_BSS_ATTR static bool       s_style_lc;
static lv_coord_t s_btn_y = 320;        // top of the shown button row (the face light stops above it)
EXT_RAM_BSS_ATTR static uint32_t   s_loop_max_us, s_loop_max_prev;   // slowest lv_timer_handler(), this and last second

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

// Every time the panel shows, in the clock setting's format: 24-hour
// "15:39:12", or 12-hour "3:39:12 PM" (no leading zero). secs false drops the
// seconds in 12-hour form only: the status bar clock, where "10:44:44 AM"
// (86 px at 14 px) would run into the network label. 12 bytes hold either.
static void fmt_time(uint32_t ts, bool secs, char *buf, size_t len)
{
    if (ts < 1600000000) { strlcpy(buf, "--:--:--", len); return; }   // pre-SNTP
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    if (settings_get()->clock_24h) { strftime(buf, len, "%H:%M:%S", &tm); return; }
    int h = tm.tm_hour % 12;
    const char *ap = tm.tm_hour < 12 ? "AM" : "PM";
    if (secs) snprintf(buf, len, "%d:%02d:%02d %s", h ? h : 12, tm.tm_min, tm.tm_sec, ap);
    else      snprintf(buf, len, "%d:%02d %s", h ? h : 12, tm.tm_min, ap);
}

// How long the incident has been open, from its first event. Empty before SNTP.
void ui_fmt_time(uint32_t ts, bool secs, char *buf, size_t len) { fmt_time(ts, secs, buf, len); }

uint32_t ui_loop_max_us(void) { return s_loop_max_prev > s_loop_max_us ? s_loop_max_prev : s_loop_max_us; }

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


// ── Condition ─────────────────────────────────────────────────────────────────
//
// What the panel shows is the incident's condition (alarm.h): RED while a
// SEV1 incident is unacknowledged, YELLOW once acknowledged or for a SEV2
// incident, GREEN with none.

static const char *COND_NAME[] = { "GREEN", "YELLOW", "RED" };   // by alarm_cond_t

static alarm_cond_t cond_of(const alarm_info_t *a)
{
    return a->cond <= ALARM_COND_RED ? a->cond : ALARM_COND_RED;
}

static bool mac_zero(const uint8_t m[6])
{
    for (int i = 0; i < 6; i++) if (m[i]) return false;
    return true;
}

// The details' first line, and what IGNORE ERROR names: "Code 17-01 ARP
// sweep", the headline's code and name without its detail.
static void fmt_what(const alarm_info_t *a, char *buf, size_t len)
{
    const char *name = a->code[0] ? describe_code_name(a->code) : NULL;
    if (name)               snprintf(buf, len, "Code %s %s", a->code, name);
    else if (a->headline[0]) {
        strlcpy(buf, a->headline, len);
        char *bar = strstr(buf, " | ");
        if (bar) *bar = '\0';
    } else                  strlcpy(buf, type_name(a->type), len);
}

// Shorten s at word boundaries, with "...", until it fits w pixels in font f.
static void fit_words(char *s, const lv_font_t *f, lv_coord_t w)
{
    size_t n = strlen(s);
    while (lv_txt_get_width(s, (uint32_t)strlen(s), f, 0, LV_TEXT_FLAG_NONE) > w) {
        char *sp = NULL;
        for (char *c = s; c < s + n; c++) if (*c == ' ') sp = c;
        if (!sp || sp == s || strlen(sp) < 4) return;   // one word left: the label clips it
        strcpy(sp, "...");
        n = (size_t)(sp - s);                   // the next cut is before this one
    }
}

// "192.168.0.75 (ASUSTek)", or the MAC when there is no address.
static void fmt_who(const alarm_info_t *a, char *buf, size_t len)
{
    const char *v = wifi_manager_mac_vendor(a->src_mac);
    if (a->src_ip) {
        char ip[16];
        fmt_ip(a->src_ip, ip, sizeof(ip));
        if (v[0]) snprintf(buf, len, "%s (%s)", ip, v);
        else      strlcpy(buf, ip, len);
    } else {
        char mac[WIFI_MAC_STR_LEN];
        wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
        if (v[0]) snprintf(buf, len, "MAC %s (%s)", mac, v);
        else      snprintf(buf, len, "MAC %s", mac);
    }
}

// ── Dashboard timer ───────────────────────────────────────────────────────────

static void set_text(lv_obj_t *l, const char *t);
static void dash_refresh(bool force);
static void kpi_seed_once(void);
static void show(lv_obj_t *o, bool on);

// Every 2 s; dash_refresh() decides what is due.
static void figures_cb(lv_timer_t *t)
{
    (void)t;
    kpi_seed_once();
    dash_refresh(false);
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
    buzzer_chirp(BUZZER_CHIRP_ACK); // queued to the buzzer task, returns at once
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
    lv_label_set_text(s_b_ack_lbl, "Acknowledging...");
    alarm_ack(ALARM_BY_PANEL);
}

static void lc_ack_done(void)
{
    lv_label_set_text(s_lc_ack_lbl, "ACKNOWLEDGING...");
    alarm_ack(ALARM_BY_PANEL);
}

static void lit_snap(const char *action);

// ACKNOWLEDGE press start. The photo is taken here, while the person is
// still at the glass (under the face light if CAM_FLASH_ENABLE); the hold
// decides whether the action fires.
static void ack_press_start_cb(lv_event_t *ev)
{
    hold_begin((hold_t *)lv_event_get_user_data(ev));
    lit_snap("ack");
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

static lv_obj_t *box(lv_obj_t *parent, lv_color_t bg);
static lv_obj_t *label(lv_obj_t *parent, const lv_font_t *font, lv_color_t col);

// ── Running light ─────────────────────────────────────────────────────────────

// A segment is one object: a trail fading in from the track colour, then a
// solid head on the right (it moves left to right), a horizontal gradient.
static void seg_style(lv_obj_t *seg, lv_color_t track, lv_color_t head, int head_w, int w)
{
    lv_obj_set_style_bg_grad_dir(seg, LV_GRAD_DIR_HOR, 0);
    lv_obj_set_style_bg_color(seg, track, 0);
    lv_obj_set_style_bg_grad_color(seg, head, 0);
    lv_obj_set_style_bg_main_stop(seg, 0, 0);
    lv_obj_set_style_bg_grad_stop(seg, (lv_coord_t)(255 * (w - head_w) / w), 0);
}

// Position from the tick, not a step count, so the speed holds if a step is
// late. Green only: during an incident the emblem's stripes move instead.
static void runlight_cb(lv_timer_t *t)
{
    (void)t;
    if (s_emb || lv_obj_has_flag(s_rl_track, LV_OBJ_FLAG_HIDDEN)) return;
    const int32_t w = RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W;
    uint32_t ph = lv_tick_get() % RUNLIGHT_SWEEP_MS;
    lv_obj_set_x(s_rl_seg, (lv_coord_t)(-w + (int32_t)((480 + w) * ph / RUNLIGHT_SWEEP_MS)));
}

static void runlight_set(lv_color_t c)
{
    s_rl_col = c;
    seg_style(s_rl_seg, COL_BG, c, RUNLIGHT_HEAD_W, RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W);
}

// ── Alert emblem ──────────────────────────────────────────────────────────────
//
// After the Starfleet alert graphic, drawn natively: a rounded chevron above
// and one below a central band, stacked stripes inside each, and in the band
// "ALERT" over "CONDITION: <name>". No side bars (Rob, 2026-11-01). Flat fills
// on black: two lv_lines (rounded caps and joins), rounded rectangles and
// labels. For height h (cx 240, cy h / 2):
//   chevrons    feet at (240 -/+ foot, cy - bar_h / 2 - lw / 2), shoulders at
//               (240 -/+ top, lw / 2 + 2), line width lw; mirrored below
//   stripes     in an area from 5 px under the shoulder line, n slots of
//               stripe_h + stripe_gap, each stripe as wide as the chevron
//               allows at its top edge less 12 px (the slanted line is wider
//               than lw)
//   text        "ALERT" centred at cy + title_dy, set twice 1 px apart (the
//               largest font is Montserrat Medium, this makes it bold), the
//               condition at cy + cond_dy
// Everything is static but the stripes: they roll toward the band (the upper
// ones down, the lower ones up) and loop, one stripe from the shoulder to the
// band in roll_ms. n + 1 stripes per chevron sit in a clipping area, so one
// slides in under the shoulder as one slides out at the band, and they fade
// to black over the last slot at either edge. emb_roll() moves them only when
// the offset changes, so a frame invalidates the two stripe areas and
// nothing else.

typedef struct {
    lv_coord_t w;                       // 0: the screen's 480
    lv_coord_t h, bar_h, foot, top, lw, stripe_h, stripe_gap, stripes;
    lv_coord_t title_dy, cond_dy, title_ls;
    const lv_font_t *f_title, *f_cond;
    const char *cond;
    uint32_t col_hex, roll_ms;
} emblem_spec_t;

static const emblem_spec_t EMB_RED = {
    .h = RED_EMB_H, .bar_h = 16, .foot = 150, .top = 70, .lw = 8,
    .stripe_h = 4, .stripe_gap = 4, .stripes = 4,
    .title_dy = -12, .cond_dy = 24, .title_ls = 4,
    .f_title = &lv_font_montserrat_48, .f_cond = &lv_font_montserrat_20,
    .cond = "CONDITION: RED", .col_hex = 0xe00000, .roll_ms = EMB_ROLL_RED_MS,
};
static const emblem_spec_t EMB_YELLOW = {
    .h = YEL_EMB_H, .bar_h = 10, .foot = 112, .top = 52, .lw = 6,
    .stripe_h = 4, .stripe_gap = 3, .stripes = 3,
    .title_dy = -8, .cond_dy = 14, .title_ls = 2,
    .f_title = &lv_font_montserrat_28, .f_cond = &lv_font_montserrat_14,
    .cond = "CONDITION: YELLOW", .col_hex = 0xf0b000, .roll_ms = EMB_ROLL_YELLOW_MS,
};

// The LCARS alert view's emblems: the YELLOW geometry at h 112 in the 400 px
// content box, no side bars; only the stripes move.
#define LC_EMB_H 112
static const emblem_spec_t EMB_LC_RED = {
    .w = LCARS_CONTENT_W, .h = LC_EMB_H, .bar_h = 10, .foot = 112, .top = 52, .lw = 6,
    .stripe_h = 4, .stripe_gap = 3, .stripes = 3,
    .title_dy = -8, .cond_dy = 14, .title_ls = 2,
    .f_title = &lv_font_montserrat_28, .f_cond = &lv_font_montserrat_14,
    .cond = "CONDITION: RED", .col_hex = 0xe00000, .roll_ms = EMB_ROLL_RED_MS,
};
static const emblem_spec_t EMB_LC_YELLOW = {
    .w = LCARS_CONTENT_W, .h = LC_EMB_H, .bar_h = 10, .foot = 112, .top = 52, .lw = 6,
    .stripe_h = 4, .stripe_gap = 3, .stripes = 3,
    .title_dy = -8, .cond_dy = 14, .title_ls = 2,
    .f_title = &lv_font_montserrat_28, .f_cond = &lv_font_montserrat_14,
    .cond = "CONDITION: YELLOW", .col_hex = 0xf0b000, .roll_ms = EMB_ROLL_YELLOW_MS,
};

// lv_line keeps a pointer to its points, so they live here.
static lv_point_t s_emb_pts[4][2][4];   // [emblem][upper, lower][point]

static lv_obj_t *emb_pill(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, lv_color_t c)
{
    lv_obj_t *o = box(p, c);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_set_style_radius(o, h / 2, 0);
    return o;
}

// The upper chevron's usable half-width at emblem y (its mirror below).
static int32_t emb_hw(const emblem_t *e, int32_t y)
{
    return e->top + (int32_t)(e->foot - e->top) * (y - e->yt) / (e->yb - e->yt) - 12;
}

static void emb_roll(emblem_t *e, uint32_t now)
{
    const int32_t travel = e->n * e->pitch;
    int32_t off = (int32_t)((uint64_t)(now % e->roll_ms) * (uint32_t)travel / e->roll_ms) % e->pitch;
    if (off == e->off) return;
    e->off = off;
    for (int i = 0; i <= e->n; i++) {
        int32_t ly = (i - 1) * e->pitch + off;          // top edge in the upper area, moving down
        int32_t hw = emb_hw(e, e->area_y + (ly > 0 ? ly : 0));
        if (hw < 4) hw = 4;
        // Fade over the last slot at either edge: in from the shoulder, out at the band.
        int32_t in = ly + e->stripe_h, out = e->area_h - ly - e->stripe_h, d = in < out ? in : out;
        uint8_t mix = d >= e->pitch ? 255 : d <= 0 ? 0 : (uint8_t)(255 * d / e->pitch);
        lv_color_t c = lv_color_mix(e->col, COL_EMB_BG, mix);
        for (int k = 0; k < 2; k++) {
            lv_obj_t *o = e->st[k][i];
            lv_obj_set_pos(o, (lv_coord_t)(e->hw_max - hw),
                           (lv_coord_t)(k ? e->area_h - ly - e->stripe_h : ly));
            lv_obj_set_width(o, (lv_coord_t)(2 * hw));
            lv_obj_set_style_bg_color(o, c, 0);
        }
    }
}

// The emblem shown, every EMB_ROLL_TICK_MS.
static void roll_cb(lv_timer_t *t)
{
    (void)t;
    if (s_emb) emb_roll(s_emb, lv_tick_get());
}

static void build_emblem(emblem_t *e, lv_point_t pts[2][4], lv_obj_t *parent, lv_coord_t y,
                         const emblem_spec_t *s)
{
    const lv_color_t col = lv_color_hex(s->col_hex);
    const lv_coord_t W = s->w ? s->w : 480, cx = W / 2;
    const lv_coord_t cy = s->h / 2, last = s->h - 1;
    const lv_coord_t yt = s->lw / 2 + 2, yb = cy - s->bar_h / 2 - s->lw / 2;

    e->root = box(parent, COL_EMB_BG);
    lv_obj_set_size(e->root, W, s->h);
    lv_obj_set_pos(e->root, 0, y);
    e->col = col;
    e->roll_ms = s->roll_ms;
    e->n = s->stripes < EMB_STRIPES_MAX ? s->stripes : EMB_STRIPES_MAX;
    e->pitch = s->stripe_h + s->stripe_gap;
    e->stripe_h = s->stripe_h;
    e->yt = yt;
    e->yb = yb;
    e->top = s->top;
    e->foot = s->foot;
    e->area_y = yt + s->lw / 2 + 5;
    e->area_h = e->n * e->pitch - s->stripe_gap;
    e->hw_max = (lv_coord_t)emb_hw(e, e->area_y + e->area_h);
    e->off = -1;

    for (int k = 0; k < 2; k++) {           // 0 upper, 1 lower (mirrored)
        lv_coord_t t = k ? last - yt : yt, b = k ? last - yb : yb;
        lv_point_t *p = pts[k];
        p[0] = (lv_point_t){ cx - s->foot, b };
        p[1] = (lv_point_t){ cx - s->top,  t };
        p[2] = (lv_point_t){ cx + s->top,  t };
        p[3] = (lv_point_t){ cx + s->foot, b };
        lv_obj_t *l = lv_line_create(e->root);
        lv_line_set_points(l, p, 4);
        lv_obj_set_style_line_width(l, s->lw, 0);
        lv_obj_set_style_line_color(l, col, 0);
        lv_obj_set_style_line_rounded(l, true, 0);
        lv_obj_set_pos(l, 0, 0);
        lv_obj_clear_flag(l, LV_OBJ_FLAG_CLICKABLE);

        // The stripe area clips its stripes (children are clipped to their parent).
        lv_obj_t *a = e->clip[k] = lv_obj_create(e->root);
        lv_obj_remove_style_all(a);
        lv_obj_set_pos(a, cx - e->hw_max, k ? s->h - e->area_y - e->area_h : e->area_y);
        lv_obj_set_size(a, 2 * e->hw_max, e->area_h);
        lv_obj_clear_flag(a, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
        for (int i = 0; i <= e->n; i++)
            e->st[k][i] = emb_pill(a, 0, 0, 8, s->stripe_h, col);
    }
    emb_roll(e, 0);

    for (int i = 0; i < 2; i++) {
        lv_obj_t *t = label(e->root, s->f_title, col);
        lv_label_set_text(t, "ALERT");
        lv_obj_set_style_text_letter_space(t, s->title_ls, 0);
        lv_obj_align(t, LV_ALIGN_CENTER, (lv_coord_t)i, s->title_dy);
    }
    lv_obj_t *c = label(e->root, s->f_cond, col);
    lv_label_set_text(c, s->cond);
    lv_obj_align(c, LV_ALIGN_CENTER, 0, s->cond_dy);
    lv_obj_add_flag(e->root, LV_OBJ_FLAG_HIDDEN);
}

// ── Backlight and the face light ──────────────────────────────────────────────
//
// The backlight is forced full on while RED and while the face light is up,
// else it follows the brightness setting.
//
// Face light (CAM_FLASH_ENABLE): a press that takes a photo (ACKNOWLEDGE's
// start, an IGNORE confirm) first turns the screen white above the button
// row (y 0 to just over the buttons: the emblem and the details) and the
// backlight full on, so the screen lights the face. The buttons stay visible
// and live under no cover, so the ACKNOWLEDGE fill keeps running in sight.
// The white is drawn at
// once (lv_refr_now, timed and logged), then the camera drops frames for
// CAM_FLASH_SETTLE_MS while its exposure settles on the light, captures, and
// its callback (camera task) queues UMSG_LIT_DONE to take the white down. The
// white layer is not clickable either. If the callback never arrives, LIT_TIMEOUT_MS takes the white down anyway.
#define LIT_TIMEOUT_MS  (CAM_FLASH_SETTLE_MS + 1500)
#define LIT_BTN_CLEAR   3       // px of black kept above the button row

static bool     s_lit;
static uint32_t s_lit_at;

static void backlight_update(void)
{
    display_set_backlight_override(s_bl_red || s_bl_lit);
}

#if CAM_FLASH_ENABLE
static void lit_done_cb(bool ok)            // camera task: queue only
{
    (void)ok;
    umsg_t m = { .kind = UMSG_LIT_DONE };
    xQueueSend(s_q, &m, 0);                 // dropped: the timeout takes the white down
}
#endif

static void lit_off(void)
{
    if (!s_lit) return;
    s_lit = false;
    lv_obj_add_flag(s_white, LV_OBJ_FLAG_HIDDEN);
    s_bl_lit = false;
    backlight_update();
}

static void lit_snap(const char *action)
{
#if CAM_FLASH_ENABLE
    if (cam_ready() && !s_lit) {
        lv_coord_t h = s_btn_y < 320 ? s_btn_y - LIT_BTN_CLEAR : 320;
        lv_obj_set_height(s_white, h);
        lv_obj_clear_flag(s_white, LV_OBJ_FLAG_HIDDEN);
        lv_obj_move_foreground(s_white);    // over a dialog too
        s_lit = true;
        s_lit_at = lv_tick_get();
        s_bl_lit = true;
        backlight_update();
        int64_t t0 = esp_timer_get_time();
        lv_refr_now(NULL);                  // the white is on the glass when this returns
        int ms = (int)((esp_timer_get_time() - t0) / 1000);
        if (cam_snap_lit(action, CAM_FLASH_SETTLE_MS, lit_done_cb)) {
            ESP_LOGI(TAG, "Face light for \"%s\": white drawn in %d ms, the camera settles %d ms",
                     action, ms, CAM_FLASH_SETTLE_MS);
        } else {
            lit_off();                      // not taken: a photo under a second ago
        }
        return;
    }
#endif
    cam_snap(action);
}

// ── Ignore error / ignore device ──────────────────────────────────────────────
//
// IGNORE ERROR stops this kind of incident from this source alerting; IGNORE
// DEVICE stops every alert from the source. Each asks first, naming exactly
// what will be ignored; the dashboard can undo either. Confirming takes the
// photo and then acts.

typedef enum { IGN_ERROR, IGN_DEVICE } ign_kind_t;
static struct { ign_kind_t kind; uint32_t id; } s_ign;     // what the open dialog is about
static const char *IGN_BTNS[] = { "Ignore", "Cancel", "" };
static const char *IGN_BTNS_LC[] = { "CANCEL", "CONFIRM", "" };

static void ignore_mb_cb(lv_event_t *ev)
{
    lv_obj_t *mb = lv_event_get_current_target(ev);
    const char *b = lv_msgbox_get_active_btn_text(mb);
    bool yes = b && (!strcmp(b, "Ignore") || !strcmp(b, "CONFIRM"));
    lv_msgbox_close_async(mb);
    alarm_info_t a;
    alarm_get(&a);
    if (yes && (a.state == ALARM_IDLE || a.id != s_ign.id)) {
        ESP_LOGW(TAG, "Ignore dropped: incident #%lu is no longer shown", (unsigned long)s_ign.id);
        yes = false;
    }
    if (!yes) {
        buzzer_chirp(BUZZER_CHIRP_CANCEL);
        return;
    }
    buzzer_chirp(BUZZER_CHIRP_CONFIRM);
    lit_snap("ignore");
    ESP_LOGW(TAG, "IGNORE %s on incident #%lu from the panel",
             s_ign.kind == IGN_ERROR ? "ERROR" : "DEVICE", (unsigned long)s_ign.id);
    esp_err_t r = s_ign.kind == IGN_ERROR ? alarm_ignore_error(ALARM_BY_PANEL)
                                          : alarm_ignore_device(ALARM_BY_PANEL);
    if (r == ESP_OK) return;
    ESP_LOGW(TAG, "Ignore failed: %s", esp_err_to_name(r));
    lv_obj_t *e = lv_msgbox_create(NULL, "Not ignored",
        r == ESP_ERR_NO_MEM ? "The ignore list is full (32). Remove entries on the dashboard."
      : r == ESP_ERR_INVALID_STATE ? "The incident has closed."
                                   : "Could not save the ignore list.", NULL, true);
    lv_obj_set_width(e, 400);
    if (s_style_lc) lcars_style_msgbox(e);
    lv_obj_center(e);
}

static void ignore_ask_cb(lv_event_t *ev)
{
    ign_kind_t kind = (ign_kind_t)(uintptr_t)lv_event_get_user_data(ev);
    if (s_alarm.state == ALARM_IDLE) return;
    s_ign.kind = kind;
    s_ign.id = s_alarm.id;

    char who[96], what[DESCRIBE_MAX];
    EXT_RAM_BSS_ATTR static char body[DESCRIBE_MAX + 192];
    fmt_who(&s_alarm, who, sizeof(who));
    if (kind == IGN_ERROR) {
        fmt_what(&s_alarm, what, sizeof(what));
        snprintf(body, sizeof(body), "Ignore %s from %s?\n\nThe dashboard can undo it.", what, who);
    } else {
        snprintf(body, sizeof(body), "Ignore all alerts from %s?\n\n"
                 "Its events are still logged. The dashboard can undo it.", who);
    }
    lv_obj_t *mb;
    if (s_style_lc) {
        mb = lv_msgbox_create(NULL, kind == IGN_ERROR ? "IGNORE ERROR" : "IGNORE DEVICE", body, IGN_BTNS_LC, false);
        lv_obj_set_width(mb, 360);
        lcars_style_msgbox(mb);
        lv_obj_set_size(lv_msgbox_get_btns(mb), 320, 40);
    } else {
        mb = lv_msgbox_create(NULL, kind == IGN_ERROR ? "Ignore error" : "Ignore device", body, IGN_BTNS, false);
        lv_obj_set_width(mb, 440);
        lv_obj_set_style_text_font(mb, &lv_font_montserrat_20, 0);
        lv_obj_t *btns = lv_msgbox_get_btns(mb);
        lv_obj_set_size(btns, 400, 56);
    }
    lv_obj_center(mb);
    lv_obj_add_event_cb(mb, ignore_mb_cb, LV_EVENT_VALUE_CHANGED, NULL);
}

// ── Refresh timing ────────────────────────────────────────────────────────────
//
// Wraps the display driver's flush (synchronous: it returns once the pixels
// are on the wire). A refresh runs from its first flush's start to its last
// flush's end, which the monitor callback closes. Logged: a view's full
// repaint, and SWEEP_MEASURE_MS of the emblem's rolling stripes once that
// has passed.

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
    if (px == 0) return;
    if (s_fm_full && px >= 400 * 160) {
        s_fm_full = false;
        ESP_LOGI(TAG, "%s repaint: %lu px, flush start to done %lld us", s_fm_what ? s_fm_what : "View",
                 (unsigned long)px, us);
        return;
    }
    if (!s_fm_on || lv_tick_elaps(s_fm_start) < SWEEP_MEASURE_DELAY_MS) return;
    s_fm_n++;
    s_fm_sum += us;
    if (us > s_fm_max) s_fm_max = us;
    if (px > s_fm_px_max) s_fm_px_max = px;
    if (lv_tick_elaps(s_fm_start) >= SWEEP_MEASURE_DELAY_MS + SWEEP_MEASURE_MS) {
        s_fm_on = false;
        if (s_fm_what)
            ESP_LOGI(TAG, "%s: %lu refreshes in %d ms, flush start to done avg %lld us, max %lld us, up to %lu px",
                     s_fm_what, (unsigned long)s_fm_n, SWEEP_MEASURE_MS, s_fm_sum / s_fm_n, s_fm_max,
                     (unsigned long)s_fm_px_max);
        else
            ESP_LOGI(TAG, "Stripes: %lu refreshes in %d ms, flush start to done avg %lld us, max %lld us, "
                     "up to %lu px (the two stripe areas are %d px)",
                     (unsigned long)s_fm_n, SWEEP_MEASURE_MS, s_fm_sum / s_fm_n, s_fm_max,
                     (unsigned long)s_fm_px_max, s_emb ? 2 * 2 * s_emb->hw_max * s_emb->area_h : 0);
    }
}

static void measure_start(const char *what)
{
    s_fm_what = what;
    s_fm_full = true;
    s_fm_on = true;
    s_fm_start = lv_tick_get();
    s_fm_n = s_fm_px_max = 0;
    s_fm_sum = s_fm_max = 0;
}

// A page change on the LCARS panel: log its repaint, then SWEEP_MEASURE_MS of
// what moves on it.
void ui_refr_measure(const char *what) { measure_start(what); }

static void refr_timing_init(void)
{
    lv_disp_t *disp = lv_disp_get_default();
    if (!disp || !disp->driver || !disp->driver->flush_cb) return;
    s_flush_orig = disp->driver->flush_cb;
    disp->driver->flush_cb = flush_timed;
    disp->driver->monitor_cb = refr_monitor_cb;
}

// ── GREEN dashboard ───────────────────────────────────────────────────────────
//
// Summary metrics only, no log, after the Pi-hole dashboard: dark rounded
// cards, big numbers, thin frequency bars.
//   y  34..81   four tiles: alerts, probes and port scans today, LAN devices
//   y  88..293  two cards, 5 rows each:
//               x   4..237  top offenders today (SEV1 and SEV2 sources):
//                           label or vendor, IP, alerts, a bar against the top
//               x 242..475  LAN talkers (discovery_top_talkers()): label or
//                           vendor, IP and packets an hour, 1 to 5 activity
//                           lights (under 30, 100, 300, 600 an hour, then 5),
//                           a bar against the busiest
//   y 300..315  ports listening, uptime, microSD free, Wi-Fi RSSI
// All on this task, from the 2 s figures timer: the tiles and offenders when
// they changed, the talkers and the footer once a minute (or on entering the
// view). Text is set only when it differs, a bar or a light only when it
// moves, so the SPI panel repaints little.

#define DASH_TILE_Y     34
#define DASH_TILE_H     48
#define DASH_TILE_W     115
#define DASH_TILE_PITCH 119
#define DASH_CARD_Y     88
#define DASH_CARD_H     206
#define DASH_CARD_W     234
#define DASH_CARD_X0    4
#define DASH_CARD_X1    242
#define DASH_ROWS       5
#define DASH_ROW_Y0     24      // in the card, under its header
#define DASH_ROW_H      36
#define DASH_NAME_W     156
#define DASH_BAR_W      218     // x 8..225 in the card
#define DASH_DOTS       5
#define DASH_DOT        8
#define DASH_DOT_GAP    4
#define DASH_FOOT_Y     300
#define DASH_SLOW_MS    60000   // talkers and footer
#define KPI_SRC_MAX     32      // sources counted today; more are not ranked
#define COL_SKY         lv_color_hex(0x38bdf8)
#define COL_TRACK       lv_color_hex(0x334155)

typedef struct {
    lv_obj_t *root, *name, *val, *sub, *fill;
    lv_obj_t *dot[DASH_DOTS];               // talkers only
    uint8_t   lit;                          // lights shown, 0 = not yet set
} dash_row_t;

static lv_obj_t  *s_idle;                   // the green view: everything below the light
static lv_obj_t  *s_tile_val[4];
EXT_RAM_BSS_ATTR static dash_row_t s_off[DASH_ROWS], s_talk[DASH_ROWS];    // PSRAM, as LVGL's heap
static lv_obj_t  *s_off_empty, *s_talk_empty, *s_foot;
static bool       s_off_dirty = true;
static uint32_t   s_slow_at;
static bool       s_slow_done;

typedef struct { uint32_t ip; uint8_t mac[6]; uint32_t n; } kpi_src_t;

// Today's counts, in RAM: seeded from the flash ring at boot, then one per
// event; reset at local midnight. PSRAM.
EXT_RAM_BSS_ATTR static struct {
    uint32_t day;                           // local YYYY*1000+yday, 0 = clock not set
    uint32_t tier[3];                       // alerts, probes, discovery
    uint32_t scans;
    kpi_src_t src[KPI_SRC_MAX];
    int      src_n;
} s_kpi;

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
        s_off_dirty = true;
    }
}

static void kpi_add(const attack_log_t *e)
{
    describe_tier_t t = describe_tier(e);
    kpi_roll();
    if (!s_kpi.day || local_day(e->timestamp) != s_kpi.day) return;   // not today
    if (t >= TIER_SEV1 && t <= TIER_SEV3) s_kpi.tier[t - 1]++;
    if (e->type == ATTACK_SCAN && !strncmp(e->payload, "Port scan:", 10)) s_kpi.scans++;
    if (t == TIER_SEV3 || !e->src_ip) return;
    s_off_dirty = true;
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
    lcars_reset();
    for (int i = n - 1; i >= 0; i--) { kpi_add(&r[i]); lcars_event(&r[i]); }
    heap_caps_free(r);
    s_off_dirty = true;
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

// A row's name and line under it, the bar at v of max.
static void row_set(dash_row_t *r, const char *name, const char *sub, uint32_t v, uint32_t max)
{
    char b[64];
    strlcpy(b, name, sizeof(b));
    for (char *c = b; *c; c++) if (*c == '#') *c = ' ';     // label recolor marker
    fit_words(b, &lv_font_montserrat_14, DASH_NAME_W);
    set_text(r->name, b);
    set_text(r->sub, sub);
    lv_coord_t w = max ? (lv_coord_t)((uint64_t)DASH_BAR_W * v / max) : 0;
    lv_obj_set_width(r->fill, w < 2 ? 2 : w);               // unchanged: no repaint
    show(r->root, true);
}

// Activity lights: 1 under 30 an hour, then 100, 300, 600; 5 above that.
// Lit in green, amber from 3, red from 4.
static void row_lights(dash_row_t *r, uint32_t per_hour)
{
    uint8_t n = per_hour < 30 ? 1 : per_hour < 100 ? 2 : per_hour < 300 ? 3 : per_hour < 600 ? 4 : 5;
    if (n == r->lit) return;
    r->lit = n;
    lv_color_t on = n >= 4 ? COL_RED : n == 3 ? COL_AMBER : COL_GREEN;
    for (int i = 0; i < DASH_DOTS; i++)
        lv_obj_set_style_bg_color(r->dot[i], i < n ? on : COL_TRACK, 0);
}

static void offenders_update(void)
{
    int idx[DASH_ROWS], n = 0;
    for (int i = 0; i < s_kpi.src_n; i++) {          // top DASH_ROWS by count, insertion
        int at = n < DASH_ROWS ? n : DASH_ROWS;
        while (at > 0 && s_kpi.src[idx[at - 1]].n < s_kpi.src[i].n) at--;
        if (at >= DASH_ROWS) continue;
        int last = n < DASH_ROWS ? n : DASH_ROWS - 1;
        memmove(&idx[at + 1], &idx[at], sizeof(idx[0]) * (size_t)(last - at));
        idx[at] = i;
        if (n < DASH_ROWS) n++;
    }
    for (int k = 0; k < DASH_ROWS; k++) {
        if (k >= n) { show(s_off[k].root, false); continue; }
        const kpi_src_t *s = &s_kpi.src[idx[k]];
        char name[48], ip[16], cnt[12];
        if (!discovery_label_for(s->ip, mac_zero(s->mac) ? NULL : s->mac, name, sizeof(name))) {
            const char *v = wifi_manager_mac_vendor(s->mac);
            strlcpy(name, v[0] ? v : "unknown device", sizeof(name));
        }
        fmt_ip(s->ip, ip, sizeof(ip));
        snprintf(cnt, sizeof(cnt), "%lu", (unsigned long)s->n);
        set_text(s_off[k].val, cnt);
        row_set(&s_off[k], name, ip, s->n, s_kpi.src[idx[0]].n);
    }
    show(s_off_empty, n == 0);
}

static void talkers_update(void)
{
    static discovery_talker_t *t;           // about 0.5 KB, PSRAM, kept
    if (!t && !(t = heap_caps_malloc(sizeof(*t) * DASH_ROWS, MALLOC_CAP_SPIRAM))) return;
    int n = discovery_top_talkers(t, DASH_ROWS);
    for (int k = 0; k < DASH_ROWS; k++) {
        if (k >= n) { show(s_talk[k].root, false); continue; }
        char name[64], sub[40], ip[16];
        if (t[k].label[0])       strlcpy(name, t[k].label, sizeof(name));
        else if (t[k].vendor[0]) snprintf(name, sizeof(name), "%s device", t[k].vendor);
        else                     strlcpy(name, "unknown device", sizeof(name));
        if (t[k].ip) fmt_ip(t[k].ip, ip, sizeof(ip));
        else         strlcpy(ip, "no IP", sizeof(ip));
        snprintf(sub, sizeof(sub), "%s   %lu/h", ip, (unsigned long)t[k].per_hour);
        row_set(&s_talk[k], name, sub, t[k].per_hour, t[0].per_hour);
        row_lights(&s_talk[k], t[k].per_hour);
    }
    show(s_talk_empty, n == 0);
}

static void footer_update(void)
{
    char up[24], sd[24], wifi[16], b[160];
    fmt_span((uint32_t)(esp_timer_get_time() / 1000000LL), up, sizeof(up));
    sd_status_t st;
    sd_log_status(&st);
    if (st.mounted) {
        unsigned long tenths = (unsigned long)(st.free_bytes / 100000000ULL);   // 0.1 GB
        snprintf(sd, sizeof(sd), "%lu.%lu GB free", tenths / 10, tenths % 10);
    } else {
        strlcpy(sd, "no card", sizeof(sd));
    }
    wifi_ap_record_t ap;
    if (wifi_manager_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        snprintf(wifi, sizeof(wifi), "%d dBm", (int)ap.rssi);
    else
        strlcpy(wifi, "--", sizeof(wifi));
    snprintf(b, sizeof(b), "#" HEX_SUB " Listening# %d ports   #" HEX_SUB " Up# %s   #" HEX_SUB " SD# %s   "
             "#" HEX_SUB " Wi-Fi# %s", listening_ports(), up, sd, wifi);
    set_text(s_foot, b);
}

static void dash_refresh(bool force)
{
    if (lv_obj_has_flag(s_idle, LV_OBJ_FLAG_HIDDEN)) return;
    char buf[16];
    kpi_roll();
    uint32_t v[4] = { s_kpi.tier[0], s_kpi.tier[1], s_kpi.scans,
                      (uint32_t)discovery_summary(NULL, 0, NULL) };
    for (int i = 0; i < 4; i++) {
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)v[i]);
        set_text(s_tile_val[i], buf);
    }
    if (force || s_off_dirty) {
        s_off_dirty = false;
        offenders_update();
    }
    if (force || !s_slow_done || lv_tick_elaps(s_slow_at) >= DASH_SLOW_MS) {
        s_slow_done = true;
        s_slow_at = lv_tick_get();
        talkers_update();
        footer_update();
    }
}

// ── Alarm ─────────────────────────────────────────────────────────────────────

// Every second: during an incident, the details' last line (count, first and
// last seen, how long it has been open). Nothing when green.
static void refresh_age(void)
{
    char age[24] = "";
    if (s_alarm.state != ALARM_IDLE) {
        char t0[12], t1[12], buf[96];
        fmt_time(s_alarm.first_ts, true, t0, sizeof(t0));
        fmt_time(s_alarm.last_ts, true, t1, sizeof(t1));
        fmt_age(s_alarm.first_ts, age, sizeof(age));
        snprintf(buf, sizeof(buf), "%lu event%s,  first %s,  last %s%s%s",
                 (unsigned long)s_alarm.count, s_alarm.count == 1 ? "" : "s", t0, t1,
                 age[0] ? ",  " : "", age);
        set_text(s_d_times, buf);
        time_t now = time(NULL);
        if (s_alarm.first_ts >= 1600000000 && now >= (time_t)s_alarm.first_ts) {
            unsigned long d = (unsigned long)(now - (time_t)s_alarm.first_ts);
            if (d < 3600) snprintf(buf, sizeof(buf), "%lu:%02lu", d / 60, d % 60);
            else          snprintf(buf, sizeof(buf), "%lu:%02lu:%02lu", d / 3600, d % 3600 / 60, d % 60);
        } else strlcpy(buf, "-", sizeof(buf));
        set_text(s_lc_stat[1], buf);
        return;
    }
}

static void show(lv_obj_t *o, bool on)
{
    if (on) lv_obj_clear_flag(o, LV_OBJ_FLAG_HIDDEN);
    else    lv_obj_add_flag(o, LV_OBJ_FLAG_HIDDEN);
}

static void place(lv_obj_t *o, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h)
{
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    show(o, true);
}

// The views. Each sets every widget's visibility and position itself, so no
// path into a condition relies on what an earlier one toggled.
static void view_incident(alarm_cond_t c)
{
    bool red = c == ALARM_COND_RED;
    lcars_view(c, false);
    s_btn_y = red ? RED_BTN_Y : YEL_BTN_Y;
    show(s_idle, false);
    show(s_rl_track, false);                // the emblem's stripes are the only motion
    show(s_bar, !red);                      // RED has the whole screen
    show(s_inc, true);
    s_emb = red ? &s_emb_red : &s_emb_yel;
    show(s_emb_red.root, red);
    show(s_emb_yel.root, !red);

    lv_coord_t y = red ? RED_DET_Y : YEL_DET_Y;
    lv_obj_set_pos(s_d_code, 6, y);
    lv_obj_set_pos(s_d_src, 6, y + DET_SRC_DY);
    lv_obj_set_pos(s_d_detail, 6, y + DET_DETAIL_DY);
    lv_obj_set_pos(s_d_times, 6, y + DET_TIMES_DY);
    // Nothing to ignore a device by without its address or MAC.
    bool dev = s_alarm.src_ip || !mac_zero(s_alarm.src_mac);
    if (red) {
        place(s_b_ack, 4, RED_BTN_Y, 184, RED_BTN_H);
        place(s_b_ign_err, 194, RED_BTN_Y, 138, RED_BTN_H);
        place(s_b_ign_dev, 338, RED_BTN_Y, 138, RED_BTN_H);
    } else {
        show(s_b_ack, false);
        place(s_b_ign_err, 4, YEL_BTN_Y, 232, YEL_BTN_H);
        place(s_b_ign_dev, 244, YEL_BTN_Y, 232, YEL_BTN_H);
    }
    show(s_b_ign_dev, dev);
    show(s_note, !red);
}

static void view_armed(void)
{
    lcars_view(ALARM_COND_GREEN, false);
    s_btn_y = 320;
    s_emb = NULL;
    show(s_inc, false);
    show(s_bar, true);
    show(s_rl_track, true);
    show(s_idle, true);
    dash_refresh(true);                     // not kept up while hidden
}

// The LCARS alert view: the frame without its rail, the alert box.
static void view_lcars_alert(alarm_cond_t c)
{
    bool red = c == ALARM_COND_RED;
    show(s_inc, false);
    show(s_bar, false);
    show(s_rl_track, false);
    show(s_idle, false);
    lcars_view(c, true);
    s_emb = red ? &s_emb_lc_red : &s_emb_lc_yel;
    show(s_emb_lc_red.root, red);
    show(s_emb_lc_yel.root, !red);
    bool dev = s_alarm.src_ip || !mac_zero(s_alarm.src_mac);
    if (red) {
        place(s_lc_ack, 0, LC_BTN_Y, 132, LC_BTN_H);
        place(s_lc_ign_err, 138, LC_BTN_Y, 126, LC_BTN_H);
        place(s_lc_ign_dev, 270, LC_BTN_Y, 130, LC_BTN_H);
    } else {
        show(s_lc_ack, false);
        place(s_lc_ign_err, 0, LC_BTN_Y, 126, LC_BTN_H);
        place(s_lc_ign_dev, 132, LC_BTN_Y, 130, LC_BTN_H);
    }
    show(s_lc_ign_dev, dev);
    s_btn_y = LCARS_CONTENT_Y + LC_BTN_Y;
}

// The LCARS alert's texts, upper case and fitted to the 400 px box.
static void lcars_alert_text(const alarm_info_t *a)
{
    char buf[DESCRIBE_MAX + 48], ip[WIFI_MAC_STR_LEN > 16 ? WIFI_MAC_STR_LEN : 16], lbl[48];   // an IP, or the MAC
    fmt_what(a, buf, sizeof(buf));
    lcars_upper(buf);
    fit_words(buf, &lv_font_montserrat_20, LCARS_CONTENT_W);
    set_text(s_lc_code, buf);
    const char *v = wifi_manager_mac_vendor(a->src_mac);
    if (a->src_ip) fmt_ip(a->src_ip, ip, sizeof(ip));
    else           wifi_manager_format_mac(a->src_mac, ip, sizeof(ip));
    if (!discovery_label_for(a->src_ip, mac_zero(a->src_mac) ? NULL : a->src_mac, lbl, sizeof(lbl))) lbl[0] = '\0';
    snprintf(buf, sizeof(buf), "%s%s%s%s%s", ip, v[0] ? " | " : "", v, lbl[0] ? " | " : "", lbl);
    lcars_upper(buf);
    fit_words(buf, &lv_font_montserrat_14, LCARS_CONTENT_W);
    set_text(s_lc_src, buf);
    const char *bar = strstr(a->headline, " | ");
    strlcpy(buf, bar ? bar + 3 : a->headline, sizeof(buf));
    fit_words(buf, &lv_font_montserrat_12, LCARS_CONTENT_W);
    set_text(s_lc_head, buf);
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)a->count);
    set_text(s_lc_stat[0], buf);
    strlcpy(buf, "-", sizeof(buf));
    for (int i = 0; i < describe_code_count() && i < 64; i++) {
        const char *nm;
        int tier;
        const char *code = describe_code_at(i, &nm, &tier);
        if (!code || !(a->codes & (1ULL << i)) || !strcmp(code, a->code)) continue;
        snprintf(buf, sizeof(buf), "%s %s", code, nm);
        lcars_upper(buf);
        fit_words(buf, &lv_font_montserrat_14, 129);
        break;
    }
    set_text(s_lc_stat[2], buf);
}

// The LCARS panel, GREEN: its frame, rail and pages over everything.
static void view_lcars_green(void)
{
    s_emb = NULL;
    s_btn_y = 320;
    show(s_inc, false);
    show(s_bar, false);
    show(s_rl_track, false);
    show(s_idle, false);
    lcars_view(ALARM_COND_GREEN, true);
}

// Once per change of condition or incident: what the panel now renders, so
// a console capture shows it.
static void log_view(alarm_cond_t c)
{
    lv_obj_update_layout(lv_scr_act());
    if (c != ALARM_COND_GREEN && s_style_lc) {
        lv_area_t e;
        lv_obj_get_coords(s_emb->root, &e);
        ESP_LOGI(TAG, "UI state: %s #%lu, LCARS, emblem y %d..%d, buttons %s%s, rail hidden",
                 COND_NAME[c], (unsigned long)s_alarm.id, e.y1, e.y2,
                 c == ALARM_COND_RED ? "ACKNOWLEDGE, IGNORE ERROR" : "IGNORE ERROR",
                 lv_obj_has_flag(s_lc_ign_dev, LV_OBJ_FLAG_HIDDEN) ? "" : ", IGNORE DEVICE");
        return;
    }
    if (c == ALARM_COND_GREEN && s_style_lc) {
        ESP_LOGI(TAG, "UI state: GREEN, last incident #%lu, LCARS panel", (unsigned long)s_alarm.id);
        return;
    }
    if (c == ALARM_COND_GREEN) {
        int off = 0, talk = 0;
        for (int i = 0; i < DASH_ROWS; i++) {
            off  += !lv_obj_has_flag(s_off[i].root, LV_OBJ_FLAG_HIDDEN);
            talk += !lv_obj_has_flag(s_talk[i].root, LV_OBJ_FLAG_HIDDEN);
        }
        ESP_LOGI(TAG, "UI state: GREEN, last incident #%lu, dashboard: tiles y %d, %d offenders, %d talkers, footer y %d",
                 (unsigned long)s_alarm.id, DASH_TILE_Y, off, talk, DASH_FOOT_Y);
        return;
    }
    lv_area_t e;
    lv_obj_get_coords(s_emb->root, &e);
    ESP_LOGI(TAG, "UI state: %s #%lu, emblem y %d..%d, details y %d, buttons %s%s, status bar %s",
             COND_NAME[c], (unsigned long)s_alarm.id, e.y1, e.y2, (int)lv_obj_get_y(s_d_code),
             c == ALARM_COND_RED ? "ACKNOWLEDGE, IGNORE ERROR" : "IGNORE ERROR",
             lv_obj_has_flag(s_b_ign_dev, LV_OBJ_FLAG_HIDDEN) ? "" : ", IGNORE DEVICE",
             c == ALARM_COND_RED ? "hidden" : "shown");
}

static void apply_alarm(const alarm_info_t *a)
{
    alarm_cond_t was = cond_of(&s_alarm), c = cond_of(a);
    // Count updates (up to 1/s during a scan) must not reset the button label
    // or the fill mid-press: those go back to their start only on a change.
    bool lc = settings_get()->panel_style == 1;
    bool changed = c != was || a->id != s_alarm.id || lc != s_style_lc;
    s_style_lc = lc;
    s_alarm = *a;
    if (changed) { hold_reset(&s_h_ack); hold_reset(&s_h_lc_ack); }

    if (c != ALARM_COND_GREEN) {
        bool red = c == ALARM_COND_RED;
        lv_obj_set_style_bg_color(s_pill, red ? COL_RED : COL_AMBER, 0);
        set_text(s_pill_lbl, COND_NAME[c]);
        char buf[DESCRIBE_MAX + 16];
        fmt_what(a, buf, sizeof(buf));
        fit_words(buf, &lv_font_montserrat_20, DET_W);
        set_text(s_d_code, buf);
        fmt_who(a, buf, sizeof(buf));
        fit_words(buf, &lv_font_montserrat_20, DET_W);
        set_text(s_d_src, buf);
        const char *bar = strstr(a->headline, " | ");
        set_text(s_d_detail, bar ? bar + 3 : a->headline);
        set_text(s_note, a->acked_by == ALARM_BY_PANEL     ? "Acknowledged on the panel. Resolve from the dashboard"
                       : a->acked_by == ALARM_BY_DASHBOARD ? "Acknowledged on the dashboard. Resolve from the dashboard"
                                                           : "Resolve from the dashboard");
        lcars_alert_text(a);
        if (lc) view_lcars_alert(c);
        else    view_incident(c);
        if (changed && red) { lv_label_set_text(s_b_ack_lbl, TXT_ACK); lv_label_set_text(s_lc_ack_lbl, "ACKNOWLEDGE"); }
    } else {
        lv_obj_set_style_bg_color(s_pill, COL_GREEN, 0);
        set_text(s_pill_lbl, COND_NAME[c]);
        runlight_set(COL_GREEN);
        if (lc) view_lcars_green();
        else    view_armed();
    }
    refresh_age();
    s_bl_red = c == ALARM_COND_RED;
    backlight_update();                     // full on while RED, else the setting
    // A new view repaints the whole screen once (a few hundred ms over SPI,
    // only on a change), so no area keeps pixels from the old one.
    static bool logged;
    if (changed || !logged) {
        logged = true;
        lv_obj_invalidate(lv_scr_act());
        if (c != ALARM_COND_GREEN) measure_start(NULL);   // then time the stripes
        else if (!lc) s_fm_full = true;     // LCARS: its page change measures
        log_view(c);
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

// A panel button: base colour and a dark 20 px label, centred. With fill, a
// hold fill (width 0) drawn under the label. Placed and shown by the views.
static lv_obj_t *panel_button(lv_obj_t *parent, lv_color_t base, const char *text,
                              lv_color_t fill_col, lv_obj_t **fill, lv_obj_t **lbl)
{
    lv_obj_t *b = lv_btn_create(parent);
    lv_obj_set_style_bg_color(b, base, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_pad_all(b, 0, 0);
    if (fill) {
        *fill = box(b, fill_col);
        lv_obj_set_style_radius(*fill, 8, 0);
        lv_obj_set_size(*fill, 0, LV_PCT(100));
        lv_obj_align(*fill, LV_ALIGN_LEFT_MID, 0, 0);
    }
    lv_obj_t *l = label(b, &lv_font_montserrat_20, COL_DARK);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(l, text);
    lv_obj_center(l);
    if (lbl) *lbl = l;
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
    fmt_time((uint32_t)time(NULL), false, buf, sizeof(buf));
    set_text(s_clock, buf);
    alarm_info_t a;
    alarm_get(&a);
    if (a.state != s_alarm.state || a.id != s_alarm.id) {
        ESP_LOGW(TAG, "Alarm state ahead of the UI queue (message dropped or late), applying it now");
        apply_alarm(&a);
    } else if ((settings_get()->panel_style == 1) != s_style_lc) {
        ESP_LOGI(TAG, "Panel style now %s", s_style_lc ? "dashboard" : "LCARS");
        apply_alarm(&a);                    // live: both panels are built
    }
    s_loop_max_prev = s_loop_max_us;
    s_loop_max_us = 0;
    refresh_age();
}

// A dark rounded card with a 14 px title, and a caption on the right.
static lv_obj_t *dash_card(lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h,
                           const char *title, const char *caption)
{
    lv_obj_t *c = box(s_idle, COL_CARD);
    lv_obj_set_pos(c, x, y);
    lv_obj_set_size(c, w, h);
    lv_obj_set_style_radius(c, 8, 0);
    lv_obj_t *t = label(c, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(t, title);
    lv_obj_set_pos(t, 8, 4);
    if (caption) {
        lv_obj_t *k = label(c, &lv_font_montserrat_12, COL_SUB);
        lv_label_set_text(k, caption);
        lv_obj_align(k, LV_ALIGN_TOP_RIGHT, -8, 6);
    }
    return c;
}

// One row of a card, y 24 + i * 36: name (14 px, x 8..163), the line under
// it (12 px, y +17), the value (20 px, right, x 166..225) or 5 lights (8 px,
// x 170..225), and a 3 px bar on a track (x 8..225, y +32). Hidden
// until it has something to show.
static void dash_row(dash_row_t *r, lv_obj_t *card, int i, bool lights)
{
    r->root = lv_obj_create(card);
    lv_obj_remove_style_all(r->root);
    lv_obj_set_pos(r->root, 0, DASH_ROW_Y0 + i * DASH_ROW_H);
    lv_obj_set_size(r->root, DASH_CARD_W, DASH_ROW_H);
    lv_obj_clear_flag(r->root, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

    r->name = label(r->root, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_long_mode(r->name, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(r->name, DASH_NAME_W);
    lv_obj_set_pos(r->name, 8, 0);
    r->sub = label(r->root, &lv_font_montserrat_12, COL_SUB);
    lv_obj_set_pos(r->sub, 8, 17);
    if (lights) {
        for (int k = 0; k < DASH_DOTS; k++) {
            r->dot[k] = box(r->root, COL_TRACK);
            lv_obj_set_size(r->dot[k], DASH_DOT, DASH_DOT);
            lv_obj_set_style_radius(r->dot[k], LV_RADIUS_CIRCLE, 0);
            lv_obj_set_pos(r->dot[k], 8 + DASH_BAR_W - DASH_DOTS * DASH_DOT - (DASH_DOTS - 1) * DASH_DOT_GAP
                                      + k * (DASH_DOT + DASH_DOT_GAP), 5);
        }
    } else {
        r->val = label(r->root, &lv_font_montserrat_20, COL_TEXT);
        lv_obj_set_width(r->val, 60);
        lv_obj_set_style_text_align(r->val, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_pos(r->val, 8 + DASH_BAR_W - 60, 1);
    }
    lv_obj_t *track = box(r->root, COL_TRACK);
    lv_obj_set_pos(track, 8, 32);
    lv_obj_set_size(track, DASH_BAR_W, 3);
    lv_obj_set_style_radius(track, 1, 0);
    r->fill = box(track, lights ? COL_SKY : COL_RED);
    lv_obj_set_size(r->fill, 0, 3);
    lv_obj_set_style_radius(r->fill, 1, 0);
    lv_obj_add_flag(r->root, LV_OBJ_FLAG_HIDDEN);
}

static lv_obj_t *dash_empty(lv_obj_t *card, const char *text)
{
    lv_obj_t *l = label(card, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(l, text);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 8);
    return l;
}

// The green dashboard; layout in the section comment above dash_refresh().
static void build_dash(void)
{
    static const char *NAME[4] = { "Alerts today", "Probes today", "Port scans today", "LAN devices" };
    const lv_color_t col[4] = { COL_RED, COL_AMBER, COL_TEXT, COL_SKY };
    for (int i = 0; i < 4; i++) {
        lv_obj_t *t = box(s_idle, COL_CARD);
        lv_obj_set_size(t, DASH_TILE_W, DASH_TILE_H);
        lv_obj_set_pos(t, 4 + i * DASH_TILE_PITCH, DASH_TILE_Y);
        lv_obj_set_style_radius(t, 8, 0);
        lv_obj_t *n = label(t, &lv_font_montserrat_12, COL_SUB);
        lv_label_set_text(n, NAME[i]);
        lv_obj_set_pos(n, 8, 3);
        s_tile_val[i] = label(t, &lv_font_montserrat_28, col[i]);
        lv_label_set_text(s_tile_val[i], "0");
        lv_obj_set_pos(s_tile_val[i], 8, 16);
    }

    lv_obj_t *off = dash_card(DASH_CARD_X0, DASH_CARD_Y, DASH_CARD_W, DASH_CARD_H,
                              "Top offenders today", "alerts");
    lv_obj_t *talk = dash_card(DASH_CARD_X1, DASH_CARD_Y, DASH_CARD_W, DASH_CARD_H,
                               "LAN talkers", "packets an hour");
    for (int i = 0; i < DASH_ROWS; i++) {
        dash_row(&s_off[i], off, i, false);
        dash_row(&s_talk[i], talk, i, true);
    }
    s_off_empty  = dash_empty(off, "No alerts today");
    s_talk_empty = dash_empty(talk, "No LAN devices yet");

    s_foot = label(s_idle, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_recolor(s_foot, true);
    lv_label_set_long_mode(s_foot, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(s_foot, 468);
    lv_obj_set_style_text_align(s_foot, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_pos(s_foot, 6, DASH_FOOT_Y);
}

static void build_incident(lv_obj_t *scr)
{
    // Black, the whole screen; the status bar, created after it, draws over
    // its top in YELLOW and is hidden in RED.
    s_inc = box(scr, COL_EMB_BG);
    lv_obj_set_size(s_inc, 480, 320);
    lv_obj_set_pos(s_inc, 0, 0);
    lv_obj_add_flag(s_inc, LV_OBJ_FLAG_HIDDEN);

    build_emblem(&s_emb_red, s_emb_pts[0], s_inc, RED_EMB_Y, &EMB_RED);
    build_emblem(&s_emb_yel, s_emb_pts[1], s_inc, YEL_EMB_Y, &EMB_YELLOW);

    s_d_code = label(s_inc, &lv_font_montserrat_20, COL_TEXT);
    s_d_src  = label(s_inc, &lv_font_montserrat_20, COL_TEXT);
    s_d_times = label(s_inc, &lv_font_montserrat_14, COL_SUB);
    lv_obj_t *det[] = { s_d_code, s_d_src, s_d_times };    // fitted at words, or short
    for (int i = 0; i < 3; i++) {
        lv_label_set_long_mode(det[i], LV_LABEL_LONG_CLIP);
        lv_obj_set_width(det[i], DET_W);
    }
    // The headline's detail wraps at word boundaries; two 14 px lines hold
    // about 120 characters, more than a headline has.
    s_d_detail = label(s_inc, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_long_mode(s_d_detail, LV_LABEL_LONG_WRAP);
    lv_obj_set_size(s_d_detail, DET_W, DET_DETAIL_H);

    s_note = label(s_inc, &lv_font_montserrat_14, COL_SUB);
    lv_label_set_text(s_note, "Resolve from the dashboard");
    lv_obj_set_width(s_note, 480);
    lv_obj_set_style_text_align(s_note, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_pos(s_note, 0, YEL_NOTE_Y);

    lv_obj_t *fill;
    s_b_ack = panel_button(s_inc, COL_RED, TXT_ACK, COL_FILL_ACK, &fill, &s_b_ack_lbl);
    hold_attach(&s_h_ack, s_b_ack, fill, ack_done, ack_press_start_cb);
    s_b_ign_err = panel_button(s_inc, COL_SUB, "IGNORE\nERROR", COL_SUB, NULL, NULL);
    lv_obj_add_event_cb(s_b_ign_err, ignore_ask_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)IGN_ERROR);
    s_b_ign_dev = panel_button(s_inc, COL_SUB, "IGNORE\nDEVICE", COL_SUB, NULL, NULL);
    lv_obj_add_event_cb(s_b_ign_dev, ignore_ask_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)IGN_DEVICE);
}

// An LCARS alert button: a pill with dark 14 px text; with fill, a c5 hold
// fill at 55 % under the label.
static lv_obj_t *lc_alert_button(lv_obj_t *parent, uint32_t col, const char *text,
                                 lv_obj_t **fill, lv_obj_t **lbl)
{
    lv_obj_t *b = lv_btn_create(parent);
    lv_obj_set_style_bg_color(b, lv_color_hex(col), 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_radius(b, LC_BTN_H / 2, 0);
    lv_obj_set_style_pad_all(b, 0, 0);
    lv_obj_set_style_clip_corner(b, true, 0);
    if (fill) {
        *fill = box(b, lv_color_hex(LCARS_PAL->c5));
        lv_obj_set_style_bg_opa(*fill, 140, 0);
        lv_obj_set_size(*fill, 0, LV_PCT(100));
        lv_obj_align(*fill, LV_ALIGN_LEFT_MID, 0, 0);
    }
    lv_obj_t *l = label(b, &lv_font_montserrat_14, lv_color_black());
    lv_label_set_text(l, text);
    lv_obj_center(l);
    if (lbl) *lbl = l;
    lv_obj_add_flag(b, LV_OBJ_FLAG_HIDDEN);
    return b;
}

static void build_lcars_alert(void)
{
    lv_obj_t *p = lcars_alert_box();
    build_emblem(&s_emb_lc_red, s_emb_pts[2], p, 0, &EMB_LC_RED);
    build_emblem(&s_emb_lc_yel, s_emb_pts[3], p, 0, &EMB_LC_YELLOW);
    const lv_coord_t W = LCARS_CONTENT_W;
    s_lc_code = label(p, &lv_font_montserrat_20, LCARS_COL(c5));
    lv_obj_set_pos(s_lc_code, 0, 114);
    s_lc_src = label(p, &lv_font_montserrat_14, LCARS_COL(c2));
    lv_obj_set_pos(s_lc_src, 0, 139);
    s_lc_head = label(p, &lv_font_montserrat_12, LCARS_COL(c2));
    lv_obj_set_pos(s_lc_head, 0, 158);
    lv_obj_t *t[] = { s_lc_code, s_lc_src, s_lc_head };
    for (int i = 0; i < 3; i++) {
        lv_label_set_long_mode(t[i], LV_LABEL_LONG_CLIP);
        lv_obj_set_width(t[i], W);
        lv_obj_set_style_text_align(t[i], LV_TEXT_ALIGN_CENTER, 0);
    }
    static const char *const K[3] = { "EVENTS", "OPEN FOR", "ALSO SEEN" };
    for (int i = 0; i < 3; i++) {
        lv_coord_t x = (lv_coord_t)(i * 135);
        lv_obj_t *bar = box(p, LCARS_COL(c3));
        lv_obj_set_pos(bar, x, 178);
        lv_obj_set_size(bar, 129, 3);
        lv_obj_t *k = label(p, &lv_font_montserrat_12, LCARS_COL(c4));
        lv_label_set_text(k, K[i]);
        lv_obj_set_pos(k, x, 183);
        s_lc_stat[i] = label(p, &lv_font_montserrat_14, LCARS_COL(c2));
        lv_label_set_long_mode(s_lc_stat[i], LV_LABEL_LONG_CLIP);
        lv_obj_set_width(s_lc_stat[i], 129);
        lv_obj_set_pos(s_lc_stat[i], x, 197);
    }
    lv_obj_t *fill;
    s_lc_ack = lc_alert_button(p, LCARS_PAL->accent, "ACKNOWLEDGE", &fill, &s_lc_ack_lbl);
    hold_attach(&s_h_lc_ack, s_lc_ack, fill, lc_ack_done, ack_press_start_cb);
    s_lc_ign_err = lc_alert_button(p, LCARS_PAL->c4, "IGNORE ERROR", NULL, NULL);
    lv_obj_add_event_cb(s_lc_ign_err, ignore_ask_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)IGN_ERROR);
    s_lc_ign_dev = lc_alert_button(p, LCARS_PAL->c4, "IGNORE DEVICE", NULL, NULL);
    lv_obj_add_event_cb(s_lc_ign_dev, ignore_ask_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)IGN_DEVICE);
}

static void build_ui(void)
{
    lv_obj_t *scr = lv_scr_act();
    lv_obj_set_style_bg_color(scr, COL_BG, 0);
    lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

    build_incident(scr);

    // Status bar
    s_bar = box(scr, COL_CARD);
    lv_obj_set_size(s_bar, 480, STATUS_H);
    lv_obj_align(s_bar, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *brand = label(s_bar, &lv_font_montserrat_20, COL_GREEN);
    lv_label_set_text(brand, "ShadowSentry");
    lv_obj_align(brand, LV_ALIGN_LEFT_MID, 6, 0);

    s_net = label(s_bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_net, "Starting...");
    lv_obj_align(s_net, LV_ALIGN_LEFT_MID, 160, 0);

    s_clock = label(s_bar, &lv_font_montserrat_14, COL_TEXT);
    lv_label_set_text(s_clock, "--:--:--");
    lv_obj_align(s_clock, LV_ALIGN_RIGHT_MID, -112, 0);

    s_pill = box(s_bar, COL_GREEN);             // nearly the bar's height, 20 px text
    lv_obj_set_size(s_pill, 104, 24);
    lv_obj_align(s_pill, LV_ALIGN_RIGHT_MID, -2, 0);
    lv_obj_set_style_radius(s_pill, 12, 0);
    // Dark text on every fill (green, red, amber), set on the pill too so
    // nothing inherited can lighten it.
    lv_obj_set_style_text_color(s_pill, COL_DARK, 0);
    s_pill_lbl = label(s_pill, &lv_font_montserrat_20, COL_DARK);
    lv_obj_set_style_text_opa(s_pill_lbl, LV_OPA_COVER, 0);
    lv_label_set_text(s_pill_lbl, "GREEN");
    lv_obj_center(s_pill_lbl);

    // Green view: one transparent, untouchable container for all of it, so the
    // views switch with one flag.
    s_idle = lv_obj_create(scr);
    lv_obj_remove_style_all(s_idle);
    lv_obj_set_size(s_idle, 480, 320);
    lv_obj_set_pos(s_idle, 0, 0);
    lv_obj_clear_flag(s_idle, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

    build_dash();
    lcars_build(scr);                       // over the dashboard, hidden until chosen
    build_lcars_alert();

    // Running light: a dark track the full width, and the moving segment on
    // it. On the top layer, so a dialog cannot stop it. Green only.
    s_rl_track = box(lv_layer_top(), COL_BG);
    lv_obj_set_size(s_rl_track, 480, RUNLIGHT_H);
    lv_obj_set_pos(s_rl_track, 0, RUNLIGHT_Y);
    s_rl_seg = box(s_rl_track, COL_BG);
    lv_obj_set_size(s_rl_seg, RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W, RUNLIGHT_H);
    lv_obj_set_pos(s_rl_seg, -(RUNLIGHT_HEAD_W + RUNLIGHT_TRAIL_W), 0);
    runlight_set(COL_GREEN);
    s_rl = lv_timer_create(runlight_cb, RUNLIGHT_STEP_MS, NULL);
    lv_timer_create(roll_cb, EMB_ROLL_TICK_MS, NULL);       // the emblem's stripes

    // Face light: pure white over everything, not clickable, hidden
    s_white = box(lv_layer_top(), lv_color_white());
    lv_obj_set_size(s_white, 480, 320);
    lv_obj_set_pos(s_white, 0, 0);
    lv_obj_add_flag(s_white, LV_OBJ_FLAG_HIDDEN);

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


    alarm_info_t a;
    alarm_get(&a);
    apply_alarm(&a);
    ESP_LOGI(TAG, "Panel built, internal heap %u B before, %u B after",
             (unsigned)heap0, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    int64_t last_us = esp_timer_get_time();
    for (;;) {
        umsg_t m;
        while (xQueueReceive(s_q, &m, 0) == pdTRUE) {
            switch (m.kind) {
            case UMSG_EVENT:
                kpi_add(&m.e);
                lcars_event(&m.e);
                break;
            case UMSG_ALARM:    apply_alarm(&m.a);              break;
            case UMSG_NET:      lv_label_set_text(s_net, m.net); break;
            case UMSG_LIT_DONE: lit_off();                      break;
            }
        }
        if (s_lit && lv_tick_elaps(s_lit_at) >= LIT_TIMEOUT_MS) {
            ESP_LOGW(TAG, "Face light: no word from the camera in %d ms, white taken down", LIT_TIMEOUT_MS);
            lit_off();
        }

        uint32_t ms = (uint32_t)((esp_timer_get_time() - last_us) / 1000);
        lv_tick_inc(ms);
        last_us += (int64_t)ms * 1000;      // carry the sub-ms remainder
        // Debug pause (POST /api/debug/panel): no LVGL timers, so no refresh,
        // no sweeps and no SPI display traffic, to split network latency.
        if (s_debug_paused) { vTaskDelay(pdMS_TO_TICKS(50)); continue; }
        int64_t t = esp_timer_get_time();
        lv_timer_handler();
        uint32_t us = (uint32_t)(esp_timer_get_time() - t);
        if (us > s_loop_max_us) s_loop_max_us = us;
        loop_measure(us);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void ui_debug_pause(bool paused)
{
    s_debug_paused = paused;
    ESP_LOGW(TAG, "Panel %s (debug)", paused ? "paused" : "running");
}

bool ui_debug_paused(void) { return s_debug_paused; }

void ui_start(void)
{
    s_q = xQueueCreate(UI_QUEUE_DEPTH, sizeof(umsg_t));
    log_store_add_listener(on_event);
    alarm_add_listener(on_alarm);
    xTaskCreatePinnedToCore(ui_task, "ui", UI_TASK_STACK, NULL, UI_TASK_PRIO, NULL, 1);
}
