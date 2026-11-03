// 07 SUBSYS, the LCARS panel's about screen. See ui_subsys.h.
//
// Layout (screen coordinates), from docs/mockups/about-boot.html:
//   header bar  y 0..13, #7a1410, its text at x 8 (12 px, letter space 1)
//   logo        x 12..107, y 24..119 (the panel logo zoomed to 96 px)
//   title       x 116, y 26: "SUBSYSTEM INFO" (28 px, letter space 2)
//   sub lines   x 116, y 62 and 80 (14 px)
//   terminal    x 16..467, y 128 + 16 * i (12 px, letter space 1): the key in
//               #ff6a5e, " = value" in #e8261c, cut with "..."; a blinking
//               cursor after the last
//   buttons     y 296..313: RETURN x 8 w 92 (red, black text), then six code
//               buttons w 58, 4 px apart (dark red, red text), to x 471

#include "ui_subsys.h"
#include "ui_logo.h"
#include "board.h"
#include "config.h"
#include "describe.h"
#include "wifi_manager.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_timer.h"
#if __has_include("gz/build_id.h")
#include "gz/build_id.h"                // tools/build_id.py
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

static const char *TAG = "SUBSYS";

#define SS_RED      0xe8261c
#define SS_DARK     0x7a1410
#define SS_HI       0xff6a5e
#define F12         (&lv_font_montserrat_12)
#define F14         (&lv_font_montserrat_14)
#define F28         (&lv_font_montserrat_28)

#define LOGO_X      12
#define LOGO_Y      24
#define LOGO_PX     96
#define TERM_X      16
#define TERM_Y      128
#define TERM_W      452
#define TERM_PITCH  16
#define TERM_LS     1                   // letter space, px
#define TERM_N      6
#define BTN_Y       296
#define BTN_H       18
#define BTN_RET_W   92
#define BTN_W       58
#define BTN_GAP     4
#define CODES       6
#define BLINK_MS    500
#define VALUES_MS   1000

static const char *const KEY[TERM_N] = { "UNIT", "BASE", "FORK", "BUILD", "NODE", "ACCESS CODE" };

EXT_RAM_BSS_ATTR static lv_obj_t *s_box, *s_logo, *s_id, *s_cursor;
EXT_RAM_BSS_ATTR static lv_obj_t *s_val[TERM_N], *s_code_lbl[CODES];
EXT_RAM_BSS_ATTR static lv_coord_t s_val_x[TERM_N];
EXT_RAM_BSS_ATTR static lv_timer_t *s_blink, *s_tick;
EXT_RAM_BSS_ATTR static char s_codes[CODES][DESCRIBE_CODE_LEN];
EXT_RAM_BSS_ATTR static bool s_logo_set;
static void (*s_back)(void);

// ── Helpers ───────────────────────────────────────────────────────────────────

static void upper(char *s) { for (; *s; s++) *s = (char)toupper((unsigned char)*s); }

static void set_text(lv_obj_t *l, const char *t)
{
    const char *o = lv_label_get_text(l);
    if (!o || strcmp(o, t)) lv_label_set_text(l, t);
}

static lv_obj_t *fill(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, uint32_t c)
{
    lv_obj_t *o = lv_obj_create(p);
    lv_obj_remove_style_all(o);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_bg_color(o, lv_color_hex(c), 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    return o;
}

// A label; w > 0 cuts it at w px with "...".
static lv_obj_t *text(lv_obj_t *p, const lv_font_t *f, uint32_t c, lv_coord_t ls,
                      lv_coord_t x, lv_coord_t y, lv_coord_t w, const char *t)
{
    lv_obj_t *l = lv_label_create(p);
    lv_obj_set_style_text_font(l, f, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(c), 0);
    lv_obj_set_style_text_letter_space(l, ls, 0);
    lv_label_set_text(l, t);
    if (w > 0) {
        lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
        lv_obj_set_width(l, w);
    }
    lv_obj_set_pos(l, x, y);
    return l;
}

static void build_hash(char *b, size_t len)
{
#ifdef SS_BUILD_HASH
    strlcpy(b, SS_BUILD_HASH, len);
#else
    strlcpy(b, esp_app_get_description()->version, len);    // git describe at configure time
#endif
    upper(b);
}

// ── Values ────────────────────────────────────────────────────────────────────

static void fmt_uptime(char *b, size_t len)
{
    uint32_t s = (uint32_t)(esp_timer_get_time() / 1000000);
    uint32_t d = s / 86400, h = s / 3600 % 24, m = s / 60 % 60;
    if (d)      snprintf(b, len, "UP %lu D %02lu H", (unsigned long)d, (unsigned long)h);
    else if (h) snprintf(b, len, "UP %lu H %02lu MIN", (unsigned long)h, (unsigned long)m);
    else        snprintf(b, len, "UP %lu MIN", (unsigned long)m);
}

static void values_update(void)
{
    char v[TERM_N][96], hash[40], ip[20], up[24];
    build_hash(hash, sizeof(hash));
    snprintf(v[0], sizeof(v[0]), " = %s", BOARD_NAME);
    snprintf(v[1], sizeof(v[1]), " = SHADOWSENTRY S3 BY RDX1S (MIT)");
    snprintf(v[2], sizeof(v[2]), " = ROBERT MECH | SHADOWSENTRYS3-ESP-TERMINAL");
    const char *idf = esp_get_idf_version();
    if (idf[0] == 'v') idf++;
#ifdef SS_BUILD_DATE
    const char *date = SS_BUILD_DATE;
#else
    const char *date = esp_app_get_description()->date;
#endif
    snprintf(v[3], sizeof(v[3]), " = %s | %s | IDF %s", hash, date, idf);
    wifi_manager_get_ip_str(ip, sizeof(ip));
    fmt_uptime(up, sizeof(up));
    if (ip[0]) snprintf(v[4], sizeof(v[4]), " = %s:%d | %s", ip, ADMIN_PORT, up);
    else       snprintf(v[4], sizeof(v[4]), " = NO WI-FI | %s", up);
    // The access code: the date, the address's last octet and the admin port.
    char day[12] = "00-00-0000";
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    if (tm.tm_year + 1900 >= 2024) strftime(day, sizeof(day), "%d-%m-%Y", &tm);
    const char *dot = strrchr(ip, '.');
    unsigned oct = dot ? (unsigned)atoi(dot + 1) % 10000u : 0;
    snprintf(v[5], sizeof(v[5]), " = %s-%04u-%d", day, oct, ADMIN_PORT);
    for (int i = 0; i < TERM_N; i++) {
        upper(v[i]);
        set_text(s_val[i], v[i]);
    }
    char id[64];
    snprintf(id, sizeof(id), "SUBSYS ID = SENTRY S3 / %s", hash);
    set_text(s_id, id);
    // The cursor follows the last line's text.
    const char *t = lv_label_get_text(s_val[TERM_N - 1]);
    lv_coord_t x = s_val_x[TERM_N - 1] + lv_txt_get_width(t, (uint32_t)strlen(t), F12, TERM_LS, LV_TEXT_FLAG_NONE) + TERM_LS;
    lv_coord_t cw = lv_txt_get_width("_", 1, F12, 0, LV_TEXT_FLAG_NONE);
    if (x > TERM_X + TERM_W - cw) x = TERM_X + TERM_W - cw;
    lv_obj_set_x(s_cursor, x);
}

static void codes_update(void)
{
    for (int i = 0; i < CODES; i++) set_text(s_code_lbl[i], s_codes[i][0] ? s_codes[i] : "--");
}

static void logo_set(void)
{
    if (s_logo_set) return;
    s_logo_set = true;
    const lv_img_dsc_t *d = ui_logo_get();
    if (!d) return;
    lv_img_set_src(s_logo, d);
    lv_coord_t m = d->header.w > d->header.h ? d->header.w : d->header.h;
    lv_img_set_zoom(s_logo, (uint16_t)(LV_IMG_ZOOM_NONE * LOGO_PX / m));
    lv_obj_center(s_logo);
}

static void blink_cb(lv_timer_t *t)
{
    (void)t;
    if (lv_obj_has_flag(s_cursor, LV_OBJ_FLAG_HIDDEN)) lv_obj_clear_flag(s_cursor, LV_OBJ_FLAG_HIDDEN);
    else                                                lv_obj_add_flag(s_cursor, LV_OBJ_FLAG_HIDDEN);
}

static void tick_cb(lv_timer_t *t)
{
    (void)t;
    values_update();
}

static void return_cb(lv_event_t *ev)
{
    (void)ev;
    if (s_back) s_back();
}

// ── Public ────────────────────────────────────────────────────────────────────

void subsys_build(lv_obj_t *root, void (*back)(void))
{
    s_back = back;
    s_box = fill(root, 0, 0, 480, 320, 0x000000);

    lv_obj_t *bar = fill(s_box, 0, 0, 480, 14, SS_DARK);
    text(bar, F12, SS_RED, 1, 8, 0, 0, "SHADOWSENTRY | LOCAL SUBSYSTEM CTL");

    lv_obj_t *la = fill(s_box, LOGO_X, LOGO_Y, LOGO_PX, LOGO_PX, 0x000000);
    lv_obj_set_style_bg_opa(la, LV_OPA_TRANSP, 0);
    s_logo = lv_img_create(la);
    // In the screen's red: a recolour that keeps some of the logo's own shading.
    lv_obj_set_style_img_recolor(s_logo, lv_color_hex(SS_RED), 0);
    lv_obj_set_style_img_recolor_opa(s_logo, LV_OPA_70, 0);

    text(s_box, F28, SS_RED, 2, 116, 26, 356, "SUBSYSTEM INFO");
    text(s_box, F14, SS_RED, 0, 116, 62, 356, "LOCAL ACCESS GRANTED");
    s_id = text(s_box, F14, SS_RED, 0, 116, 80, 356, "SUBSYS ID = SENTRY S3");

    for (int i = 0; i < TERM_N; i++) {
        lv_coord_t y = TERM_Y + i * TERM_PITCH;
        text(s_box, F12, SS_HI, TERM_LS, TERM_X, y, 0, KEY[i]);
        lv_coord_t kw = lv_txt_get_width(KEY[i], (uint32_t)strlen(KEY[i]), F12, TERM_LS, LV_TEXT_FLAG_NONE) + TERM_LS;
        s_val_x[i] = TERM_X + kw;
        s_val[i] = text(s_box, F12, SS_RED, TERM_LS, s_val_x[i], y, TERM_W - kw, "");
    }
    s_cursor = text(s_box, F12, SS_HI, 0, TERM_X, TERM_Y + (TERM_N - 1) * TERM_PITCH, 0, "_");

    lv_obj_t *ret = fill(s_box, 8, BTN_Y, BTN_RET_W, BTN_H, SS_RED);
    lv_obj_add_flag(ret, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_ext_click_area(ret, 6);             // an 18 px row: a little more to aim at
    lv_obj_add_event_cb(ret, return_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l = text(ret, F12, 0x000000, 0, 0, 0, 0, "RETURN");
    lv_obj_center(l);
    for (int i = 0; i < CODES; i++) {
        lv_obj_t *b = fill(s_box, 8 + BTN_RET_W + BTN_GAP + i * (BTN_W + BTN_GAP), BTN_Y, BTN_W, BTN_H, SS_DARK);
        s_code_lbl[i] = text(b, F12, SS_RED, 0, 0, 0, 0, "--");
        lv_obj_align(s_code_lbl[i], LV_ALIGN_CENTER, 0, 0);
    }

    s_blink = lv_timer_create(blink_cb, BLINK_MS, NULL);
    s_tick = lv_timer_create(tick_cb, VALUES_MS, NULL);
    lv_timer_pause(s_blink);
    lv_timer_pause(s_tick);
    lv_obj_add_flag(s_box, LV_OBJ_FLAG_HIDDEN);
}

void subsys_show(bool on)
{
    if (!s_box || on == subsys_shown()) return;
    if (on) {
        logo_set();
        values_update();
        codes_update();
        lv_obj_clear_flag(s_cursor, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_box, LV_OBJ_FLAG_HIDDEN);
        lv_timer_resume(s_blink);
        lv_timer_resume(s_tick);
        ESP_LOGI(TAG, "Shown");
    } else {
        lv_obj_add_flag(s_box, LV_OBJ_FLAG_HIDDEN);
        lv_timer_pause(s_blink);
        lv_timer_pause(s_tick);
    }
}

bool subsys_shown(void) { return s_box && !lv_obj_has_flag(s_box, LV_OBJ_FLAG_HIDDEN); }

void subsys_note(const attack_log_t *e)
{
    const char *c = describe_code(e);
    int k = CODES - 1;                              // where it was, else the oldest
    for (int i = 0; i < CODES; i++) if (!strcmp(s_codes[i], c)) { k = i; break; }
    memmove(&s_codes[1], &s_codes[0], sizeof(s_codes[0]) * (size_t)k);
    strlcpy(s_codes[0], c, sizeof(s_codes[0]));
    if (subsys_shown()) codes_update();
}
