// Clan front panel (panel_style 2). See ui_clan.h.
//
// Layout on the 480 x 320 grid (ui_scale.h), from docs/mockups/clan-panel.html:
//   emblem      x 4, y 4, 64 x 64 (kept square: UI_SS), a hexagon plate and the sigil
//   banner      x 96..365, y 4..47: the title (28 px gold, else 20 px) and the
//               subtitle "SENTRY | 0N PAGE" (12 px)
//   status      x 374..475, y 4..47: "STATUS" and the pill
//   glow strips x 120..179 and 300..359, y 50..52
//   nav         x 4..103, six plate buttons 32 px tall from y 74, 35 apart; AUTO
//               at y 284..315
//   main        x 108..475, y 58..315 (368 x 258): the pages
//   alert       x 4..475, y 58..315 (472 x 258), nav and pages hidden
//
// Plates are LVGL rectangles with a vertical gradient (corners rounded, not
// cut: a cut corner is a polygon mask on every repaint under it); the
// emblem, banner, nav and alert buttons are convex polygons drawn in their
// own LV_EVENT_DRAW_MAIN (lv_draw_polygon, then lv_draw_line for the edge).
// The background is the 64 x 64 metal tile (ui_clan_tex.c), tiled by LVGL.

#include "ui_clan.h"
#include "ui_lcars.h"
#include "ui_scale.h"
#include "ui_subsys.h"
#include "describe.h"
#include "discovery.h"
#include "ignore.h"
#include "router_trip.h"
#include "settings.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static const char *TAG = "CLAN";

extern const lv_img_dsc_t ui_clan_tex;          // ui_clan_tex.c (tools/make_clan_texture.py)

// ── Palette ───────────────────────────────────────────────────────────────────
//
// The preview's: gunmetal plates, crimson, gold, holo cyan; text #e9e2d6 and
// dim #a89f92 (7.9:1 on the plates' #26231f).

#define C_BG        0x1a1817
#define C_PLATE1    0x34302c                    // plate gradient, top to bottom
#define C_PLATE2    0x1f1c1a
#define C_BTN1      0x3d3935                    // nav and buttons
#define C_BTN2      0x24211f
#define C_EDGE      0x5a534b
#define C_HOLO1     0x0d2c3a                    // holo plate
#define C_HOLO2     0x05121a
#define C_HOLOEDGE  0x2c6f86
#define C_RED       0xc4161c
#define C_RED2      0x7d0f12
#define C_REDSEL1   0xa3161c                    // the selected nav button
#define C_REDSEL2   0x5a0b0e
#define C_GLOW      0xff3b30
#define C_REDHI     0xff4a3d
#define C_REDTXT    0xff6a5e
#define C_HOTTXT    0xffb3ac
#define C_GOLD      0xe0b04a
#define C_GOLDHI    0xffe08a
#define C_GOLDT     0xf3c75c                    // the title
#define C_GOLDSEG   0xc58f22
#define C_HOLO      0x3fd2ff
#define C_HOLO_D    0x167fa8
#define C_GREEN     0x35e06b
#define C_AMBER     0xffc53d
#define C_TXT       0xe9e2d6
#define C_DIM       0xa89f92
#define C_SEGOFF    0x3a2e28
#define C_TRACK     0x2a2522
#define C_SEP       0x3a3531
#define C_HI        0xfff1c9                    // near-white gold: flashes, the selected icon

#define F12 UI_F12
#define F14 UI_F14
#define F20 UI_F20
#define F28 UI_F28

// The motion engine's tones (ui_lcars.c, Motion): hits red, packets cyan,
// ripples gold.
static lv_obj_t *fx_obj_cb(int it, uint8_t *part);
static void      fx_rest_cb(int it);
static const lcars_fx_skin_t CLAN_FX = {
    .obj = fx_obj_cb, .rest = fx_rest_cb,
    .hi = C_HI, .decay = C_REDHI, .glow = C_HOLO, .ripple = C_GOLD, .tick = C_GOLDHI,
};

// ── Layout ────────────────────────────────────────────────────────────────────

#define MAIN_X      108
#define MAIN_Y      58
#define MAIN_W      368
#define MAIN_H      258
#define NAV_X       4
#define NAV_Y       74
#define NAV_W       100
#define NAV_H       32
#define NAV_PITCH   35
#define AUTO_Y      284
#define DATA_MS     2000                        // the shown page's figures
#define SWEEP_MS    100                         // the radar's sweep line: one step
#define SWEEP_STEPS 40                          //   a turn in 4 s
#define SEGS        12                          // SHIELDS and POWER bars
#define POWER_FULL_KB 100

enum { CP_TAC, CP_BAIT, CP_PERIM, CP_SYS, CP_CONT, CP_INFO, CP_N };
#define CP_AUTO_N   5                           // AUTO rotates TACTICAL..CONTACTS, as LCARS its five
static const char *const NAV_TXT[CP_N] = { "TACTICAL", "BAIT", "PERIMETER", "SYSTEMS", "CONTACTS", "INFO" };
static const int8_t PG_SENSE[CP_N] = {          // whose senses the motion runs
    LCARS_PG_OPS, LCARS_PG_TRAPS, LCARS_PG_WIRES, LCARS_PG_NET, LCARS_PG_DEV, LCARS_PG_NONE,
};

EXT_RAM_BSS_ATTR static lv_obj_t *s_root, *s_main, *s_alert_box, *s_nav, *s_auto_btn, *s_auto_led;
EXT_RAM_BSS_ATTR static lv_obj_t *s_title, *s_sub, *s_pill, *s_pill_led, *s_pill_lbl, *s_glow[2];
EXT_RAM_BSS_ATTR static lv_obj_t *s_page[CP_N], *s_nav_btn[CP_N];
EXT_RAM_BSS_ATTR static char      s_title_txt[20];
static int       s_cur = CP_TAC;
static bool      s_auto = true;
EXT_RAM_BSS_ATTR static bool      s_green;      // the pages are shown (GREEN, clan style)
EXT_RAM_BSS_ATTR static uint32_t  s_page_at, s_data_at;
EXT_RAM_BSS_ATTR static alarm_cond_t s_cond;

// ── Helpers ───────────────────────────────────────────────────────────────────

static void show(lv_obj_t *o, bool on)
{
    if (on) lv_obj_clear_flag(o, LV_OBJ_FLAG_HIDDEN);
    else    lv_obj_add_flag(o, LV_OBJ_FLAG_HIDDEN);
}

static void set_text(lv_obj_t *l, const char *t)
{
    const char *o = lv_label_get_text(l);
    if (!o || strcmp(o, t)) lv_label_set_text(l, t);
}

static void fmt_ip(uint32_t ip_net, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip_net };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

// "3:39 PM" or "15:39"
static void fmt_hm(uint32_t ts, char *buf, size_t len)
{
    ui_fmt_time(ts, false, buf, len);
    if (settings_get()->clock_24h && strlen(buf) == 8) buf[5] = '\0';
}

static lv_obj_t *area_px(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h)
{
    lv_obj_t *o = lv_obj_create(p);
    lv_obj_remove_style_all(o);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    return o;
}

// A transparent area at grid x, y (relative to p's grid origin), w x h.
static lv_obj_t *area(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h)
{
    return area_px(p, UI_SX(x), UI_SY(y), UI_SW(x, w), UI_SH(y, h));
}

static lv_obj_t *fill(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, uint32_t c)
{
    lv_obj_t *o = area(p, x, y, w, h);
    lv_obj_set_style_bg_color(o, lv_color_hex(c), 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    return o;
}

// A label at grid x, y; w > 0 clips it at w grid px.
static lv_obj_t *text(lv_obj_t *p, const lv_font_t *f, uint32_t c, lv_coord_t x, lv_coord_t y,
                      lv_coord_t w, const char *t)
{
    lv_obj_t *l = lv_label_create(p);
    lv_obj_set_style_text_font(l, f, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(c), 0);
    lv_label_set_text(l, t ? t : "");
    if (w > 0) {
        lv_label_set_long_mode(l, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(l, UI_SW(x, w));
    }
    lv_obj_set_pos(l, UI_SX(x), UI_SY(y));
    return l;
}

// A plate: a vertical gradient, a 1 px edge, corners rounded 3 px; holo: the
// cyan panel. ticks: the red corner marks (top left, bottom right).
static lv_obj_t *plate(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, bool holo, bool ticks)
{
    lv_obj_t *o = area(p, x, y, w, h);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(o, lv_color_hex(holo ? C_HOLO1 : C_PLATE1), 0);
    lv_obj_set_style_bg_grad_color(o, lv_color_hex(holo ? C_HOLO2 : C_PLATE2), 0);
    lv_obj_set_style_bg_grad_dir(o, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_border_color(o, lv_color_hex(holo ? C_HOLOEDGE : C_EDGE), 0);
    lv_obj_set_style_border_width(o, 1, 0);
    lv_obj_set_style_radius(o, UI_SS(3), 0);
    if (ticks) {
        fill(o, 6, 3, 14, 3, C_RED);
        fill(o, w - 20, h - 6, 14, 3, C_RED);
    }
    return o;
}

// The label's font for a string at most w screen px wide: big, else small,
// else small and shortened.
static const lv_font_t *fit_font(char *s, const lv_font_t *big, lv_coord_t ls_big, const lv_font_t *small,
                                 lv_coord_t ls_small, lv_coord_t w, lv_coord_t *ls)
{
    uint32_t n = (uint32_t)strlen(s);
    *ls = ls_big;
    if (lv_txt_get_width(s, n, big, ls_big, LV_TEXT_FLAG_NONE) <= w) return big;
    *ls = ls_small;
    if (lv_txt_get_width(s, n, small, ls_small, LV_TEXT_FLAG_NONE) > w) lcars_fit(s, small, w - ls_small * (lv_coord_t)n);
    return small;
}

// ── Shapes: polygon plates ────────────────────────────────────────────────────
//
// HEX_H  points left and right (the banner, the alert banner and buttons)
// HEX_V  points up and down (the emblem)
// PENT   square left, pointed right (the nav buttons)
// Convex, so lv_draw_polygon draws them in one pass with the gradient. The
// edge is lv_draw_line around it; a glow is a wider, faint line under the
// fill. With fill set (a child whose width the hold animation grows), the
// part of the shape left of the fill's width is drawn again in fill_col.

enum { SH_HEX_H, SH_HEX_V, SH_PENT };
typedef struct {
    uint8_t    kind;
    lv_coord_t cut, edge_w;                     // screen px
    uint32_t   top, bot, edge, glow;            // glow 0: none
    lv_obj_t  *fill;
    uint32_t   fill_col;
} shape_t;
#define SHAPES 16
EXT_RAM_BSS_ATTR static shape_t s_shp[SHAPES];
EXT_RAM_BSS_ATTR static int     s_nshp;

static int shape_points(const shape_t *s, const lv_area_t *a, lv_point_t *p)
{
    const lv_coord_t c = s->cut, ym = (lv_coord_t)((a->y1 + a->y2) / 2), xm = (lv_coord_t)((a->x1 + a->x2) / 2);
    const lv_coord_t h = (lv_coord_t)(a->y2 - a->y1);
    switch (s->kind) {
    case SH_HEX_V:
        p[0] = (lv_point_t){ xm, a->y1 };
        p[1] = (lv_point_t){ a->x2, (lv_coord_t)(a->y1 + h * 22 / 100) };
        p[2] = (lv_point_t){ a->x2, (lv_coord_t)(a->y1 + h * 78 / 100) };
        p[3] = (lv_point_t){ xm, a->y2 };
        p[4] = (lv_point_t){ a->x1, (lv_coord_t)(a->y1 + h * 78 / 100) };
        p[5] = (lv_point_t){ a->x1, (lv_coord_t)(a->y1 + h * 22 / 100) };
        return 6;
    case SH_PENT:
        p[0] = (lv_point_t){ a->x1, a->y1 };
        p[1] = (lv_point_t){ (lv_coord_t)(a->x2 - c), a->y1 };
        p[2] = (lv_point_t){ a->x2, ym };
        p[3] = (lv_point_t){ (lv_coord_t)(a->x2 - c), a->y2 };
        p[4] = (lv_point_t){ a->x1, a->y2 };
        return 5;
    default:                                    // SH_HEX_H
        p[0] = (lv_point_t){ (lv_coord_t)(a->x1 + c), a->y1 };
        p[1] = (lv_point_t){ (lv_coord_t)(a->x2 - c), a->y1 };
        p[2] = (lv_point_t){ a->x2, ym };
        p[3] = (lv_point_t){ (lv_coord_t)(a->x2 - c), a->y2 };
        p[4] = (lv_point_t){ (lv_coord_t)(a->x1 + c), a->y2 };
        p[5] = (lv_point_t){ a->x1, ym };
        return 6;
    }
}

static void shape_edges(lv_draw_ctx_t *dc, const lv_point_t *p, int n, lv_color_t c, lv_coord_t w, lv_opa_t opa)
{
    lv_draw_line_dsc_t l;
    lv_draw_line_dsc_init(&l);
    l.color = c;
    l.width = w;
    l.opa = opa;
    l.round_start = l.round_end = 1;            // closed joins
    for (int i = 0; i < n; i++) lv_draw_line(dc, &l, &p[i], &p[(i + 1) % n]);
}

static void shape_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t *o = lv_event_get_target(e);
    const shape_t *s = lv_event_get_user_data(e);
    if (code == LV_EVENT_REFR_EXT_DRAW_SIZE) { lv_event_set_ext_draw_size(e, UI_SS(4)); return; }
    if (code != LV_EVENT_DRAW_MAIN) { lv_obj_invalidate(o); return; }   // pressed, released: repaint
    lv_draw_ctx_t *dc = lv_event_get_draw_ctx(e);
    lv_area_t a;
    lv_obj_get_coords(o, &a);
    lv_point_t p[6];
    int n = shape_points(s, &a, p);
    if (s->glow) shape_edges(dc, p, n, lv_color_hex(s->glow), (lv_coord_t)(s->edge_w + UI_SS(5)), 90);
    lv_color_t top = lv_color_hex(s->top), bot = lv_color_hex(s->bot);
    if (lv_obj_has_state(o, LV_STATE_PRESSED)) { top = lv_color_lighten(top, 50); bot = lv_color_lighten(bot, 30); }
    lv_draw_rect_dsc_t r;
    lv_draw_rect_dsc_init(&r);
    r.bg_color = top;
    r.bg_grad.dir = LV_GRAD_DIR_VER;
    r.bg_grad.stops_count = 2;
    r.bg_grad.stops[0].color = top;
    r.bg_grad.stops[0].frac = 0;
    r.bg_grad.stops[1].color = bot;
    r.bg_grad.stops[1].frac = 255;
    lv_draw_polygon(dc, &r, p, (uint16_t)n);
    lv_coord_t fw = s->fill ? lv_obj_get_width(s->fill) : 0;
    if (fw > 0) {                               // the hold fill: the shape again, clipped to its width
        lv_area_t f = { a.x1, a.y1, (lv_coord_t)(a.x1 + fw - 1), a.y2 }, clip;
        const lv_area_t *old = dc->clip_area;
        if (_lv_area_intersect(&clip, old, &f)) {
            lv_draw_rect_dsc_t fr;
            lv_draw_rect_dsc_init(&fr);
            fr.bg_color = lv_color_hex(s->fill_col);
            fr.bg_opa = 170;
            dc->clip_area = &clip;
            lv_draw_polygon(dc, &fr, p, (uint16_t)n);
            dc->clip_area = old;
        }
    }
    shape_edges(dc, p, n, lv_color_hex(s->edge), s->edge_w, LV_OPA_COVER);
}

// A shape at grid x, y, w, h (square ones pass sq: w and h through UI_SS).
static lv_obj_t *shape(lv_obj_t *p, uint8_t kind, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, bool sq,
                       lv_coord_t cut, uint32_t top, uint32_t bot, uint32_t edge, shape_t **out)
{
    lv_obj_t *o = sq ? area_px(p, UI_SX(x), UI_SY(y), UI_SS(w), UI_SS(h)) : area(p, x, y, w, h);
    shape_t *s = &s_shp[s_nshp < SHAPES - 1 ? s_nshp++ : SHAPES - 1];
    *s = (shape_t){ .kind = kind, .cut = UI_SS(cut), .edge_w = UI_SS(1), .top = top, .bot = bot, .edge = edge };
    lv_obj_add_event_cb(o, shape_cb, LV_EVENT_DRAW_MAIN, s);
    lv_obj_add_event_cb(o, shape_cb, LV_EVENT_REFR_EXT_DRAW_SIZE, s);
    lv_obj_refresh_ext_draw_size(o);
    if (out) *out = s;
    return o;
}

// A shape that is a button: pressed and released repaint it.
static void shape_clickable(lv_obj_t *o, shape_t *s, lv_event_cb_t cb, void *ud)
{
    lv_obj_add_flag(o, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(o, shape_cb, LV_EVENT_PRESSED, s);
    lv_obj_add_event_cb(o, shape_cb, LV_EVENT_RELEASED, s);
    lv_obj_add_event_cb(o, shape_cb, LV_EVENT_PRESS_LOST, s);
    if (cb) lv_obj_add_event_cb(o, cb, LV_EVENT_CLICKED, ud);
}

// ── Icons ─────────────────────────────────────────────────────────────────────
//
// Drawn in their object's box, on the preview's grids: the nav icons on 18
// units, the small marks (triangle, diamond, dot: events and radar blips) on
// 10. Lines 2 units wide (small marks 1.6).

enum { IC_TAC, IC_BAIT, IC_PERIM, IC_SYS, IC_CONT, IC_INFO, IC_TRI, IC_DIA, IC_DOT };
typedef struct { uint8_t kind; uint32_t col; } icon_t;
#define ICONS 16
EXT_RAM_BSS_ATTR static icon_t s_ic[ICONS];
EXT_RAM_BSS_ATTR static int    s_nic;

typedef struct { lv_draw_ctx_t *dc; lv_coord_t x, y; float k; lv_draw_line_dsc_t l; } pen_t;

static lv_point_t pt(const pen_t *p, float x, float y)
{
    return (lv_point_t){ (lv_coord_t)(p->x + x * p->k + 0.5f), (lv_coord_t)(p->y + y * p->k + 0.5f) };
}

static void seg_to(pen_t *p, float x0, float y0, float x1, float y1)
{
    lv_point_t a = pt(p, x0, y0), b = pt(p, x1, y1);
    lv_draw_line(p->dc, &p->l, &a, &b);
}

static void poly(pen_t *p, const float (*v)[2], int n, bool closed)
{
    for (int i = 0; i + 1 < n; i++) seg_to(p, v[i][0], v[i][1], v[i + 1][0], v[i + 1][1]);
    if (closed) seg_to(p, v[n - 1][0], v[n - 1][1], v[0][0], v[0][1]);
}

static void ring(pen_t *p, float cx, float cy, float r, uint16_t a0, uint16_t a1)
{
    lv_draw_arc_dsc_t d;
    lv_draw_arc_dsc_init(&d);
    d.color = p->l.color;
    d.width = p->l.width;
    lv_point_t c = pt(p, cx, cy);
    lv_draw_arc(p->dc, &d, &c, (uint16_t)(r * p->k + 0.5f), a0, a1);
}

static void dot(pen_t *p, float cx, float cy, float r)
{
    lv_draw_rect_dsc_t d;
    lv_draw_rect_dsc_init(&d);
    d.bg_color = p->l.color;
    d.radius = LV_RADIUS_CIRCLE;
    lv_point_t c = pt(p, cx, cy);
    lv_coord_t rr = (lv_coord_t)(r * p->k + 0.5f);
    lv_area_t a = { (lv_coord_t)(c.x - rr), (lv_coord_t)(c.y - rr), (lv_coord_t)(c.x + rr), (lv_coord_t)(c.y + rr) };
    lv_draw_rect(p->dc, &d, &a);
}

static void icon_cb(lv_event_t *e)
{
    const icon_t *ic = lv_event_get_user_data(e);
    lv_obj_t *o = lv_event_get_target(e);
    lv_area_t a;
    lv_obj_get_coords(o, &a);
    bool small = ic->kind >= IC_TRI;
    pen_t p = { .dc = lv_event_get_draw_ctx(e), .x = a.x1, .y = a.y1,
                .k = (float)lv_area_get_width(&a) / (small ? 10.0f : 18.0f) };
    lv_draw_line_dsc_init(&p.l);
    p.l.color = lv_color_hex(ic->col);
    p.l.width = (lv_coord_t)((small ? 1.6f : 2.0f) * p.k + 0.5f);
    if (p.l.width < 1) p.l.width = 1;
    p.l.round_start = p.l.round_end = 1;
    switch (ic->kind) {
    case IC_TAC:
        ring(&p, 9, 9, 6, 0, 360);
        seg_to(&p, 9, 1, 9, 5); seg_to(&p, 9, 13, 9, 17); seg_to(&p, 1, 9, 5, 9); seg_to(&p, 13, 9, 17, 9);
        break;
    case IC_BAIT: { static const float V[][2] = { { 3, 15 }, { 9, 3 }, { 15, 15 } }; poly(&p, V, 3, true); break; }
    case IC_PERIM: {
        static const float V[][2] = { { 9, 2 }, { 16, 5 }, { 16, 10 }, { 13.5f, 14.5f }, { 9, 17 }, { 4.5f, 14.5f },
                                      { 2, 10 }, { 2, 5 } };
        poly(&p, V, 8, true);
        break;
    }
    case IC_SYS:
        dot(&p, 9, 9, 3);
        for (int i = 0; i < 8; i++) ring(&p, 9, 9, 7, (uint16_t)(i * 45), (uint16_t)(i * 45 + 28));
        break;
    case IC_CONT: {
        static const float A[][2] = { { 1, 16 }, { 2.5f, 12.5f }, { 6, 11.5f }, { 9.5f, 12.5f }, { 11, 16 } };
        static const float B[][2] = { { 8, 16 }, { 9.5f, 12.5f }, { 13, 11.5f }, { 16.5f, 12.5f }, { 17, 16 } };
        dot(&p, 6, 6, 3); dot(&p, 13, 6, 3);
        poly(&p, A, 5, false); poly(&p, B, 5, false);
        break;
    }
    case IC_INFO:
        ring(&p, 9, 9, 7, 0, 360);
        seg_to(&p, 9, 8, 9, 13);
        dot(&p, 9, 5.2f, 1.2f);
        break;
    case IC_TRI: { static const float V[][2] = { { 5, 1 }, { 9, 9 }, { 1, 9 } }; poly(&p, V, 3, true); break; }
    case IC_DIA: { static const float V[][2] = { { 5, 1.5f }, { 8.5f, 5 }, { 5, 8.5f }, { 1.5f, 5 } }; poly(&p, V, 4, true); break; }
    default: ring(&p, 5, 5, 3.5f, 0, 360); break;
    }
}

// An icon object of box size sz (grid, kept square), at grid x, y; its
// colour lives in ic (repaint after a change).
static lv_obj_t *icon_obj(lv_obj_t *par, icon_t *ic, lv_coord_t x, lv_coord_t y, lv_coord_t sz)
{
    lv_obj_t *o = area_px(par, UI_SX(x), UI_SY(y), UI_SS(sz), UI_SS(sz));
    lv_obj_add_event_cb(o, icon_cb, LV_EVENT_DRAW_MAIN, ic);
    return o;
}

static icon_t *icon_new(uint8_t kind, uint32_t col)
{
    icon_t *ic = &s_ic[s_nic < ICONS - 1 ? s_nic++ : ICONS - 1];
    *ic = (icon_t){ kind, col };
    return ic;
}

static void icon_set(lv_obj_t *o, icon_t *ic, uint8_t kind, uint32_t col)
{
    if (ic->kind == kind && ic->col == col) return;
    ic->kind = kind;
    ic->col = col;
    lv_obj_invalidate(o);
}

// ── Header and nav ────────────────────────────────────────────────────────────

EXT_RAM_BSS_ATTR static shape_t *s_nav_shp[CP_N];
EXT_RAM_BSS_ATTR static icon_t  *s_nav_ic[CP_N];
EXT_RAM_BSS_ATTR static lv_obj_t *s_nav_ico[CP_N];
static void page_show(int p);

static void title_update(void)
{
    char b[24];
    strlcpy(b, settings_get()->panel_title, sizeof(b));
    if (!b[0]) strlcpy(b, "YAIM VIRD", sizeof(b));
    lcars_upper(b);
    if (!strcmp(b, s_title_txt)) return;
    strlcpy(s_title_txt, b, sizeof(s_title_txt));
    lv_coord_t ls;
    const lv_font_t *f = fit_font(b, F28, UI_SS(3), F20, UI_SS(2), UI_SW(110, 242), &ls);
    lv_obj_set_style_text_font(s_title, f, 0);
    lv_obj_set_style_text_letter_space(s_title, ls, 0);
    lv_label_set_text(s_title, b);
    lv_obj_align(s_title, LV_ALIGN_TOP_MID, 0, f == F28 ? UI_SY(1) : UI_SY(5));
}

static void sub_update(void)
{
    char b[40];
    if (s_cond == ALARM_COND_RED)         strlcpy(b, "SENTRY | RED ALERT", sizeof(b));
    else if (s_cond == ALARM_COND_YELLOW) strlcpy(b, "SENTRY | YELLOW ALERT", sizeof(b));
    else snprintf(b, sizeof(b), "SENTRY | %02d %s", s_cur + 1, NAV_TXT[s_cur]);
    set_text(s_sub, b);
}

static void pill_update(void)
{
    static const uint32_t FG[3] = { C_GREEN, C_AMBER, C_REDHI }, BG[3] = { 0x0d1a10, 0x241d0b, 0x240b0b },
                          ED[3] = { 0x1f5a2d, 0x7a5a10, C_RED2 };
    static const char *const TXT[3] = { "NOMINAL", "CAUTION", "HOSTILE" };
    int c = s_cond <= ALARM_COND_RED ? (int)s_cond : ALARM_COND_RED;
    lv_obj_set_style_bg_color(s_pill, lv_color_hex(BG[c]), 0);
    lv_obj_set_style_border_color(s_pill, lv_color_hex(ED[c]), 0);
    lv_obj_set_style_bg_color(s_pill_led, lv_color_hex(FG[c]), 0);
    lv_obj_set_style_shadow_color(s_pill_led, lv_color_hex(FG[c]), 0);
    lv_obj_set_style_text_color(s_pill_lbl, lv_color_hex(FG[c]), 0);
    set_text(s_pill_lbl, TXT[c]);
    for (int i = 0; i < 2; i++) {               // the glow strips take the condition's colour
        uint32_t g = c == ALARM_COND_YELLOW ? C_AMBER : C_GLOW;
        lv_obj_set_style_bg_color(s_glow[i], lv_color_hex(g), 0);
        lv_obj_set_style_shadow_color(s_glow[i], lv_color_hex(g), 0);
        lv_obj_set_style_opa(s_glow[i], LV_OPA_COVER, 0);
    }
}

static void nav_update(void)
{
    for (int i = 0; i < CP_N; i++) {
        bool on = i == s_cur;
        shape_t *s = s_nav_shp[i];
        uint32_t top = on ? C_REDSEL1 : C_BTN1;
        if (s->top != top) {
            s->top = top;
            s->bot = on ? C_REDSEL2 : C_BTN2;
            s->edge = on ? C_GLOW : C_EDGE;
            s->glow = on ? C_GLOW : 0;
            lv_obj_invalidate(s_nav_btn[i]);
        }
        icon_set(s_nav_ico[i], s_nav_ic[i], s_nav_ic[i]->kind, on ? C_HI : C_GOLD);
    }
    lv_obj_set_style_bg_color(s_auto_led, lv_color_hex(s_auto ? C_GREEN : C_SEGOFF), 0);
    lv_obj_set_style_shadow_opa(s_auto_led, s_auto ? LV_OPA_70 : LV_OPA_TRANSP, 0);
}

static void nav_cb(lv_event_t *ev)
{
    int i = (int)(uintptr_t)lv_event_get_user_data(ev);
    if (!s_green) return;
    s_auto = false;                             // a touch holds the page, as on LCARS
    page_show(i);
}

static void auto_cb(lv_event_t *ev)
{
    (void)ev;
    if (!s_green) return;
    s_auto = !s_auto;
    s_page_at = lv_tick_get();
    nav_update();
    ESP_LOGI(TAG, "AUTO %s", s_auto ? "on" : "off");
}

// The sigil: an original mark (a crowned arrowhead with a chevron), on the
// preview's 44 x 48 grid, gold on the red hexagon.
EXT_RAM_BSS_ATTR static lv_point_t s_sig_a[9], s_sig_b[3];

static void build_header(void)
{
    lv_obj_t *em = shape(s_root, SH_HEX_V, 4, 4, 64, 64, true, 0, 0xa4141a, 0x4a080a, C_EDGE, NULL);
    s_shp[s_nshp - 1].edge_w = UI_SS(2);
    static const int16_t A[9][2] = { { 22, 4 }, { 30, 14 }, { 38, 8 }, { 34, 26 }, { 22, 44 }, { 10, 26 },
                                     { 6, 8 }, { 14, 14 }, { 22, 4 } };
    static const int16_t B[3][2] = { { 15, 22 }, { 22, 30 }, { 29, 22 } };
    for (int i = 0; i < 9; i++) s_sig_a[i] = (lv_point_t){ UI_SS(A[i][0]), UI_SS(A[i][1]) };
    for (int i = 0; i < 3; i++) s_sig_b[i] = (lv_point_t){ UI_SS(B[i][0]), UI_SS(B[i][1]) };
    for (int k = 0; k < 2; k++) {
        lv_obj_t *l = lv_line_create(em);
        lv_line_set_points(l, k ? s_sig_b : s_sig_a, k ? 3 : 9);
        lv_obj_set_style_line_color(l, lv_color_hex(C_GOLD), 0);
        lv_obj_set_style_line_width(l, UI_SS(3), 0);
        lv_obj_set_style_line_rounded(l, true, 0);
        lv_obj_set_pos(l, UI_SS(10), UI_SS(8));
        lv_obj_clear_flag(l, LV_OBJ_FLAG_CLICKABLE);
    }

    lv_obj_t *bn = shape(s_root, SH_HEX_H, 96, 4, 270, 44, false, 14, C_RED2, 0x4a090b, 0xb51f24, NULL);
    s_title = lv_label_create(bn);
    lv_obj_set_style_text_color(s_title, lv_color_hex(C_GOLDT), 0);
    s_sub = lv_label_create(bn);
    lv_obj_set_style_text_font(s_sub, F12, 0);
    lv_obj_set_style_text_color(s_sub, lv_color_hex(C_GOLD), 0);
    lv_obj_set_style_text_letter_space(s_sub, UI_SS(2), 0);
    lv_label_set_text(s_sub, "SENTRY");
    lv_obj_align(s_sub, LV_ALIGN_TOP_MID, 0, UI_SY(29));
    title_update();

    lv_obj_t *st = plate(s_root, 374, 4, 102, 44, false, false);
    lv_obj_t *k = text(st, F12, C_DIM, 0, 0, 0, "STATUS");
    lv_obj_align(k, LV_ALIGN_TOP_MID, 0, UI_SY(3));
    s_pill = area(st, 5, 21, 90, 18);
    lv_obj_set_style_bg_opa(s_pill, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_pill, 1, 0);
    lv_obj_set_style_radius(s_pill, UI_SS(2), 0);
    s_pill_led = fill(s_pill, 5, 4, 12, 10, C_GREEN);
    lv_obj_set_style_shadow_width(s_pill_led, UI_SS(6), 0);
    lv_obj_set_style_shadow_opa(s_pill_led, LV_OPA_70, 0);
    s_pill_lbl = text(s_pill, F12, C_GREEN, 22, 0, 0, "NOMINAL");
    lv_obj_align(s_pill_lbl, LV_ALIGN_LEFT_MID, UI_SX(22), 0);

    for (int i = 0; i < 2; i++) {
        s_glow[i] = fill(s_root, i ? 300 : 120, 50, 60, 3, C_GLOW);
        lv_obj_set_style_radius(s_glow[i], UI_SS(1), 0);
        lv_obj_set_style_shadow_width(s_glow[i], UI_SS(8), 0);
        lv_obj_set_style_shadow_color(s_glow[i], lv_color_hex(C_GLOW), 0);
        lv_obj_set_style_shadow_opa(s_glow[i], LV_OPA_60, 0);
    }
}

static void build_nav(void)
{
    static const uint8_t IC[CP_N] = { IC_TAC, IC_BAIT, IC_PERIM, IC_SYS, IC_CONT, IC_INFO };
    s_nav = area(s_root, 0, 0, 480, 320);
    for (int i = 0; i < CP_N; i++) {
        lv_obj_t *b = s_nav_btn[i] = shape(s_nav, SH_PENT, NAV_X, (lv_coord_t)(NAV_Y + i * NAV_PITCH), NAV_W, NAV_H,
                                          false, 8, C_BTN1, C_BTN2, C_EDGE, &s_nav_shp[i]);
        shape_clickable(b, s_nav_shp[i], nav_cb, (void *)(uintptr_t)i);
        s_nav_ic[i] = icon_new(IC[i], C_GOLD);
        s_nav_ico[i] = icon_obj(b, s_nav_ic[i], 0, 0, 14);
        lv_obj_align(s_nav_ico[i], LV_ALIGN_LEFT_MID, UI_SX(4), 0);
        lv_obj_t *l = text(b, F12, C_TXT, 0, 0, 0, NAV_TXT[i]);
        lv_obj_align(l, LV_ALIGN_LEFT_MID, UI_SX(21), 0);       // to x 97, where the point starts at mid-height
    }
    shape_t *as;
    s_auto_btn = shape(s_nav, SH_PENT, NAV_X, AUTO_Y, NAV_W, NAV_H, false, 8, C_BTN1, C_BTN2, C_EDGE, &as);
    shape_clickable(s_auto_btn, as, auto_cb, NULL);
    s_auto_led = fill(s_auto_btn, 0, 0, 12, 10, C_GREEN);
    lv_obj_align(s_auto_led, LV_ALIGN_LEFT_MID, UI_SX(5), 0);
    lv_obj_set_style_shadow_width(s_auto_led, UI_SS(6), 0);
    lv_obj_set_style_shadow_color(s_auto_led, lv_color_hex(C_GREEN), 0);
    lv_obj_t *l = text(s_auto_btn, F12, C_TXT, 0, 0, 0, "AUTO");
    lv_obj_align(l, LV_ALIGN_LEFT_MID, UI_SX(21), 0);
}

// ── HOSTILE contacts ──────────────────────────────────────────────────────────
//
// Today's sources of SEV1 and SEV2 events (the ones that open RED and YELLOW),
// not ignored for that code: the radar's HOSTILE blips.

#define HOSTILE_MAX 16
typedef struct { uint32_t ip; uint8_t mac[6]; } contact_t;
EXT_RAM_BSS_ATTR static contact_t s_hos[HOSTILE_MAX];
EXT_RAM_BSS_ATTR static int       s_nhos;
EXT_RAM_BSS_ATTR static uint32_t  s_hos_day;
EXT_RAM_BSS_ATTR static uint32_t  s_admin[ROUTER_ADMIN_MAX];
EXT_RAM_BSS_ATTR static int       s_nadmin;

static uint32_t day_of(uint32_t ts)
{
    if (ts < 1600000000) return 0;
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    return (uint32_t)(tm.tm_year + 1900) * 1000u + (uint32_t)tm.tm_yday;
}

static bool mac_zero(const uint8_t *m) { return !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]); }

static bool is_hostile(uint32_t ip, const uint8_t *mac)
{
    for (int i = 0; i < s_nhos; i++) {
        if (ip && s_hos[i].ip == ip) return true;
        if (mac && !mac_zero(mac) && !memcmp(s_hos[i].mac, mac, 6)) return true;
    }
    return false;
}

static bool is_admin(uint32_t ip)
{
    for (int i = 0; i < s_nadmin; i++) if (ip && s_admin[i] == ip) return true;
    return false;
}

void clan_reset(void)
{
    s_nhos = 0;
    s_hos_day = 0;
}

void clan_event(const attack_log_t *e)
{
    uint32_t today = day_of((uint32_t)time(NULL));
    if (today != s_hos_day) { s_hos_day = today; s_nhos = 0; }
    if (!today || day_of(e->timestamp) != today) return;
    describe_tier_t t = describe_tier(e);
    if (t != TIER_SEV1 && t != TIER_SEV2) return;
    if (!e->src_ip && mac_zero(e->src_mac)) return;
    if (ignore_match(e->src_ip, e->src_mac, describe_code(e))) return;
    if (is_hostile(e->src_ip, e->src_mac) || s_nhos >= HOSTILE_MAX) return;
    s_hos[s_nhos].ip = e->src_ip;
    memcpy(s_hos[s_nhos].mac, e->src_mac, 6);
    s_nhos++;
}

// ── 01 TACTICAL ───────────────────────────────────────────────────────────────
//
// Page coordinates (the main area's):
//   x 0..223, y 0..185    the holo plate: "TACTICAL HOLOMAP", the radar at
//                         (8, 26), 140 px (kept round: UI_SS), the legend at x 154
//   x 230..367            SENSORS (y 0..57: ports watched, a strip of one
//                         cell per port in its group's colour, lit when hit
//                         today), SHIELDS (y 64..121: Pi-hole's blocked share
//                         over the six busiest devices, 12 red segments),
//                         POWER (y 128..185: free internal RAM, 12 gold
//                         segments, 100 KB full)
//   x 0..367, y 192..257  EVENTS / ALERTS: the last three
// The radar: two range rings, the sweep line (one lv_line from the centre,
// moved every SWEEP_MS; its old and new bounding boxes repaint), and a blip
// per LAN device (discovery's table, up to BLIPS) at an angle and radius
// from a hash of its MAC (else its IP): FRIENDLY (ROUTER_ADMIN_IPS) cyan
// triangles, NEUTRAL amber diamonds, HOSTILE red diamonds (today's
// contacts; also those not in the table). A blip brightens as the sweep
// passes it and fades over three steps.

#define RADAR_X     8
#define RADAR_Y     26
#define RADAR_D     140
#define BLIP_SZ     10
#define BLIPS       48
#define STRIP_MAX   40
#define SIDE_X      230
#define SIDE_W      138

enum { BK_FRIEND, BK_NEUTRAL, BK_HOSTILE };
static const uint32_t BLIP_COL[3] = { C_HOLO, C_AMBER, C_REDHI };
typedef struct {
    lv_obj_t *o;
    icon_t    ic;
    uint32_t  key;                              // FNV-1a of the MAC, else of the IP
    uint16_t  ang;                              // degrees, 0 up, clockwise
    uint8_t   kind, lit;
    bool      used, seen;
} blip_t;
EXT_RAM_BSS_ATTR static blip_t     s_blip[BLIPS];
EXT_RAM_BSS_ATTR static discovery_talker_t *s_dev;      // PSRAM, BLIPS
EXT_RAM_BSS_ATTR static lv_obj_t  *s_radar, *s_sweep, *s_leg[3];
EXT_RAM_BSS_ATTR static lv_point_t s_sw_pts[2];
EXT_RAM_BSS_ATTR static lv_coord_t s_rd_c, s_rd_r, s_blip_px;   // centre, sweep radius, blip box: screen px
static int       s_sw_i;
EXT_RAM_BSS_ATTR static lv_obj_t  *s_strip[STRIP_MAX], *s_sens_v, *s_shield_v, *s_power_v;
EXT_RAM_BSS_ATTR static bool       s_strip_hit[STRIP_MAX];
EXT_RAM_BSS_ATTR static int        s_nstrip;
EXT_RAM_BSS_ATTR static lv_obj_t  *s_seg[2][SEGS];
EXT_RAM_BSS_ATTR static int8_t     s_seg_n[2];
EXT_RAM_BSS_ATTR static lv_obj_t  *s_ev_ico[LCARS_LAST], *s_ev_l[LCARS_LAST];
EXT_RAM_BSS_ATTR static icon_t    *s_ev_ic[LCARS_LAST];

static uint32_t fnv(const uint8_t *b, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 16777619u; }
    return h;
}

static uint32_t strip_col(int i)
{
    uint8_t grp;
    bool hit;
    lcars_port(i, &grp, &hit);
    uint32_t c = grp == LCARS_GRP_TRAP ? C_RED : grp == LCARS_GRP_WIRE ? C_GOLD : C_HOLO;
    return hit ? c : lv_color_to32(lv_color_mix(lv_color_hex(c), lv_color_hex(C_PLATE2), 105)) & 0xffffff;
}

static void strip_rest(int i)
{
    lv_obj_set_style_bg_color(s_strip[i], lv_color_hex(strip_col(i)), 0);
}

static void seg_bar(lv_obj_t *p, int k, lv_coord_t y, uint32_t on)
{
    // 12 segments, 2 grid px apart, across the plate's inner width
    const lv_coord_t x0 = 7, w = SIDE_W - 14;
    for (int i = 0; i < SEGS; i++) {
        lv_coord_t a = (lv_coord_t)(x0 + w * i / SEGS), b = (lv_coord_t)(x0 + w * (i + 1) / SEGS - 2);
        lv_obj_t *s = s_seg[k][i] = fill(p, a, y, b - a, 10, C_SEGOFF);
        lv_obj_set_style_bg_grad_color(s, lv_color_hex(on == C_REDHI ? 0xa3161c : C_GOLDSEG), 0);
    }
    s_seg_n[k] = -1;
}

static void seg_set(int k, int n, uint32_t on)
{
    if (n < 0) n = 0;
    if (n > SEGS) n = SEGS;
    if (n == s_seg_n[k]) return;
    s_seg_n[k] = (int8_t)n;
    for (int i = 0; i < SEGS; i++) {
        lv_obj_set_style_bg_color(s_seg[k][i], lv_color_hex(i < n ? on : C_SEGOFF), 0);
        lv_obj_set_style_bg_grad_dir(s_seg[k][i], i < n ? LV_GRAD_DIR_VER : LV_GRAD_DIR_NONE, 0);
    }
}

// A side plate: name and value on the first line, a dim key under it.
static lv_obj_t *side_plate(lv_obj_t *pg, lv_coord_t y, const char *name, const char *key, uint32_t vcol,
                            lv_obj_t **val, bool ticks)
{
    lv_obj_t *p = plate(pg, SIDE_X, y, SIDE_W, 58, false, ticks);
    lv_obj_t *n = text(p, F12, C_TXT, 7, 6, 0, name);
    lv_obj_set_style_text_letter_space(n, UI_SS(1), 0);
    *val = text(p, F14, vcol, 76, 4, 54, "-");
    lv_obj_set_style_text_align(*val, LV_TEXT_ALIGN_RIGHT, 0);
    text(p, F12, C_DIM, 7, 21, 0, key);
    return p;
}

static void build_tac(lv_obj_t *pg)
{
    lv_obj_t *tp = plate(pg, 0, 0, 224, 186, true, true);
    lv_obj_t *h = text(tp, F12, C_TXT, 8, 7, 0, "TACTICAL HOLOMAP");
    lv_obj_set_style_text_letter_space(h, UI_SS(1), 0);

    const lv_coord_t D = UI_SS(RADAR_D);
    s_rd_c = D / 2;
    s_rd_r = D / 2 - UI_SS(3);
    s_blip_px = UI_SS(BLIP_SZ);
    s_radar = area_px(tp, UI_SX(RADAR_X), UI_SY(RADAR_Y), D, D);
    lv_obj_set_style_radius(s_radar, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_opa(s_radar, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(s_radar, lv_color_hex(0x0a2a38), 0);
    lv_obj_set_style_bg_grad_color(s_radar, lv_color_hex(0x03101a), 0);
    lv_obj_set_style_bg_grad_dir(s_radar, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_border_color(s_radar, lv_color_hex(C_HOLO_D), 0);
    lv_obj_set_style_border_width(s_radar, 1, 0);
    for (int k = 1; k <= 2; k++) {                          // range rings at a third and two thirds
        lv_coord_t d = (lv_coord_t)(D * k / 3);
        lv_obj_t *r = area_px(s_radar, (D - d) / 2, (D - d) / 2, d, d);
        lv_obj_set_style_radius(r, LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_border_color(r, lv_color_hex(C_HOLO), 0);
        lv_obj_set_style_border_opa(r, 70, 0);
        lv_obj_set_style_border_width(r, 1, 0);
    }
    for (int i = 0; i < BLIPS; i++) {
        blip_t *b = &s_blip[i];
        b->ic = (icon_t){ IC_DIA, C_AMBER };
        b->o = area_px(s_radar, 0, 0, s_blip_px, s_blip_px);
        lv_obj_add_event_cb(b->o, icon_cb, LV_EVENT_DRAW_MAIN, &b->ic);
        show(b->o, false);
    }
    s_sweep = lv_line_create(s_radar);
    lv_obj_clear_flag(s_sweep, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_line_color(s_sweep, lv_color_hex(C_HOLO), 0);
    lv_obj_set_style_line_width(s_sweep, UI_SS(2), 0);
    lv_obj_set_style_line_opa(s_sweep, 220, 0);
    lv_obj_set_style_line_rounded(s_sweep, true, 0);
    s_sw_pts[0] = (lv_point_t){ 0, s_rd_r };
    s_sw_pts[1] = (lv_point_t){ 0, 0 };
    lv_obj_set_pos(s_sweep, s_rd_c, s_rd_c - s_rd_r);
    lv_obj_set_size(s_sweep, 1, s_rd_r + 1);
    lv_line_set_points(s_sweep, s_sw_pts, 2);

    static const char *const LEG[3] = { "FRIENDLY", "NEUTRAL", "HOSTILE" };
    static const uint32_t LC[3] = { C_HOLO, C_AMBER, C_REDTXT };
    for (int i = 0; i < 3; i++) {
        text(tp, F12, LC[i], 156, (lv_coord_t)(30 + i * 34), 64, LEG[i]);
        s_leg[i] = text(tp, F14, LC[i], 156, (lv_coord_t)(45 + i * 34), 64, "0");
    }

    lv_obj_t *sp = side_plate(pg, 0, "SENSORS", "PORTS WATCHED", C_HOLO, &s_sens_v, true);
    s_nstrip = lcars_port_count() < STRIP_MAX ? lcars_port_count() : STRIP_MAX;
    if (s_nstrip > 0) {
        // One cell per port across the inner width, 1 px apart, in screen px
        // so they share it evenly.
        const lv_coord_t x0 = UI_SX(7), w = UI_SW(7, SIDE_W - 14), y = UI_SY(38), hh = UI_SH(38, 12);
        for (int i = 0; i < s_nstrip; i++) {
            lv_coord_t a = (lv_coord_t)(x0 + w * i / s_nstrip), b = (lv_coord_t)(x0 + w * (i + 1) / s_nstrip - 1);
            s_strip[i] = area_px(sp, a, y, b - a > 0 ? b - a : 1, hh);
            lv_obj_set_style_bg_opa(s_strip[i], LV_OPA_COVER, 0);
            strip_rest(i);
            s_strip_hit[i] = false;
        }
    }
    lv_obj_t *shp = side_plate(pg, 64, "SHIELDS", "PI-HOLE BLOCKED", C_REDTXT, &s_shield_v, false);
    seg_bar(shp, 0, 38, C_REDHI);
    lv_obj_t *pw = side_plate(pg, 128, "POWER", "FREE RAM", C_GOLD, &s_power_v, false);
    seg_bar(pw, 1, 38, C_GOLDHI);

    lv_obj_t *ev = plate(pg, 0, 192, 368, 66, false, true);
    lv_obj_t *eh = text(ev, F12, C_TXT, 8, 5, 0, "EVENTS / ALERTS");
    lv_obj_set_style_text_letter_space(eh, UI_SS(1), 0);
    for (int i = 0; i < LCARS_LAST; i++) {
        lv_coord_t y = (lv_coord_t)(20 + i * 14);
        s_ev_ic[i] = icon_new(IC_DOT, C_DIM);
        s_ev_ico[i] = icon_obj(ev, s_ev_ic[i], 8, (lv_coord_t)(y + 2), 10);
        s_ev_l[i] = text(ev, F12, C_TXT, 22, y, 340, "");
    }

    s_dev = heap_caps_calloc(BLIPS, sizeof(*s_dev), MALLOC_CAP_SPIRAM);
}

static void blip_place(blip_t *b)
{
    float a = (float)b->ang * (float)M_PI / 180.0f;
    float r = (float)s_rd_r * (0.22f + 0.66f * (float)((b->key >> 9) & 255) / 255.0f);
    lv_coord_t x = (lv_coord_t)(s_rd_c + r * sinf(a) - s_blip_px / 2.0f + 0.5f);
    lv_coord_t y = (lv_coord_t)(s_rd_c - r * cosf(a) - s_blip_px / 2.0f + 0.5f);
    lv_obj_set_pos(b->o, x, y);
}

// One contact on the radar, by key: its slot kept while it is listed.
static int blip_take(uint32_t key, uint8_t kind)
{
    int free = -1;
    for (int i = 0; i < BLIPS; i++) {
        blip_t *b = &s_blip[i];
        if (b->used && b->key == key) {
            b->seen = true;
            if (b->kind != kind) { b->kind = kind; icon_set(b->o, &b->ic, kind == BK_FRIEND ? IC_TRI : IC_DIA, BLIP_COL[kind]); }
            return i;
        }
        if (!b->used && free < 0) free = i;
    }
    if (free < 0) return -1;
    blip_t *b = &s_blip[free];
    b->used = b->seen = true;
    b->key = key;
    b->ang = (uint16_t)(key % 360u);
    b->kind = kind;
    b->lit = 0;
    b->ic = (icon_t){ kind == BK_FRIEND ? IC_TRI : IC_DIA, BLIP_COL[kind] };
    blip_place(b);
    show(b->o, true);
    lv_obj_invalidate(b->o);
    return free;
}

static void blips_refresh(void)
{
    if (!s_dev) return;
    int n = discovery_top_talkers(s_dev, BLIPS), cnt[3] = { 0 };
    for (int i = 0; i < BLIPS; i++) s_blip[i].seen = false;
    for (int i = 0; i < n; i++) {
        const discovery_talker_t *d = &s_dev[i];
        uint8_t kind = is_admin(d->ip) ? BK_FRIEND : is_hostile(d->ip, d->mac) ? BK_HOSTILE : BK_NEUTRAL;
        uint32_t key = !mac_zero(d->mac) ? fnv(d->mac, 6) : fnv((const uint8_t *)&d->ip, 4);
        blip_take(key, kind);
        cnt[kind]++;
    }
    for (int i = 0; i < s_nhos; i++) {          // hostile sources not in the device table
        bool listed = false;
        for (int k = 0; k < n && !listed; k++)
            listed = (s_hos[i].ip && s_dev[k].ip == s_hos[i].ip)
                  || (!mac_zero(s_hos[i].mac) && !memcmp(s_dev[k].mac, s_hos[i].mac, 6));
        if (listed) continue;
        uint32_t key = !mac_zero(s_hos[i].mac) ? fnv(s_hos[i].mac, 6) : fnv((const uint8_t *)&s_hos[i].ip, 4);
        blip_take(key, BK_HOSTILE);
        cnt[BK_HOSTILE]++;
    }
    for (int i = 0; i < BLIPS; i++)
        if (s_blip[i].used && !s_blip[i].seen) { s_blip[i].used = false; show(s_blip[i].o, false); }
    for (int k = 0; k < 3; k++) {
        char b[12];
        snprintf(b, sizeof(b), "%d", cnt[k]);
        set_text(s_leg[k], b);
    }
    // SHIELDS over the six busiest, as LCARS NET's BLOCKED gauge
    uint32_t tot = 0, blk = 0;
    for (int i = 0; i < n && i < 6; i++) {
        uint32_t t, k;
        if (lcars_pihole_share(s_dev[i].ip, s_dev[i].mac, &t, &k)) { tot += t; blk += k; }
    }
    char b[16];
    if (tot) snprintf(b, sizeof(b), "%lu %%", (unsigned long)(blk * 100 / tot)); else strlcpy(b, "-", sizeof(b));
    set_text(s_shield_v, b);
    seg_set(0, tot ? (int)((blk * SEGS + tot / 2) / tot) : 0, C_REDHI);
}

static void tac_refresh(bool force)
{
    (void)force;
    char b[64], ip[16], t[12];
    snprintf(b, sizeof(b), "%d", lcars_port_count());
    set_text(s_sens_v, b);
    for (int i = 0; i < s_nstrip; i++) {
        uint8_t grp;
        bool hit;
        lcars_port(i, &grp, &hit);
        if (hit == s_strip_hit[i] || lcars_fx_busy(s_strip[i])) continue;
        s_strip_hit[i] = hit;
        strip_rest(i);
    }
    uint32_t kb = (uint32_t)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024);
    snprintf(b, sizeof(b), "%lu KB", (unsigned long)kb);
    set_text(s_power_v, b);
    seg_set(1, (int)((kb * SEGS + POWER_FULL_KB / 2) / POWER_FULL_KB), C_GOLDHI);
    blips_refresh();

    const lcars_today_t *td = lcars_today();
    for (int i = 0; i < LCARS_LAST; i++) {
        if (i >= td->last_n) {
            set_text(s_ev_l[i], i ? "" : "NO EVENTS SINCE BOOT");
            show(s_ev_ico[i], false);
            continue;
        }
        const lcars_last_t *l = &td->last[i];
        int tier = describe_code_tier(l->code);
        if (l->ip) fmt_ip(l->ip, ip, sizeof(ip)); else strlcpy(ip, "NEARBY", sizeof(ip));
        fmt_hm(l->ts, t, sizeof(t));
        snprintf(b, sizeof(b), "%s %s | %s | %s", l->code, l->name, ip, t);
        lcars_fit(b, F12, UI_SX(340));
        set_text(s_ev_l[i], b);
        lv_obj_set_style_text_color(s_ev_l[i], lv_color_hex(tier == TIER_SEV1 ? C_HOTTXT : tier == TIER_SEV2 ? C_TXT : C_DIM), 0);
        icon_set(s_ev_ico[i], s_ev_ic[i], tier == TIER_SEV1 ? IC_TRI : tier == TIER_SEV2 ? IC_DIA : IC_DOT,
                 tier == TIER_SEV1 ? C_REDTXT : tier == TIER_SEV2 ? C_AMBER : C_DIM);
        show(s_ev_ico[i], true);
    }
}

// The sweep one step on, and the blips it passed brighten (then fade).
static void sweep_step(void)
{
    static const uint8_t LIT_MIX[4] = { 0, 60, 130, 200 };   // toward C_HI, by steps left
    int prev = s_sw_i;
    s_sw_i = (s_sw_i + 1) % SWEEP_STEPS;
    float a = 2.0f * (float)M_PI * (float)s_sw_i / SWEEP_STEPS;
    lv_coord_t c = s_rd_c;
    lv_coord_t ex = (lv_coord_t)(c + s_rd_r * sinf(a) + 0.5f), ey = (lv_coord_t)(c - s_rd_r * cosf(a) + 0.5f);
    lv_coord_t x0 = ex < c ? ex : c, y0 = ey < c ? ey : c;
    s_sw_pts[0] = (lv_point_t){ (lv_coord_t)(c - x0), (lv_coord_t)(c - y0) };
    s_sw_pts[1] = (lv_point_t){ (lv_coord_t)(ex - x0), (lv_coord_t)(ey - y0) };
    lv_obj_set_pos(s_sweep, x0, y0);
    lv_obj_set_size(s_sweep, (lv_coord_t)(LV_ABS(ex - c) + 1), (lv_coord_t)(LV_ABS(ey - c) + 1));
    lv_line_set_points(s_sweep, s_sw_pts, 2);

    uint16_t lo = (uint16_t)(prev * 360 / SWEEP_STEPS), hi = (uint16_t)(s_sw_i ? s_sw_i * 360 / SWEEP_STEPS : 360);
    for (int i = 0; i < BLIPS; i++) {
        blip_t *b = &s_blip[i];
        if (!b->used) continue;
        uint8_t lit = b->lit;
        uint16_t ang = b->ang ? b->ang : 360;
        if (ang > lo && ang <= hi) lit = 3;
        else if (lit) lit--;
        if (lit == b->lit && lit != 3) continue;
        b->lit = lit;
        lv_color_t col = lv_color_mix(lv_color_hex(C_HI), lv_color_hex(BLIP_COL[b->kind]), LIT_MIX[lit]);
        icon_set(b->o, &b->ic, b->ic.kind, lv_color_to32(col) & 0xffffff);
    }
}

// ── Motion: the items on the clan pages ───────────────────────────────────────

static lv_obj_t *fx_obj_cb(int it, uint8_t *part)
{
    *part = LCARS_FX_TEXT;
    switch (s_cur) {
    case CP_TAC:
        *part = LCARS_FX_BG;
        return it >= 0 && it < s_nstrip ? s_strip[it] : NULL;
    default:
        return NULL;
    }
}

static void fx_rest_cb(int it)
{
    switch (s_cur) {
    case CP_TAC: if (it >= 0 && it < s_nstrip) strip_rest(it); break;
    default: break;
    }
}

// ── Pages ─────────────────────────────────────────────────────────────────────

static void page_refresh(bool force)
{
    switch (s_cur) {
    case CP_TAC: tac_refresh(force); break;
    default: break;
    }
}

static void page_show(int p)
{
    if (p < 0 || p >= CP_N) p = CP_TAC;
    s_cur = p;
    s_page_at = s_data_at = lv_tick_get();
    for (int i = 0; i < CP_N; i++) show(s_page[i], i == p);
    nav_update();
    sub_update();
    lcars_fx_bind(&CLAN_FX, PG_SENSE[p]);
    page_refresh(true);
    EXT_RAM_BSS_ATTR static bool measured[CP_N];             // the first show of each page after boot
    static const char *const WHAT[CP_N] = {
        "CLAN TACTICAL, radar sweep and port strip", "CLAN BAIT, watch pass and row sweeps",
        "CLAN PERIMETER, watch pass and cell flashes", "CLAN SYSTEMS, label flashes",
        "CLAN CONTACTS, name glows", "CLAN INFO, static",
    };
    if (!measured[p]) {
        measured[p] = true;
        ui_refr_measure(WHAT[p]);
    }
}

static void fast_cb(lv_timer_t *t)
{
    (void)t;
    if (lv_obj_has_flag(s_root, LV_OBJ_FLAG_HIDDEN)) return;
    if (s_green) {
        if (s_cur == CP_TAC) sweep_step();
        return;
    }
    // An alert: the glow strips breathe, 1.4 s a cycle (the preview's banner pulse)
    uint32_t ph = lv_tick_get() % 1400;
    uint32_t v = ph < 700 ? ph : 1400 - ph;
    lv_opa_t o = (lv_opa_t)(110 + 145 * v / 700);
    for (int i = 0; i < 2; i++) lv_obj_set_style_opa(s_glow[i], o, 0);
}

static void slow_cb(lv_timer_t *t)
{
    (void)t;
    if (lv_obj_has_flag(s_root, LV_OBJ_FLAG_HIDDEN)) return;
    title_update();
    if (!s_green) return;
    if (s_auto && lv_tick_elaps(s_page_at) >= (uint32_t)settings_get()->panel_rotate_s * 1000u) {
        page_show(s_cur + 1 < CP_AUTO_N ? s_cur + 1 : 0);
        return;
    }
    if (lv_tick_elaps(s_data_at) >= DATA_MS) { s_data_at = lv_tick_get(); page_refresh(false); }
}

// ── Public ────────────────────────────────────────────────────────────────────

void clan_build(lv_obj_t *scr)
{
    s_nadmin = router_trip_parse_ips(ROUTER_ADMIN_IPS, s_admin, ROUTER_ADMIN_MAX);
    s_root = area_px(scr, 0, 0, BOARD_LCD_HRES, BOARD_LCD_VRES);
    lv_obj_set_style_bg_color(s_root, lv_color_hex(C_BG), 0);
    lv_obj_set_style_bg_opa(s_root, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_img_src(s_root, &ui_clan_tex, 0);
    lv_obj_set_style_bg_img_tiled(s_root, true, 0);
    build_header();
    build_nav();
    s_main = area(s_root, MAIN_X, MAIN_Y, MAIN_W, MAIN_H);
    for (int i = 0; i < CP_N; i++) {
        s_page[i] = area(s_main, 0, 0, MAIN_W, MAIN_H);
        show(s_page[i], false);
    }
    build_tac(s_page[CP_TAC]);
    s_alert_box = area(s_root, 4, MAIN_Y, 472, MAIN_H);
    show(s_alert_box, false);
    show(s_root, false);
    lv_timer_create(fast_cb, SWEEP_MS, NULL);
    lv_timer_create(slow_cb, 1000, NULL);
    ESP_LOGI(TAG, "Built: %d ports, %d blips at most, %d admin address%s, texture %ux%u",
             lcars_port_count(), BLIPS, s_nadmin, s_nadmin == 1 ? "" : "es",
             (unsigned)ui_clan_tex.header.w, (unsigned)ui_clan_tex.header.h);
}

void clan_view(alarm_cond_t c, bool on)
{
    if (!on) {
        if (lcars_fx_skin() == &CLAN_FX) lcars_fx_bind(NULL, LCARS_PG_NONE);
        s_green = false;
        show(s_root, false);
        return;
    }
    s_cond = c;
    show(s_root, true);
    pill_update();
    bool green = c == ALARM_COND_GREEN;
    show(s_nav, green);
    show(s_main, green);
    show(s_alert_box, !green);
    if (green) {
        if (!s_green) { s_green = true; page_show(s_cur); }
        else sub_update();
        return;
    }
    s_green = false;
    lcars_fx_bind(&CLAN_FX, LCARS_PG_NONE);     // nothing moves under the alert but the glow strips
    sub_update();
}

void clan_style_msgbox(lv_obj_t *mb)
{
    lv_obj_set_style_bg_color(mb, lv_color_hex(C_PLATE1), 0);
    lv_obj_set_style_bg_grad_color(mb, lv_color_hex(C_PLATE2), 0);
    lv_obj_set_style_bg_grad_dir(mb, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_opa(mb, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(mb, lv_color_hex(C_RED), 0);
    lv_obj_set_style_border_width(mb, UI_SS(2), 0);
    lv_obj_set_style_radius(mb, UI_SS(4), 0);
    lv_obj_set_style_shadow_width(mb, 0, 0);
    lv_obj_set_style_text_color(mb, lv_color_hex(C_TXT), 0);
    lv_obj_set_style_text_font(mb, F14, 0);
    lv_obj_t *t = lv_msgbox_get_title(mb);
    if (t) lv_obj_set_style_text_color(t, lv_color_hex(C_GOLD), 0);
    lv_obj_t *x = lv_msgbox_get_close_btn(mb);
    if (x) {
        lv_obj_set_style_bg_color(x, lv_color_hex(C_RED), 0);
        lv_obj_set_style_text_color(x, lv_color_hex(C_TXT), 0);
    }
    lv_obj_t *b = lv_msgbox_get_btns(mb);
    if (b) {
        lv_obj_set_style_bg_color(b, lv_color_hex(C_BTN1), LV_PART_ITEMS);
        lv_obj_set_style_bg_grad_color(b, lv_color_hex(C_BTN2), LV_PART_ITEMS);
        lv_obj_set_style_bg_grad_dir(b, LV_GRAD_DIR_VER, LV_PART_ITEMS);
        lv_obj_set_style_bg_opa(b, LV_OPA_COVER, LV_PART_ITEMS);
        lv_obj_set_style_border_color(b, lv_color_hex(C_EDGE), LV_PART_ITEMS);
        lv_obj_set_style_border_width(b, 1, LV_PART_ITEMS);
        lv_obj_set_style_text_color(b, lv_color_hex(C_TXT), LV_PART_ITEMS);
        lv_obj_set_style_radius(b, UI_SS(3), LV_PART_ITEMS);
        lv_obj_set_style_shadow_width(b, 0, LV_PART_ITEMS);
        lv_obj_set_style_bg_color(b, lv_color_hex(C_REDSEL1), LV_PART_ITEMS | LV_STATE_PRESSED);
    }
}
