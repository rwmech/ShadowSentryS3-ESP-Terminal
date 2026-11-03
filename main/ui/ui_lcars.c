#include "ui_lcars.h"
#include "ui_subsys.h"
#include "ui_logo.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "describe.h"
#include "discovery.h"
#include "sd_log.h"
#include "settings.h"
#include "tripwire.h"           // with http_engine.h and trap_listen.h: the port config
#include "router_trip.h"
#include "pihole.h"
#include "mikrotik.h"
#include "mikrotik_watch.h"
#include "mt_decoy.h"
#include "correlate.h"
#include "router_flow.h"
#include "cam.h"
#include "discord.h"
#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "blocklist.h"
#include "lwip/ip4_addr.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

static const char *TAG = "LCARS";

// ── Palette ───────────────────────────────────────────────────────────────────
//
// Cerritos, after thelcars.com's Lower Decks colour guide. No white and no
// reverse video: text is black on the frame colours, else c5 or c2 on black.
// Lifted 2026-11-03 for legibility (Rob: "the dark ones are too hard to
// read"): every text tone is at least 6:1 on black (dim #cc9966 8.3:1, was
// #8a5a2b at 3.6:1), black on c3 6:1 (was 4.9:1).

const lcars_palette_t LCARS_CERRITOS = {
    .c1 = 0xff7700, .c2 = 0xffcc99, .c3 = 0xdd6622, .c4 = 0xffaa44, .c5 = 0xffeecc, .c6 = 0xff9911,
    .txt = 0xffeecc, .dim = 0xcc9966, .track = 0x553719, .accent = 0xff5522,
    .hi = 0xfff3dd, .red = 0xe00000, .yellow = 0xf0b000,
};

#define F12 (&lv_font_montserrat_12)
#define F14 (&lv_font_montserrat_14)
#define F20 (&lv_font_montserrat_20)
#define F28 (&lv_font_montserrat_28)
#define COL_BLACK lv_color_black()
#define DIM_OPA   185                   // 73 %: a port not hit today (was 45 %)

// Layout (screen coordinates; the pages use content coordinates)
//   frame       top elbow 70 x 32 (radius 24, inner black 18 x 22, radius 8)
//               and bar segments y 0..9, the title right-aligned (14 px);
//               bottom elbow 70 x 34 (the 07 SUBSYS button) and segments y 310..319, the clock
//               right-aligned at y 304 (12 px)
//   rail        x 0..51, six buttons 52 x 38 from y 36, 3 px apart
//   content     x 76..475, y 20..301
#define RAIL_Y      36
#define RAIL_H      38
#define RAIL_PITCH  41
#define RAIL_W      52
#define MARK_H      2                   // the selection mark: the box's own bottom 2 px
#define PAGES       5
#define SCAN_MS     33                  // the chart's scan line: one step
#define SCAN_STEP   3
#define FOCUS_MS    5000
#define DATA_MS     2000                // the shown page's figures
#define STATS_MS    60000               // sd_log_stats() for the chart and total

enum { PG_OPS, PG_TRAPS, PG_WIRES, PG_NET, PG_DEV };
static const char *const PAGE_TITLE[PAGES] = { "OPS", "TRAPS", "TRIPWIRES", "NET", "DEVICES" };
static const char *const RAIL_TXT[6] = { "01\nOPS", "02\nTRAPS", "03\nWIRES", "04\nNET", "05\nDEV", "06\nAUTO" };

EXT_RAM_BSS_ATTR static lv_obj_t *s_root, *s_rail, *s_title, *s_clock, *s_content, *s_alert;
EXT_RAM_BSS_ATTR static lv_obj_t *s_frame;              // elbows, bars, title, rail, clock
EXT_RAM_BSS_ATTR static bool      s_splash;             // the boot splash is running
EXT_RAM_BSS_ATTR static lv_obj_t *s_page[PAGES];
EXT_RAM_BSS_ATTR static lv_obj_t *s_rail_mark[6];
static int       s_cur = PG_OPS;
static bool      s_auto = true;
EXT_RAM_BSS_ATTR static bool      s_green;               // the pages are shown (GREEN, LCARS style)
// The strip says "SECURED FROM RED/YELLOW ALERT" for SECURED_MS after an incident
// closes, then "ALL SYSTEMS NORMAL" (TNG wording; "condition green" is the TOS
// duress code, "Bread and Circuses"). Rob, 2026-11-03.
#define SECURED_MS        60000
EXT_RAM_BSS_ATTR static alarm_cond_t s_prev_cond;         // the last condition lcars_view() was given
EXT_RAM_BSS_ATTR static alarm_cond_t s_secured_cond;      // RED or YELLOW while the secured line shows
EXT_RAM_BSS_ATTR static uint32_t     s_secured_at;
EXT_RAM_BSS_ATTR static uint32_t  s_page_at;             // tick of the last page change, for AUTO

// ── Today's figures (UI task) ─────────────────────────────────────────────────

#define LC_PORTS_MAX 40
#define LC_TRAPS     8
#define LC_WIRES     18
#define LC_LAST      3
enum { GRP_TRAP, GRP_WIRE, GRP_NET };

typedef struct { uint16_t port; uint8_t grp; bool hit, lit; lv_obj_t *l; } lc_port_t;   // lit: as drawn
typedef struct { char name[24]; uint32_t n, ts, ip; char what[64]; } lc_hit_t;
typedef struct { char code[DESCRIBE_CODE_LEN]; char name[24]; uint32_t ip, ts; } lc_last_t;

EXT_RAM_BSS_ATTR static struct {
    uint32_t  day;                      // local YYYY*1000+yday, 0 = clock not set
    uint32_t  alerts, probes, scans, new_dev;
    lc_hit_t  trap[LC_TRAPS];
    lc_hit_t  wire[LC_WIRES];
    lc_last_t last[LC_LAST];            // newest first
    int       last_n;
} s_t;

EXT_RAM_BSS_ATTR static lc_port_t s_ports[LC_PORTS_MAX];
EXT_RAM_BSS_ATTR static int s_nports;
EXT_RAM_BSS_ATTR static bool s_port_ev[LC_PORTS_MAX];    // an event named the port since the last sense

static bool s_chart_dirty = true;
static bool fx_busy(lv_obj_t *o);      // Motion: o is being flashed
static void fx_stop_all(void);
static uint32_t rnd(uint32_t lo, uint32_t hi);

static lv_color_t grp_col(uint8_t g)
{
    // NET in honey c2, not butter c5: dimmed to 73 % butter read as grey (Rob, 2026-11-03).
    return lv_color_hex(g == GRP_TRAP ? LCARS_PAL->c6 : g == GRP_WIRE ? LCARS_PAL->c4 : LCARS_PAL->c2);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

void lcars_upper(char *s)
{
    for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s = (char)(*s - 'a' + 'A');
}

static uint32_t local_day(uint32_t ts)
{
    if (ts < 1600000000) return 0;
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    return (uint32_t)(tm.tm_year + 1900) * 1000u + (uint32_t)tm.tm_yday;
}

static void fmt_ip(uint32_t ip_net, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip_net };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

// "3:39 PM" or "15:39": the status bar's format, no seconds.
static void fmt_hm(uint32_t ts, char *buf, size_t len)
{
    ui_fmt_time(ts, false, buf, len);
    if (settings_get()->clock_24h && strlen(buf) == 8) buf[5] = '\0';
}

// Shorten s for w pixels in font f, ending "...": at a word, unless that
// drops more than half of what fits, else mid-word. In place: the dots go
// where at least 3 characters were.
static void fit(char *s, const lv_font_t *f, lv_coord_t w)
{
    uint32_t n = (uint32_t)strlen(s);
    if (n < 4 || lv_txt_get_width(s, n, f, 0, LV_TEXT_FLAG_NONE) <= w) return;
    lv_coord_t dots = lv_txt_get_width("...", 3, f, 0, LV_TEXT_FLAG_NONE);
    uint32_t k = n - 3;
    while (k > 0 && lv_txt_get_width(s, k, f, 0, LV_TEXT_FLAG_NONE) + dots > w) k--;
    uint32_t j = k;
    while (j > 0 && s[j] != ' ') j--;
    if (j > k / 2) k = j;
    while (k > 0 && s[k - 1] == ' ') k--;
    memcpy(s + k, "...", 4);
}

// The label's text, only if it differs: an unchanged label is not repainted.
static void set_text(lv_obj_t *l, const char *t)
{
    const char *o = lv_label_get_text(l);
    if (!o || strcmp(o, t)) lv_label_set_text(l, t);
}

static void show(lv_obj_t *o, bool on)
{
    if (on) lv_obj_clear_flag(o, LV_OBJ_FLAG_HIDDEN);
    else    lv_obj_add_flag(o, LV_OBJ_FLAG_HIDDEN);
}

// A transparent area: no style, scrolling or touch.
static lv_obj_t *area(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h)
{
    lv_obj_t *o = lv_obj_create(p);
    lv_obj_remove_style_all(o);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    return o;
}

static lv_obj_t *fill(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, lv_color_t c)
{
    lv_obj_t *o = area(p, x, y, w, h);
    lv_obj_set_style_bg_color(o, c, 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    return o;
}

static lv_obj_t *text(lv_obj_t *p, const lv_font_t *f, lv_color_t c, lv_coord_t x, lv_coord_t y,
                      lv_coord_t w, const char *t)
{
    lv_obj_t *l = lv_label_create(p);
    lv_obj_set_style_text_font(l, f, 0);
    lv_obj_set_style_text_color(l, c, 0);
    lv_label_set_text(l, t ? t : "");
    if (w > 0) {
        lv_label_set_long_mode(l, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(l, w);
    }
    lv_obj_set_pos(l, x, y);
    return l;
}

// One rounded corner only (LVGL rounds all four): a circle of radius r in the
// corner and two boxes, clipped by the area. TL top-left, else bottom-left.
static lv_obj_t *corner(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h,
                        lv_coord_t r, lv_color_t c, bool tl)
{
    lv_obj_t *a = area(p, x, y, w, h);
    lv_obj_t *d = fill(a, 0, tl ? 0 : h - 2 * r, 2 * r, 2 * r, c);
    lv_obj_set_style_radius(d, LV_RADIUS_CIRCLE, 0);
    fill(a, r, 0, w - r, h, c);
    fill(a, 0, tl ? r : 0, r, h - r, c);
    return a;
}

// A bar segment with a rounded right end (radius h / 2).
static lv_obj_t *seg(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, lv_color_t c, bool cap)
{
    if (!cap) return fill(p, x, y, w, h, c);
    lv_obj_t *a = area(p, x, y, w, h);
    lv_obj_t *d = fill(a, w - h, 0, h, h, c);
    lv_obj_set_style_radius(d, LV_RADIUS_CIRCLE, 0);
    fill(a, 0, 0, w - h / 2, h, c);
    return a;
}

// The selection mark: the bottom MARK_H px of a box of width w, height h.
static lv_obj_t *mark(lv_obj_t *box, lv_coord_t w, lv_coord_t h)
{
    lv_obj_t *m = fill(box, 0, h - MARK_H, w, MARK_H, LCARS_COL(hi));
    show(m, false);
    return m;
}

// A pill with dark 12 px text, as wide as the text plus 12 px.
static lv_obj_t *pill(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_color_t c, const char *t)
{
    lv_coord_t w = lv_txt_get_width(t, (uint32_t)strlen(t), F12, 0, LV_TEXT_FLAG_NONE) + 12;
    lv_obj_t *o = fill(p, x, y, w, 14, c);
    lv_obj_set_style_radius(o, 7, 0);
    lv_obj_t *l = text(o, F12, COL_BLACK, 0, 0, 0, t);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
    return o;
}

void lcars_style_msgbox(lv_obj_t *mb)
{
    lv_obj_set_style_bg_color(mb, COL_BLACK, 0);
    lv_obj_set_style_bg_opa(mb, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(mb, LCARS_COL(c4), 0);
    lv_obj_set_style_border_width(mb, 3, 0);
    lv_obj_set_style_radius(mb, 14, 0);
    lv_obj_set_style_shadow_width(mb, 0, 0);
    lv_obj_set_style_text_color(mb, LCARS_COL(c2), 0);
    lv_obj_set_style_text_font(mb, F14, 0);
    lv_obj_t *t = lv_msgbox_get_title(mb);
    if (t) lv_obj_set_style_text_color(t, LCARS_COL(c4), 0);
    lv_obj_t *x = lv_msgbox_get_close_btn(mb);
    if (x) {
        lv_obj_set_style_bg_color(x, LCARS_COL(c4), 0);
        lv_obj_set_style_text_color(x, COL_BLACK, 0);
    }
    lv_obj_t *b = lv_msgbox_get_btns(mb);
    if (b) {
        lv_obj_set_style_bg_color(b, LCARS_COL(c4), LV_PART_ITEMS);
        lv_obj_set_style_bg_opa(b, LV_OPA_COVER, LV_PART_ITEMS);
        lv_obj_set_style_text_color(b, COL_BLACK, LV_PART_ITEMS);
        lv_obj_set_style_radius(b, 17, LV_PART_ITEMS);
        lv_obj_set_style_shadow_width(b, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_width(b, 0, LV_PART_ITEMS);
        lv_obj_set_style_bg_color(b, LCARS_COL(accent), LV_PART_ITEMS | LV_STATE_PRESSED);
    }
}

// ── Ports ─────────────────────────────────────────────────────────────────────
//
// What the board listens on, from the port settings: the traps (TRAPS page
// colour), the tripwires and MikroTik decoys (WIRES), the discovery listeners
// and the router syslog and IPFIX copies (NET). A port set to 0 is left out.

static void ports_add(const uint16_t *p, int n, uint8_t grp)
{
    uint16_t v[24];
    int k = 0;
    for (int i = 0; i < n && k < (int)(sizeof(v) / sizeof(v[0])); i++) {
        if (!p[i]) continue;
        int at = k;
        while (at > 0 && v[at - 1] > p[i]) at--;
        if (at > 0 && v[at - 1] == p[i]) continue;      // listed twice
        memmove(&v[at + 1], &v[at], sizeof(v[0]) * (size_t)(k - at));
        v[at] = p[i];
        k++;
    }
    for (int i = 0; i < k && s_nports < LC_PORTS_MAX; i++)
        s_ports[s_nports++] = (lc_port_t){ .port = v[i], .grp = grp };
}

static void ports_init(void)
{
    static const uint16_t TRAP[] = {
        RTSP_PORT, HTTP_PORT, TELNET_PORT, SSH_PORT, FTP_PORT, TELNET_ALT_PORT, SSH_ALT_PORT, ADB_PORT,
#if HTTP_ENGINE_ENABLE
        HTTP_ALT_PORT1, HTTP_ALT_PORT2, HTTP_ALT_PORT3,
#endif
    };
    static const uint16_t WIRE[] = {
#if TRIPWIRE_ENABLE
        TRIPWIRE_RDP_PORT, TRIPWIRE_VNC_PORT, TRIPWIRE_SMB_PORT, TRIPWIRE_REDIS_PORT,
        TRIPWIRE_MYSQL_PORT, TRIPWIRE_MSSQL_PORT, TRIPWIRE_JETDIRECT_PORT, TRIPWIRE_WINBOX_PORT,
        TRIPWIRE_ROSAPI_PORT, TRIPWIRE_BTEST_PORT, TRIPWIRE_MNDP_PORT, TRIPWIRE_MACTELNET_PORT,
#else
        0,
#endif
    };
    uint16_t net[20];
    int n = discovery_ports(net, 16);
    net[n++] = ROUTER_SYSLOG_PORT;
    net[n++] = ROUTER_IPFIX_PORT;
    s_nports = 0;
    ports_add(TRAP, (int)(sizeof(TRAP) / sizeof(TRAP[0])), GRP_TRAP);
    ports_add(WIRE, (int)(sizeof(WIRE) / sizeof(WIRE[0])), GRP_WIRE);
    ports_add(net, n, GRP_NET);
}

// The digits right after key in s, as a port; 0 if none.
static uint16_t num_after(const char *s, const char *key)
{
    const char *p = strstr(s, key);
    if (!p) return 0;
    p += strlen(key);
    uint32_t v = 0;
    int d = 0;
    while (*p >= '0' && *p <= '9' && d < 5) { v = v * 10 + (uint32_t)(*p - '0'); p++; d++; }
    return d && v <= 65535 ? (uint16_t)v : 0;
}

// The port an event names: " on N" (HTTP engine, tripwires, decoys), "port N"
// (probes, the alternate Telnet and SSH ports), else the trap's own port.
static uint16_t ev_port(const attack_log_t *e)
{
    char pl[sizeof(e->payload) + 1];
    size_t n = strnlen(e->payload, sizeof(e->payload));
    memcpy(pl, e->payload, n);
    pl[n] = '\0';
    uint16_t p = num_after(pl, " on ");
    if (!p) p = num_after(pl, "port ");
    if (p) return p;
    switch (e->type) {
    case ATTACK_RTSP:   return RTSP_PORT;
    case ATTACK_HTTP:   return HTTP_PORT;
    case ATTACK_TELNET:
    case ATTACK_SHELL:  return TELNET_PORT;
    case ATTACK_SSH:    return SSH_PORT;
    case ATTACK_FTP:    return FTP_PORT;
    case ATTACK_ADB:    return ADB_PORT;
    default:            return 0;
    }
}

// ── Traps and tripwires ───────────────────────────────────────────────────────
//
// TRAPS: the services that pretend (code families 20 and 30, ADB). WIRES: the
// LAN tripwires, the MikroTik decoys and the router's own tripwires (40, 55,
// 60-02), by the event's code.

enum { TR_WEB, TR_WEB_ALT, TR_RTSP, TR_TELNET, TR_SHELL, TR_SSH, TR_FTP, TR_ADB };

static const char *const WIRE_CODE[LC_WIRES] = {
    "40-02", "40-03", "40-04", "40-05", "40-06", "40-07", "40-08",       // LAN tripwires
    "40-10", "40-11", "40-12", "40-13", "40-14",                         // MikroTik decoys
    "55-21", "55-25", "55-24", "55-26", "60-02", "55-0",                 // router; "55-0" a prefix
};
enum { WI_LAN0 = 0, WI_DECOY0 = 7, WI_ROUTER0 = 12, WI_NEWDEV = 16, WI_CONFIG = 17 };

static const uint16_t WIRE_PORT[WI_ROUTER0] = {
    TRIPWIRE_RDP_PORT, TRIPWIRE_VNC_PORT, TRIPWIRE_SMB_PORT, TRIPWIRE_REDIS_PORT,
    TRIPWIRE_MYSQL_PORT, TRIPWIRE_MSSQL_PORT, TRIPWIRE_JETDIRECT_PORT, TRIPWIRE_WINBOX_PORT,
    TRIPWIRE_ROSAPI_PORT, TRIPWIRE_BTEST_PORT, TRIPWIRE_MNDP_PORT, TRIPWIRE_MACTELNET_PORT,
};

static void names_init(void)
{
    static const char *const NM[LC_WIRES] = {
        "RDP", "VNC", "SMB", "REDIS", "MYSQL", "MSSQL", "JETDIRECT", "WINBOX", "ROUTEROS API",
        "BTEST", "MNDP", "MAC-TELNET", "ROUTER LOGIN FAIL", "ROUTER MGMT PORT", "ROUTER PORT SCAN",
        "DNS BYPASS", "NEW DEVICE", "ROUTER CONFIG",
    };
    for (int i = 0; i < LC_WIRES; i++) {
        if (i < WI_ROUTER0) snprintf(s_t.wire[i].name, sizeof(s_t.wire[i].name), "%s %u", NM[i], (unsigned)WIRE_PORT[i]);
        else                strlcpy(s_t.wire[i].name, NM[i], sizeof(s_t.wire[i].name));
    }
    int alt = 0;
    uint16_t alt1 = 0;
#if HTTP_ENGINE_ENABLE
    const uint16_t A[3] = { HTTP_ALT_PORT1, HTTP_ALT_PORT2, HTTP_ALT_PORT3 };
    for (int i = 0; i < 3; i++) if (A[i]) { if (!alt1) alt1 = A[i]; alt++; }
#endif
    snprintf(s_t.trap[TR_WEB].name, sizeof(s_t.trap[0].name), "HIKVISION %u", (unsigned)HTTP_PORT);
    if (alt > 1) snprintf(s_t.trap[TR_WEB_ALT].name, sizeof(s_t.trap[0].name), "WEB %u +%d", (unsigned)alt1, alt - 1);
    else if (alt) snprintf(s_t.trap[TR_WEB_ALT].name, sizeof(s_t.trap[0].name), "WEB %u", (unsigned)alt1);
    else strlcpy(s_t.trap[TR_WEB_ALT].name, "WEB ALT OFF", sizeof(s_t.trap[0].name));
    snprintf(s_t.trap[TR_RTSP].name, sizeof(s_t.trap[0].name), "CAMERA RTSP %u", (unsigned)RTSP_PORT);
    snprintf(s_t.trap[TR_TELNET].name, sizeof(s_t.trap[0].name), "TELNET %u %u", (unsigned)TELNET_PORT, (unsigned)TELNET_ALT_PORT);
    strlcpy(s_t.trap[TR_SHELL].name, "SHELL SESSIONS", sizeof(s_t.trap[0].name));
    snprintf(s_t.trap[TR_SSH].name, sizeof(s_t.trap[0].name), "SSH %u %u", (unsigned)SSH_PORT, (unsigned)SSH_ALT_PORT);
    snprintf(s_t.trap[TR_FTP].name, sizeof(s_t.trap[0].name), "FTP %u", (unsigned)FTP_PORT);
    snprintf(s_t.trap[TR_ADB].name, sizeof(s_t.trap[0].name), "ADB %u", (unsigned)ADB_PORT);
}

static int trap_index(const attack_log_t *e, uint16_t port)
{
    switch (e->type) {
    case ATTACK_HTTP:   return port == HTTP_PORT ? TR_WEB : TR_WEB_ALT;
    case ATTACK_RTSP:   return TR_RTSP;
    case ATTACK_TELNET: return TR_TELNET;
    case ATTACK_SHELL:  return TR_SHELL;
    case ATTACK_SSH:    return TR_SSH;
    case ATTACK_FTP:    return TR_FTP;
    case ATTACK_ADB:    return TR_ADB;
    default:            return -1;
    }
}

static int wire_index(const char *code)
{
    for (int i = 0; i < WI_CONFIG; i++) if (!strcmp(code, WIRE_CODE[i])) return i;
    if (!strncmp(code, "55-0", 4) || !strcmp(code, "55-10") || !strcmp(code, "55-11") || !strcmp(code, "55-23"))
        return WI_CONFIG;
    return -1;
}

static void hit_note(lc_hit_t *h, const attack_log_t *e)
{
    char d[DESCRIBE_MAX], ip[16];
    describe_event(e, d, sizeof(d));
    const char *bar = strstr(d, " | ");
    const char *what = bar ? bar + 3 : d;
    h->n++;
    h->ts = e->timestamp;
    h->ip = e->src_ip;
    h->what[0] = '\0';
    if (e->src_ip) {
        fmt_ip(e->src_ip, ip, sizeof(ip));
        strlcpy(h->what, ip, sizeof(h->what));
        strlcat(h->what, " | ", sizeof(h->what));
    }
    strlcat(h->what, what, sizeof(h->what));
    lcars_upper(h->what);
}

static void day_roll(void)
{
    uint32_t today = local_day((uint32_t)time(NULL));
    if (today == s_t.day) return;
    s_t.day = today;
    s_t.alerts = s_t.probes = s_t.scans = s_t.new_dev = 0;
    for (int i = 0; i < LC_TRAPS; i++) s_t.trap[i].n = 0;
    for (int i = 0; i < LC_WIRES; i++) s_t.wire[i].n = 0;
    for (int i = 0; i < s_nports; i++) s_ports[i].hit = false;
}

void lcars_reset(void)
{
    s_t.day = 0;
    s_t.last_n = 0;
    day_roll();
}

void lcars_event(const attack_log_t *e)
{
    const char *code = describe_code(e);
    subsys_note(e);                             // the SUBSYS screen's code buttons
    // The last events: any day, newest first.
    memmove(&s_t.last[1], &s_t.last[0], sizeof(s_t.last[0]) * (LC_LAST - 1));
    lc_last_t *l = &s_t.last[0];
    strlcpy(l->code, code, sizeof(l->code));
    const char *nm = describe_code_name(code);
    strlcpy(l->name, nm ? nm : "Event", sizeof(l->name));
    lcars_upper(l->name);
    l->ip = e->src_ip;
    l->ts = e->timestamp;
    if (s_t.last_n < LC_LAST) s_t.last_n++;
    s_chart_dirty = true;

    day_roll();
    if (!s_t.day || local_day(e->timestamp) != s_t.day) return;      // counts are today's
    describe_tier_t t = describe_tier(e);
    if (t == TIER_SEV1) s_t.alerts++;
    else if (t == TIER_SEV2) s_t.probes++;
    if (e->type == ATTACK_SCAN && !strncmp(e->payload, "Port scan:", 10)) s_t.scans++;
    if (e->type == ATTACK_NEW_DEVICE) s_t.new_dev++;

    uint16_t port = ev_port(e);
    if (port)
        for (int i = 0; i < s_nports; i++) if (s_ports[i].port == port) s_ports[i].hit = s_port_ev[i] = true;
    int k = trap_index(e, port);
    if (k >= 0) hit_note(&s_t.trap[k], e);
    k = wire_index(code);
    if (k >= 0) hit_note(&s_t.wire[k], e);
}

// ── Boot splash: the frame's pieces ───────────────────────────────────────────
//
// In the order they roll in (docs/mockups/about-boot.html): top elbow, top
// bars, title, the six rail buttons, bottom elbow, bottom bars, clock. dx, dy:
// where each starts from, px.

#define SP_PIECES 15

typedef struct { lv_obj_t *o; int8_t dx, dy; } sp_piece_t;
EXT_RAM_BSS_ATTR static sp_piece_t s_sp[SP_PIECES];
EXT_RAM_BSS_ATTR static int        s_sp_n;

static void sp_add(lv_obj_t *o, int8_t dx, int8_t dy)
{
    if (s_sp_n < SP_PIECES) s_sp[s_sp_n++] = (sp_piece_t){ o, dx, dy };
}

// ── Frame and rail ────────────────────────────────────────────────────────────

static void page_show(int p);
static void ops_refresh(bool force);

static void title_set(alarm_cond_t c)
{
    char b[40];
    if (c == ALARM_COND_RED)         strlcpy(b, "SHADOWSENTRY | RED ALERT", sizeof(b));
    else if (c == ALARM_COND_YELLOW) strlcpy(b, "SHADOWSENTRY | YELLOW ALERT", sizeof(b));
    else snprintf(b, sizeof(b), "SHADOWSENTRY | %02d %s", s_cur + 1, PAGE_TITLE[s_cur]);
    set_text(s_title, b);
}

// AUTO marks only 06; a page picked by hand marks its own button.
static void marks_update(void)
{
    for (int i = 0; i < PAGES; i++) show(s_rail_mark[i], !s_auto && i == s_cur);
    show(s_rail_mark[5], s_auto);
}

static void rail_cb(lv_event_t *ev)
{
    int i = (int)(uintptr_t)lv_event_get_user_data(ev);
    if (!s_green || s_splash) return;
    if (i == 5) {
        s_auto = !s_auto;
        s_page_at = lv_tick_get();
        marks_update();
        ESP_LOGI(TAG, "AUTO %s", s_auto ? "on" : "off");
        return;
    }
    s_auto = false;
    page_show(i);
}

// ── 07 SUBSYS ─────────────────────────────────────────────────────────────────
//
// The bottom-left elbow is a button: the about screen (ui_subsys.c), GREEN
// only, and it stops AUTO as 01 to 05 do. While it is up the frame and the
// pages are hidden (s_green false, so nothing on them moves); RETURN brings
// back the page that was shown, any alert closes it.

static void subsys_close(bool back)
{
    if (!subsys_shown()) return;
    subsys_show(false);
    show(s_frame, true);
    show(s_content, true);
    if (back) {
        s_green = true;
        page_show(s_cur);
    }
}

static void subsys_back(void) { subsys_close(true); }

static void subsys_cb(lv_event_t *ev)
{
    (void)ev;
    if (!s_green || s_splash) return;
    s_auto = false;
    marks_update();
    fx_stop_all();
    s_green = false;
    show(s_frame, false);
    show(s_content, false);
    subsys_show(true);
}

static void build_frame(void)
{
    s_frame = area(s_root, 0, 0, 480, 320);

    // Top: elbow, its inner black corner, three segments, the title. Each
    // piece goes on the boot splash's list in its order, with the edge it
    // rolls in from (sp_add, under Boot splash).
    lv_obj_t *e = corner(s_frame, 0, 0, 70, 32, 24, LCARS_COL(c1), true);
    corner(e, 52, 10, 18, 22, 8, COL_BLACK, true);
    sp_add(e, -80, 0);
    sp_add(seg(s_frame, 74, 0, 86, 10, LCARS_COL(c1), false), 0, -14);
    sp_add(seg(s_frame, 163, 0, 22, 10, LCARS_COL(c2), false), 0, -14);
    sp_add(seg(s_frame, 188, 0, 24, 10, LCARS_COL(c4), true), 0, -14);
    s_title = text(s_frame, F14, LCARS_COL(c1), 0, 0, 0, "SHADOWSENTRY");
    lv_obj_align(s_title, LV_ALIGN_TOP_RIGHT, -4, -1);
    sp_add(s_title, 60, 0);

    // Rail
    // 02 TRAPS, 03 WIRES and 04 NET in their ports' colours on OPS. 04 is honey
    // c2 (the mockup had butter c5, on which the near-white mark would not
    // show), so 01 OPS took c1, the frame's colour.
    const uint32_t col[6] = { LCARS_PAL->c1, LCARS_PAL->c6, LCARS_PAL->c4, LCARS_PAL->c2, LCARS_PAL->c3, LCARS_PAL->c6 };
    s_rail = area(s_frame, 0, RAIL_Y, RAIL_W, 6 * RAIL_PITCH);
    for (int i = 0; i < 6; i++) {
        lv_obj_t *b = fill(s_rail, 0, i * RAIL_PITCH, RAIL_W, RAIL_H, lv_color_hex(col[i]));
        lv_obj_add_flag(b, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(b, rail_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)i);
        lv_obj_t *l = text(b, F12, COL_BLACK, 0, 0, 0, RAIL_TXT[i]);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_style_text_line_space(l, -2, 0);
        lv_obj_align(l, LV_ALIGN_BOTTOM_RIGHT, -4, -3);
        s_rail_mark[i] = mark(b, RAIL_W, RAIL_H);
        sp_add(b, -80, 0);
    }

    // Bottom: the elbow (07 SUBSYS), segments, the clock. "07 SUBSYS" on one
    // line is 67 px in the 70 px elbow, whose inner black corner takes x 52..69
    // above y 310, so it is on two lines like the rail's, right-aligned in the
    // full-height part (SUBSYS is 49 px of the 52).
    e = corner(s_frame, 0, 286, 70, 34, 24, LCARS_COL(c3), false);
    corner(e, 52, 0, 18, 24, 8, COL_BLACK, false);
    lv_obj_add_flag(e, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(e, subsys_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l = text(e, F12, COL_BLACK, 0, 0, 0, "07\nSYS");   // "SUBSYS" ran into the rounded corner (Rob, 2026-11-03)
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_style_text_line_space(l, -2, 0);
    lv_obj_align(l, LV_ALIGN_BOTTOM_RIGHT, -(70 - 52) - 2, -3);
    sp_add(e, -80, 0);
    sp_add(seg(s_frame, 74, 310, 70, 10, LCARS_COL(c3), false), 0, 14);
    sp_add(seg(s_frame, 147, 310, 30, 10, LCARS_COL(c6), true), 0, 14);
    s_clock = text(s_frame, F12, LCARS_COL(c4), 0, 0, 0, "--:--");
    lv_obj_align(s_clock, LV_ALIGN_TOP_RIGHT, -4, 304);
    sp_add(s_clock, 60, 0);
}

// ── 01 OPS ────────────────────────────────────────────────────────────────────
//
// Content coordinates:
//   y   0..17   condition strip (c4, dark text)
//   y  24..83   four tiles, x i * 76: pill, value (28 px), line under (12 px)
//   y  24..281  x 310..399, the port table: 2 columns of 45 px, 13 px rows
//   y  90..169  events per hour, 24 h: bars x 18..299, y 106..153, scan line
//   y 178..281  the focus panel, a c1 bar on its left, rotating every 5 s

#define CH_X    18
#define CH_Y    106
#define CH_W    282
#define CH_H    48
#define FOC_Y   178

EXT_RAM_BSS_ATTR static lv_obj_t *s_cond, *s_tile_v[4], *s_tile_d[4];
EXT_RAM_BSS_ATTR static lv_obj_t *s_bar[24], *s_scan, *s_scale_top, *s_tick[5];
EXT_RAM_BSS_ATTR static lv_obj_t *s_foc_h, *s_foc_k[3], *s_foc_v[3];
static int       s_scan_x, s_focus;
EXT_RAM_BSS_ATTR static uint32_t  s_focus_at, s_stats_at, s_data_at, s_tick_hour;
EXT_RAM_BSS_ATTR static sd_stats_t *s_stats;             // PSRAM, about 10 KB

static void build_ops(lv_obj_t *pg)
{
    lv_obj_t *c = fill(pg, 0, 0, 400, 18, LCARS_COL(c4));
    lv_obj_set_style_radius(c, 9, 0);
    s_cond = text(c, F12, COL_BLACK, 0, 0, 0, "ALL SYSTEMS NORMAL");
    lv_obj_align(s_cond, LV_ALIGN_RIGHT_MID, -10, 0);

    static const char *const PILL[4] = { "ALERTS", "PROBES", "SCANS", "DEVICES" };
    const uint32_t col[4] = { LCARS_PAL->c1, LCARS_PAL->c2, LCARS_PAL->accent, LCARS_PAL->c4 };
    for (int i = 0; i < 4; i++) {
        pill(pg, (lv_coord_t)(i * 76), 24, lv_color_hex(col[i]), PILL[i]);
        s_tile_v[i] = text(pg, F28, lv_color_hex(col[i]), (lv_coord_t)(i * 76), 38, 72, "0");
        s_tile_d[i] = text(pg, F12, LCARS_COL(dim), (lv_coord_t)(i * 76), 70, 72, "TODAY");
    }

    text(pg, F12, LCARS_COL(c4), 310, 24, 0, "PORTS");
    for (int i = 0; i < s_nports; i++) {
        char b[8];
        snprintf(b, sizeof(b), "%05u", (unsigned)s_ports[i].port);
        lc_port_t *p = &s_ports[i];
        p->l = text(pg, F12, grp_col(p->grp), (lv_coord_t)(310 + (i % 2) * 45),
                    (lv_coord_t)(40 + (i / 2) * 13), 45, b);
        lv_obj_set_style_text_opa(p->l, DIM_OPA, 0);
    }

    text(pg, F12, LCARS_COL(c4), 0, 90, 0, "EVENTS PER HOUR, 24 H");
    s_scale_top = text(pg, F12, LCARS_COL(dim), 0, CH_Y - 2, 14, "0");
    lv_obj_set_style_text_align(s_scale_top, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_t *z = text(pg, F12, LCARS_COL(dim), 0, CH_Y + CH_H - 12, 14, "0");
    lv_obj_set_style_text_align(z, LV_TEXT_ALIGN_RIGHT, 0);
    for (int i = 0; i < 24; i++) {
        lv_coord_t x0 = (lv_coord_t)(i * CH_W / 24), x1 = (lv_coord_t)((i + 1) * CH_W / 24);
        s_bar[i] = fill(pg, CH_X + x0, CH_Y + CH_H - 2, x1 - x0 - 2, 2, i == 23 ? LCARS_COL(c1) : LCARS_COL(c2));
    }
    s_scan = fill(pg, CH_X, CH_Y, 2, CH_H, LCARS_COL(accent));
    for (int k = 0; k < 5; k++) s_tick[k] = text(pg, F12, LCARS_COL(dim), CH_X, CH_Y + CH_H + 2, 0, "");

    fill(pg, 0, FOC_Y, 4, 104, LCARS_COL(c1));
    s_foc_h = text(pg, F12, LCARS_COL(c1), 12, FOC_Y + 2, 288, "");
    for (int i = 0; i < 3; i++) {
        s_foc_k[i] = text(pg, F12, LCARS_COL(c4), 12, (lv_coord_t)(FOC_Y + 19 + i * 16), 0, "");
        s_foc_v[i] = text(pg, F12, LCARS_COL(txt), 12, (lv_coord_t)(FOC_Y + 19 + i * 16), 200, "");
    }
}

// "4 PM" or "16": an hour for the chart's ticks.
static void fmt_hour(time_t t, char *b, size_t len)
{
    struct tm tm;
    localtime_r(&t, &tm);
    if (settings_get()->clock_24h) { snprintf(b, len, "%02d", tm.tm_hour); return; }
    int h = tm.tm_hour % 12;
    snprintf(b, len, "%d %s", h ? h : 12, tm.tm_hour < 12 ? "AM" : "PM");
}

static void chart_update(void)
{
    if (!s_stats && !(s_stats = heap_caps_malloc(sizeof(*s_stats), MALLOC_CAP_SPIRAM))) return;
    sd_log_stats(s_stats);
    s_chart_dirty = false;
    s_stats_at = lv_tick_get();
    char b[24];
    snprintf(b, sizeof(b), "%lu TOTAL", (unsigned long)s_stats->total);
    set_text(s_tile_d[0], b);

    uint32_t now_h = (uint32_t)time(NULL) / 3600, v[24], max = 0;
    for (int i = 0; i < 24; i++) {
        uint32_t h = now_h - 23 + (uint32_t)i;
        v[i] = 0;
        for (int k = 0; k < 24; k++) if (s_stats->hour_key[k] == h) v[i] = s_stats->hour_count[k];
        if (v[i] > max) max = v[i];
    }
    snprintf(b, sizeof(b), "%lu", (unsigned long)max);
    set_text(s_scale_top, b);
    for (int i = 0; i < 24; i++) {
        lv_coord_t h = max ? (lv_coord_t)((uint64_t)v[i] * CH_H / max) : 0;
        if (h < 2) h = 2;
        if (lv_obj_get_height(s_bar[i]) != h) {       // unchanged: no repaint
            lv_obj_set_height(s_bar[i], h);
            lv_obj_set_y(s_bar[i], CH_Y + CH_H - h);
        }
    }
    if (now_h == s_tick_hour || time(NULL) < 1600000000) return;
    s_tick_hour = now_h;
    for (int k = 0; k < 5; k++) {
        if (k == 4) strlcpy(b, "NOW", sizeof(b));
        else fmt_hour((time_t)(now_h - 24 + 6 * (uint32_t)k) * 3600, b, sizeof(b));
        lv_coord_t w = lv_txt_get_width(b, (uint32_t)strlen(b), F12, 0, LV_TEXT_FLAG_NONE);
        lv_coord_t cx = (lv_coord_t)(CH_X + k * CH_W / 4);
        lv_coord_t x = k == 0 ? CH_X : k == 4 ? CH_X + CH_W - w : cx - w / 2;
        set_text(s_tick[k], b);
        lv_obj_set_x(s_tick[k], x);
    }
}

static void foc_line(int i, const char *key, const char *val)
{
    char k[40], v[96];
    snprintf(k, sizeof(k), "%s |", key);
    lcars_upper(k);
    strlcpy(v, val, sizeof(v));
    lcars_upper(v);
    lv_coord_t kw = lv_txt_get_width(k, (uint32_t)strlen(k), F12, 0, LV_TEXT_FLAG_NONE);
    lv_coord_t w = 288 - kw - 4;
    fit(v, F12, w);
    set_text(s_foc_k[i], k);
    if (lv_obj_get_x(s_foc_v[i]) != 12 + kw + 4) lv_obj_set_x(s_foc_v[i], 12 + kw + 4);
    if (lv_obj_get_width(s_foc_v[i]) != w) lv_obj_set_width(s_foc_v[i], w);
    set_text(s_foc_v[i], v);
}

static const char *const MT_STATE[] = { "OFF", "STARTING", "OK", "UNREACHABLE", "LOGIN REFUSED", "CERTIFICATE", "HTTP ERROR" };

static void focus_update(void)
{
    char b[96], ip[16], t[12];
    int n = 0;
    switch (s_focus) {
    case 0:
        set_text(s_foc_h, "LAST EVENTS");
        for (; n < s_t.last_n; n++) {
            const lc_last_t *l = &s_t.last[n];
            char k[40];
            if (l->ip) fmt_ip(l->ip, ip, sizeof(ip)); else strlcpy(ip, "NEARBY", sizeof(ip));
            fmt_hm(l->ts, t, sizeof(t));
            snprintf(k, sizeof(k), "%s %s", l->code, l->name);
            snprintf(b, sizeof(b), "%s | %s", ip, t);
            foc_line(n, k, b);
        }
        if (!n) foc_line(n++, "NONE", "NO EVENTS SINCE BOOT");
        break;
    case 1: {
        pihole_status_t *p = heap_caps_malloc(sizeof(*p), MALLOC_CAP_SPIRAM);
        set_text(s_foc_h, "PI-HOLE");
        if (!p) break;
        pihole_get_status(p);
        if (!p->enabled) { foc_line(n++, "OFF", "NOT CONFIGURED"); heap_caps_free(p); break; }
        foc_line(n++, "STATE", p->state);
        snprintf(b, sizeof(b), "%lu | %lu WITH TOP DOMAINS", (unsigned long)p->devices, (unsigned long)p->with_top);
        foc_line(n++, "DEVICES", b);
        if (p->last_ok_ts) { fmt_hm(p->last_ok_ts, t, sizeof(t)); snprintf(b, sizeof(b), "%s | %lu SYNCS", t, (unsigned long)p->syncs); }
        else strlcpy(b, p->error[0] ? p->error : "NOT YET", sizeof(b));
        foc_line(n++, "LAST SYNC", b);
        heap_caps_free(p);
        break;
    }
    case 2: {
        mikrotik_status_t *m = heap_caps_malloc(sizeof(*m), MALLOC_CAP_SPIRAM);
        set_text(s_foc_h, "ROUTER");
        if (!m) break;
        mikrotik_get_status(m);
        foc_line(n++, "STATE", m->state < sizeof(MT_STATE) / sizeof(MT_STATE[0]) ? MT_STATE[m->state] : "?");
        if (m->state != MIKROTIK_ST_OFF) {
            snprintf(b, sizeof(b), "%u | LEASES %u | NEW %lu", (unsigned)m->hosts, (unsigned)m->leases,
                     (unsigned long)m->new_devices);
            foc_line(n++, "HOSTS", b);
        }
        heap_caps_free(m);
        router_trip_status_t r;
        router_trip_get_status(&r);
        snprintf(b, sizeof(b), "%s | %lu LINES | %lu EVENTS", r.live ? "LIVE" : "NOT LIVE",
                 (unsigned long)r.received, (unsigned long)r.events);
        foc_line(n++, "SYSLOG", b);
        break;
    }
    default: {
        set_text(s_foc_h, "TRAPS TODAY");
        const struct { const char *k; const lc_hit_t *h; int lo, hi; } G[3] = {
            { "TOP", s_t.trap, 0, LC_TRAPS },
            { "TRIPWIRES", s_t.wire, WI_LAN0, WI_DECOY0 },
            { "DECOYS", s_t.wire, WI_DECOY0, WI_ROUTER0 },
        };
        for (int g = 0; g < 3; g++) {
            const lc_hit_t *best = NULL;
            for (int i = G[g].lo; i < G[g].hi; i++)
                if (G[g].h[i].n && (!best || G[g].h[i].n > best->n)) best = &G[g].h[i];
            if (best) snprintf(b, sizeof(b), "%s | %lu HIT%s", best->name, (unsigned long)best->n, best->n == 1 ? "" : "S");
            else strlcpy(b, "NONE TODAY", sizeof(b));
            foc_line(n++, G[g].k, b);
        }
        break;
    }
    }
    for (; n < 3; n++) { set_text(s_foc_k[n], ""); set_text(s_foc_v[n], ""); }
}

static void ops_refresh(bool force)
{
    char b[64], ip[WIFI_IP_STR_LEN];
    day_roll();
    // The board's address and admin port (Rob, 2026-11-02). Widths in the strip's
    // 380 px at worst ("255.255.255.255:65535"): normal 350, secured 340 (the port
    // count left out while the secured line shows).
    wifi_manager_get_ip_str(ip, sizeof(ip));
    if (s_secured_cond != ALARM_COND_GREEN && lv_tick_elaps(s_secured_at) >= SECURED_MS)
        s_secured_cond = ALARM_COND_GREEN;
    if (s_secured_cond != ALARM_COND_GREEN) {
        const char *w = s_secured_cond == ALARM_COND_RED ? "RED" : "YELLOW";
        if (ip[0]) snprintf(b, sizeof(b), "SECURED FROM %s ALERT | %s:%d", w, ip, ADMIN_PORT);
        else       snprintf(b, sizeof(b), "SECURED FROM %s ALERT | NO WI-FI", w);
    } else if (ip[0]) snprintf(b, sizeof(b), "ALL SYSTEMS NORMAL | %s:%d | %d PORTS", ip, ADMIN_PORT, s_nports);
    else              snprintf(b, sizeof(b), "ALL SYSTEMS NORMAL | NO WI-FI | %d PORTS", s_nports);
    set_text(s_cond, b);
    uint32_t dev = (uint32_t)discovery_summary(NULL, 0, NULL);
    const uint32_t v[4] = { s_t.alerts, s_t.probes, s_t.scans, dev };
    for (int i = 0; i < 4; i++) {
        snprintf(b, sizeof(b), "%lu", (unsigned long)v[i]);
        set_text(s_tile_v[i], b);
    }
    snprintf(b, sizeof(b), "%lu NEW", (unsigned long)s_t.new_dev);
    set_text(s_tile_d[3], b);
    for (int i = 0; i < s_nports; i++) {
        lc_port_t *p = &s_ports[i];
        if (p->lit == p->hit || fx_busy(p->l)) continue;
        p->lit = p->hit;
        lv_obj_set_style_text_opa(p->l, p->hit ? LV_OPA_COVER : DIM_OPA, 0);
    }
    if (force || lv_tick_elaps(s_stats_at) >= STATS_MS || (s_chart_dirty && lv_tick_elaps(s_stats_at) >= 10000))
        chart_update();
    if (force) focus_update();
}


// ── Shared: a detail box, Pi-hole shares ──────────────────────────────────────

// The detail box under a list (y 228..281): an accent bar, a heading line in
// accent and up to two lines under it.
typedef struct { lv_obj_t *h, *v; } detail_t;

static void detail_build(detail_t *d, lv_obj_t *pg, const char *hint)
{
    fill(pg, 0, 228, 4, 54, LCARS_COL(accent));
    d->h = text(pg, F12, LCARS_COL(accent), 12, 230, 388, "");
    d->v = text(pg, F12, LCARS_COL(txt), 12, 246, 0, hint);
    lv_label_set_long_mode(d->v, LV_LABEL_LONG_WRAP);
    lv_obj_set_size(d->v, 388, 32);
}

static void detail_set(detail_t *d, const lc_hit_t *h, const char *idle)
{
    char b[64], t[12];
    if (h->ts) fmt_hm(h->ts, t, sizeof(t)); else strlcpy(t, "-", sizeof(t));
    snprintf(b, sizeof(b), "%s | LAST HIT %s", h->name, h->n ? t : "-");
    set_text(d->h, b);
    set_text(d->v, h->n ? h->what : idle);
}

EXT_RAM_BSS_ATTR static correlate_dns_t s_dns;     // about 1.3 KB

// Queries and blocked from Pi-hole's cache for one device; false if none.
static bool pihole_share(uint32_t ip, const uint8_t *mac, uint32_t *tot, uint32_t *blk)
{
    if (!correlate_pihole_device(ip, mac, &s_dns) || !s_dns.total) return false;
    *tot = s_dns.total;
    *blk = s_dns.blocked;
    return true;
}

#define LC_DEVS 6
EXT_RAM_BSS_ATTR static discovery_talker_t s_talk[LC_DEVS];
EXT_RAM_BSS_ATTR static int s_ntalk;

// ── 02 TRAPS ──────────────────────────────────────────────────────────────────
//
//   y   0       header (12 px, c4)
//   y  16 + i * 25, 8 rows of 22 px: tag x 0..131 (rounded left, dark text),
//               bar x 138..301 (8 px on the track), hits x 308..337 (14 px),
//               last x 344..399 (12 px, dim)
//   y 228..281  the selected trap's last hit

#define TR_TAG_W  132
#define TR_BAR_X  138
#define TR_BAR_W  164

EXT_RAM_BSS_ATTR static lv_obj_t *s_tr_fill[LC_TRAPS], *s_tr_n[LC_TRAPS], *s_tr_w[LC_TRAPS], *s_tr_mark[LC_TRAPS];
EXT_RAM_BSS_ATTR static lv_obj_t *s_tr_dot[LC_TRAPS], *s_tr_tag[LC_TRAPS], *s_tr_track[LC_TRAPS];
EXT_RAM_BSS_ATTR static detail_t  s_tr_det;
static int       s_tr_sel = -1;

static void traps_refresh(bool force)
{
    (void)force;
    uint32_t max = 0;
    for (int i = 0; i < LC_TRAPS; i++) if (s_t.trap[i].n > max) max = s_t.trap[i].n;
    for (int i = 0; i < LC_TRAPS; i++) {
        const lc_hit_t *h = &s_t.trap[i];
        char b[12];
        lv_coord_t w = max ? (lv_coord_t)((uint64_t)TR_BAR_W * h->n / max) : 0;
        if (lv_obj_get_width(s_tr_fill[i]) != w) lv_obj_set_width(s_tr_fill[i], w);
        snprintf(b, sizeof(b), "%lu", (unsigned long)h->n);
        set_text(s_tr_n[i], b);
        if (h->n && h->ts) fmt_hm(h->ts, b, sizeof(b)); else strlcpy(b, "-", sizeof(b));
        set_text(s_tr_w[i], b);
        show(s_tr_mark[i], i == s_tr_sel);
    }
    if (s_tr_sel >= 0) detail_set(&s_tr_det, &s_t.trap[s_tr_sel], "NO HITS TODAY");
}

static void trap_cb(lv_event_t *ev)
{
    s_tr_sel = (int)(uintptr_t)lv_event_get_user_data(ev);
    s_page_at = lv_tick_get();                  // AUTO waits a full page after a touch
    traps_refresh(true);
}

static void build_traps(lv_obj_t *pg)
{
    text(pg, F12, LCARS_COL(c4), 0, 0, 0, "TRAPS | HITS TODAY | LAST");
    for (int i = 0; i < LC_TRAPS; i++) {
        lv_obj_t *r = area(pg, 0, (lv_coord_t)(16 + i * 25), 400, 22);
        lv_obj_add_flag(r, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(r, trap_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)i);
        lv_obj_t *d = s_tr_dot[i] = fill(r, 0, 0, 22, 22, LCARS_COL(c6));
        lv_obj_set_style_radius(d, LV_RADIUS_CIRCLE, 0);
        lv_obj_t *tag = s_tr_tag[i] = fill(r, 11, 0, TR_TAG_W - 11, 22, LCARS_COL(c6));
        lv_obj_t *l = text(tag, F12, COL_BLACK, 0, 0, 0, s_t.trap[i].name);
        lv_obj_align(l, LV_ALIGN_RIGHT_MID, -6, 0);
        s_tr_mark[i] = mark(tag, TR_TAG_W - 11, 22);
        lv_obj_t *tr = s_tr_track[i] = fill(r, TR_BAR_X, 7, TR_BAR_W, 8, LCARS_COL(track));
        s_tr_fill[i] = fill(tr, 0, 0, 0, 8, LCARS_COL(c1));
        s_tr_n[i] = text(r, F14, LCARS_COL(c2), 308, 2, 30, "0");
        lv_obj_set_style_text_align(s_tr_n[i], LV_TEXT_ALIGN_RIGHT, 0);
        s_tr_w[i] = text(r, F12, LCARS_COL(dim), 344, 4, 56, "-");
        lv_obj_set_style_text_align(s_tr_w[i], LV_TEXT_ALIGN_RIGHT, 0);
    }
    detail_build(&s_tr_det, pg, "TAP A TRAP FOR ITS LAST HIT");
}

// ── 03 WIRES ──────────────────────────────────────────────────────────────────
//
//   y   0       header
//   y  17 + row * 23, two columns x 0 and 204, cells 196 x 20: a 6 px state
//               bar (hit accent, armed c4, off dark), name (12 px), hits or
//               OFF (right, x 164..191)
//   y 228..281  the selected cell's last hit, or why it is off

enum { WS_ARMED, WS_HIT, WS_OFF };

EXT_RAM_BSS_ATTR static lv_obj_t *s_wi_bar[LC_WIRES], *s_wi_nm[LC_WIRES], *s_wi_n[LC_WIRES], *s_wi_mark[LC_WIRES];
EXT_RAM_BSS_ATTR static uint8_t   s_wi_st[LC_WIRES];
EXT_RAM_BSS_ATTR static detail_t  s_wi_det;
static int       s_wi_sel = -1;

// Why a cell is off, or NULL when it is armed.
static const char *wire_off(int i)
{
    if (i < WI_DECOY0)  return TRIPWIRE_ENABLE && WIRE_PORT[i] ? NULL : "NOT LISTENING (PORT OFF)";
    if (i < WI_DECOY0 + MT_TCP_N) {
        if (!TRIPWIRE_ENABLE || !WIRE_PORT[i]) return "NOT LISTENING (PORT OFF)";
        return mikrotik_tcp_listening((mt_tcp_kind_t)(i - WI_DECOY0)) ? NULL : "NOT LISTENING";
    }
    if (i < WI_ROUTER0) return mikrotik_udp_on() && WIRE_PORT[i] ? NULL : "NOT LISTENING";
    if (i < WI_NEWDEV)  return router_trip_syslog_live() ? NULL : "NEEDS THE ROUTER SYSLOG (TRIPWIRES.RSC)";
    if (i == WI_NEWDEV) return mikrotik_running() ? NULL : "NEEDS THE ROUTER LOGIN (SETTINGS)";
    return mikrotik_watch_armed() ? NULL : "NOT ARMED: ARM THE BASELINE IN SETTINGS";
}

// The cell's colours for its state (also what an effect returns to): part 0
// the bar, 1 the name.
static void wire_part_style(int i, int part)
{
    uint8_t st = s_wi_st[i];
    if (!part) lv_obj_set_style_bg_color(s_wi_bar[i], st == WS_HIT ? LCARS_COL(accent)
                                         : st == WS_OFF ? LCARS_COL(track) : LCARS_COL(c4), 0);
    else       lv_obj_set_style_text_color(s_wi_nm[i], st == WS_OFF ? LCARS_COL(dim) : LCARS_COL(txt), 0);
}

static void wire_style(int i) { wire_part_style(i, 0); wire_part_style(i, 1); }

static void wires_refresh(bool force)
{
    (void)force;
    for (int i = 0; i < LC_WIRES; i++) {
        const lc_hit_t *h = &s_t.wire[i];
        const char *off = wire_off(i);
        uint8_t st = h->n ? WS_HIT : off ? WS_OFF : WS_ARMED;
        char b[12];
        if (st != s_wi_st[i]) {
            s_wi_st[i] = st;
            wire_style(i);
        }
        if (st == WS_OFF) strlcpy(b, "OFF", sizeof(b));
        else snprintf(b, sizeof(b), "%lu", (unsigned long)h->n);
        set_text(s_wi_n[i], b);
        show(s_wi_mark[i], i == s_wi_sel);
    }
    if (s_wi_sel >= 0) {
        const char *off = wire_off(s_wi_sel);
        detail_set(&s_wi_det, &s_t.wire[s_wi_sel], off ? off : "NOTHING YET TODAY");
    }
}

static void wire_cb(lv_event_t *ev)
{
    s_wi_sel = (int)(uintptr_t)lv_event_get_user_data(ev);
    s_page_at = lv_tick_get();
    wires_refresh(true);
}

static void build_wires(lv_obj_t *pg)
{
    text(pg, F12, LCARS_COL(c4), 0, 0, 0, "TRIPWIRES | ANY TOUCH ALERTS");
    for (int i = 0; i < LC_WIRES; i++) {
        lv_obj_t *c = area(pg, (lv_coord_t)((i % 2) * 204), (lv_coord_t)(17 + (i / 2) * 23), 196, 20);
        lv_obj_add_flag(c, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(c, wire_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)i);
        s_wi_bar[i] = fill(c, 0, 0, 6, 20, LCARS_COL(c4));
        s_wi_nm[i] = text(c, F12, LCARS_COL(txt), 12, 3, 150, s_t.wire[i].name);
        s_wi_n[i] = text(c, F12, LCARS_COL(c2), 164, 3, 28, "0");
        lv_obj_set_style_text_align(s_wi_n[i], LV_TEXT_ALIGN_RIGHT, 0);
        s_wi_mark[i] = mark(c, 196, 20);
        s_wi_st[i] = WS_ARMED;
    }
    detail_build(&s_wi_det, pg, "TAP A TRIPWIRE FOR ITS LAST HIT");
}

// ── 04 NET ────────────────────────────────────────────────────────────────────
//
//   y   0..91   five gauges, x i * 81, 76 wide: Wi-Fi RSSI, the UI loop (the
//               slowest lv_timer_handler() in the last second; there is no
//               pinger), free internal RAM, Pi-hole's blocked share over the
//               busiest devices, sockets (no getter: "-"); ticks at 25, 50
//               and 75 %; value (14 px) at y 94, name (12 px) at y 112
//   y 150..245  3 x 3 link states, x col * 136, y 150 + row * 34

#define G_N 5
#define G_H 92

EXT_RAM_BSS_ATTR static lv_obj_t *s_g_fill[G_N], *s_g_v[G_N];
EXT_RAM_BSS_ATTR static lv_obj_t *s_nl_v[9], *s_nl_k[9];
EXT_RAM_BSS_ATTR static lv_coord_t s_g_tgt[G_N];         // the gauge's height to ease to
EXT_RAM_BSS_ATTR static uint32_t  s_ipfix_rec, s_ipfix_at, s_ipfix_rate;
EXT_RAM_BSS_ATTR static bool      s_ipfix_have;

static void gauge_set(int i, const char *v, int32_t pct)
{
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    lv_coord_t h = (lv_coord_t)(G_H * pct / 100);
    if (s_g_tgt[i] != h) {                                  // anim_cb eases the fill there
        s_g_tgt[i] = h;
        lv_obj_set_style_bg_color(s_g_fill[i], pct >= 100 ? LCARS_COL(c1) : LCARS_COL(c4), 0);
    }
    set_text(s_g_v[i], v);
}

static void nl_set(int i, const char *v)
{
    char b[72];
    strlcpy(b, v, sizeof(b));
    lcars_upper(b);
    fit(b, F12, 128);
    set_text(s_nl_v[i], b);
}

static void talkers_load(void)
{
    s_ntalk = discovery_top_talkers(s_talk, LC_DEVS);
}

static void net_refresh(bool force)
{
    char b[72];
    wifi_ap_record_t ap;
    bool up = wifi_manager_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    if (up) { snprintf(b, sizeof(b), "%d DBM", (int)ap.rssi); gauge_set(0, b, (ap.rssi + 100) * 100 / 70); }
    else    gauge_set(0, "-", 0);
    uint32_t ms = (ui_loop_max_us() + 500) / 1000;
    snprintf(b, sizeof(b), "%lu MS", (unsigned long)ms);
    gauge_set(1, b, (int32_t)(ms * 2));                     // 50 ms full
    uint32_t kb = (uint32_t)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024);
    snprintf(b, sizeof(b), "%lu KB", (unsigned long)kb);
    gauge_set(2, b, (int32_t)kb);                           // 100 KB full
    if (force || !s_ntalk) talkers_load();
    uint32_t tot = 0, blk = 0;
    for (int i = 0; i < s_ntalk; i++) {
        uint32_t t, k;
        if (pihole_share(s_talk[i].ip, s_talk[i].mac, &t, &k)) { tot += t; blk += k; }
    }
    if (tot) { snprintf(b, sizeof(b), "%lu %%", (unsigned long)(blk * 100 / tot)); gauge_set(3, b, (int32_t)(blk * 100 / tot)); }
    else     gauge_set(3, "-", 0);
    gauge_set(4, "-", 0);

    if (up) snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", ap.bssid[0], ap.bssid[1], ap.bssid[2],
                     ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    else    strlcpy(b, "NOT CONNECTED", sizeof(b));
    nl_set(0, b);
    if (time(NULL) >= 1600000000) snprintf(b, sizeof(b), "SET | %s", settings_get()->tz);
    else                          strlcpy(b, "NOT SET (NO SNTP YET)", sizeof(b));
    nl_set(1, b);
    uint32_t s = (uint32_t)(esp_timer_get_time() / 1000000LL);
    snprintf(b, sizeof(b), "%lu D %02lu H %02lu M", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600),
             (unsigned long)(s % 3600 / 60));
    nl_set(2, b);
    pihole_status_t *p = heap_caps_malloc(sizeof(*p), MALLOC_CAP_SPIRAM);
    if (p) {
        pihole_get_status(p);
        if (p->enabled) snprintf(b, sizeof(b), "%s | %lu DEVICES", p->state, (unsigned long)p->devices);
        else            strlcpy(b, "OFF", sizeof(b));
        nl_set(3, b);
        heap_caps_free(p);
    }
    mikrotik_status_t *m = heap_caps_malloc(sizeof(*m), MALLOC_CAP_SPIRAM);
    if (m) {
        mikrotik_get_status(m);
        const char *st = m->state < sizeof(MT_STATE) / sizeof(MT_STATE[0]) ? MT_STATE[m->state] : "?";
        if (m->state == MIKROTIK_ST_OK) snprintf(b, sizeof(b), "%s | %u HOSTS", st, (unsigned)m->hosts);
        else                            strlcpy(b, st, sizeof(b));
        nl_set(4, b);
        heap_caps_free(m);
    }
    uint32_t rec, drop;
    router_flow_counters(&rec, &drop);
    if (!s_ipfix_have) { s_ipfix_have = true; s_ipfix_rec = rec; s_ipfix_at = lv_tick_get(); }
    else if (lv_tick_elaps(s_ipfix_at) >= 60000) {
        s_ipfix_rate = (rec - s_ipfix_rec) * 60000u / lv_tick_elaps(s_ipfix_at);
        s_ipfix_rec = rec;
        s_ipfix_at = lv_tick_get();
    }
    if (!rec) strlcpy(b, "NO RECORDS YET", sizeof(b));
    else      snprintf(b, sizeof(b), "%lu FLOWS / MIN", (unsigned long)s_ipfix_rate);
    nl_set(5, b);
    sd_status_t sd;
    sd_log_status(&sd);
    if (sd.mounted) {
        unsigned long tenths = (unsigned long)(sd.free_bytes / 100000000ULL);
        snprintf(b, sizeof(b), "%lu.%lu GB FREE", tenths / 10, tenths % 10);
    } else strlcpy(b, "NO CARD", sizeof(b));
    nl_set(6, b);
    nl_set(7, cam_ready() ? "READY" : "NOT FOUND");
    if (settings_get()->discord_webhook[0]) {
        discord_status_t d;
        discord_get_status(&d);
        snprintf(b, sizeof(b), "%lu POSTED | LAST %d", (unsigned long)d.posted, d.last_status);
    } else strlcpy(b, "OFF", sizeof(b));
    nl_set(8, b);
}

static void build_net(lv_obj_t *pg)
{
    static const char *const GK[G_N] = { "WI-FI", "UI LOOP", "FREE RAM", "BLOCKED", "SOCKETS" };
    for (int i = 0; i < G_N; i++) {
        lv_coord_t x = (lv_coord_t)(i * 81);
        lv_obj_t *col = fill(pg, x, 0, 76, G_H, LCARS_COL(track));
        s_g_fill[i] = fill(col, 0, G_H, 76, 0, LCARS_COL(c4));
        for (int k = 1; k <= 3; k++) fill(col, 0, (lv_coord_t)(G_H - G_H * k / 4), 76, 1, COL_BLACK);
        s_g_v[i] = text(pg, F14, LCARS_COL(c2), x, 94, 76, "-");
        lv_obj_set_style_text_align(s_g_v[i], LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_t *k = text(pg, F12, LCARS_COL(c4), x, 112, 76, GK[i]);
        lv_obj_set_style_text_align(k, LV_TEXT_ALIGN_CENTER, 0);
    }
    static const char *const NK[9] = { "ACCESS POINT", "CLOCK", "UPTIME", "PI-HOLE", "ROUTER", "IPFIX",
                                       "MICROSD", "CAMERA", "DISCORD" };
    for (int i = 0; i < 9; i++) {
        lv_coord_t x = (lv_coord_t)((i % 3) * 136), y = (lv_coord_t)(150 + (i / 3) * 34);
        s_nl_k[i] = text(pg, F12, LCARS_COL(c4), x, y, 128, NK[i]);
        s_nl_v[i] = text(pg, F12, LCARS_COL(c2), x, y + 14, 128, "-");
    }
}

// ── 05 DEV ────────────────────────────────────────────────────────────────────
//
// List (busiest first, discovery_top_talkers()): header, then 6 rows of 30 px
// from y 16: name (14 px, c2) and "IP | VENDOR" (12 px, dim) x 0..235,
// Pi-hole's blocked share (12 px, c4, right) x 244..399 at y 3, under it an
// activity bar (DV_BAR_*: the fill eases to the device's packet rate on a log
// scale, a short hi segment travels along it at a speed that grows with the
// rate; anim_cb moves it), a track line under each row. A tap opens the detail:
// name (20 px), Pi-hole's lookups and blocked count, the last allowed and
// blocked names, the router's flow summary, BACK and BLOCK DEVICE (asks
// first; blocklist_add() on confirm: the router drops the device's forward
// traffic within a minute; the dashboard undoes it).

EXT_RAM_BSS_ATTR static lv_obj_t *s_dv_list, *s_dv_det;
EXT_RAM_BSS_ATTR static lv_obj_t *s_dv_row[LC_DEVS], *s_dv_nm[LC_DEVS], *s_dv_sub[LC_DEVS], *s_dv_q[LC_DEVS];
#define DV_BAR_X        244         // the activity bar, in the row
#define DV_BAR_Y        22
#define DV_BAR_W        156
#define DV_BAR_H        4
#define DV_RATE_FULL    3600        // packets an hour for a full bar (log scale: 1 an hour 8 %, 60 an hour 50 %)
#define DV_SEG_W        12          // the travelling segment
#define DV_SEG_MS       80          // how often it moves
#define DV_SEG_MIN_PXS  10          // its speed, px a second: a quiet device (DV_BAR_W in 16 s) ...
#define DV_SEG_MAX_PXS  70          // ... to a full bar (in 2.4 s); between, in step with the fill

EXT_RAM_BSS_ATTR static lv_obj_t *s_dv_fill[LC_DEVS], *s_dv_seg[LC_DEVS];
EXT_RAM_BSS_ATTR static lv_coord_t s_dv_tgt[LC_DEVS];                        // the fill's width to ease to
EXT_RAM_BSS_ATTR static uint8_t   s_dv_pct[LC_DEVS];                         // the rate on the log scale, %
EXT_RAM_BSS_ATTR static int32_t   s_dv_pos[LC_DEVS];                         // the segment's x, 1/16 px
EXT_RAM_BSS_ATTR static uint32_t  s_dv_seg_at;
EXT_RAM_BSS_ATTR static lv_obj_t *s_dd_nm, *s_dd_sub, *s_dd_v[4], *s_dd_block;
EXT_RAM_BSS_ATTR static discovery_talker_t s_dv_sel;     // the device shown in the detail (a copy)
EXT_RAM_BSS_ATTR static bool      s_dv_open;
EXT_RAM_BSS_ATTR static router_flow_dev_t s_flow;   // about 2.6 KB

static void dev_name(const discovery_talker_t *t, char *b, size_t len)
{
    if (t->label[0])       strlcpy(b, t->label, len);
    else if (t->vendor[0]) snprintf(b, len, "%s device", t->vendor);
    else                   strlcpy(b, "unknown device", len);
    lcars_upper(b);
}

static void dev_sub(const discovery_talker_t *t, char *b, size_t len)
{
    char ip[16];
    if (t->ip) fmt_ip(t->ip, ip, sizeof(ip)); else strlcpy(ip, "NO IP", sizeof(ip));
    if (t->vendor[0]) snprintf(b, len, "%s | %s", ip, t->vendor); else strlcpy(b, ip, len);
    lcars_upper(b);
}

static void dev_detail(void)
{
    char b[96];
    const discovery_talker_t *t = &s_dv_sel;
    dev_name(t, b, sizeof(b));
    fit(b, F20, 400);
    set_text(s_dd_nm, b);
    dev_sub(t, b, sizeof(b));
    fit(b, F12, 400);
    set_text(s_dd_sub, b);
    if (correlate_pihole_device(t->ip, t->mac, &s_dns) && s_dns.total) {
        snprintf(b, sizeof(b), "%u LOOKUPS, %u BLOCKED IN %lu MIN", (unsigned)s_dns.total, (unsigned)s_dns.blocked,
                 (unsigned long)(s_dns.window_s / 60));
        set_text(s_dd_v[0], b);
        const char *al = "-", *bl = "-";
        for (int i = s_dns.n - 1; i >= 0; i--) {             // newest first: keep the first of each
            if (s_dns.q[i].blocked) bl = s_dns.q[i].domain; else al = s_dns.q[i].domain;
        }
        strlcpy(b, al, sizeof(b)); lcars_upper(b); fit(b, F12, 400); set_text(s_dd_v[1], b);
        strlcpy(b, bl, sizeof(b)); lcars_upper(b); fit(b, F12, 400); set_text(s_dd_v[2], b);
    } else {
        set_text(s_dd_v[0], "NO PI-HOLE DATA");
        set_text(s_dd_v[1], "-");
        set_text(s_dd_v[2], "-");
    }
    if (t->ip && router_flow_device(t->ip, &s_flow) && s_flow.state == ROUTER_FLOW_ST_OK) {
        uint64_t up = 0;
        for (int i = 0; i < s_flow.n && i < ROUTER_FLOW_DST; i++) up += s_flow.d[i].bytes_out;
        snprintf(b, sizeof(b), "%u HOSTS | %lu.%lu MB UP", (unsigned)s_flow.n,
                 (unsigned long)(up / 1000000), (unsigned long)(up % 1000000 / 100000));
    } else strlcpy(b, "NO FLOW DATA", sizeof(b));
    set_text(s_dd_v[3], b);
    show(s_dd_block, t->ip != 0);
}

static void dev_open(bool on)
{
    s_dv_open = on;
    show(s_dv_list, !on);
    show(s_dv_det, on);
    if (on) dev_detail();
}

static void dev_refresh(bool force)
{
    if (s_dv_open) { if (force) dev_detail(); return; }
    talkers_load();
    for (int i = 0; i < LC_DEVS; i++) {
        if (i >= s_ntalk) { show(s_dv_row[i], false); continue; }
        const discovery_talker_t *t = &s_talk[i];
        char b[96];
        dev_name(t, b, sizeof(b));
        fit(b, F14, 236);
        set_text(s_dv_nm[i], b);
        dev_sub(t, b, sizeof(b));
        fit(b, F12, 236);
        set_text(s_dv_sub[i], b);
        uint32_t tot, blk;
        if (pihole_share(t->ip, t->mac, &tot, &blk)) snprintf(b, sizeof(b), "%lu %% BLOCKED", (unsigned long)(blk * 100 / tot));
        else snprintf(b, sizeof(b), "%lu / H", (unsigned long)t->per_hour);
        set_text(s_dv_q[i], b);
        uint32_t ph = t->per_hour > DV_RATE_FULL ? DV_RATE_FULL : t->per_hour;
        s_dv_pct[i] = (uint8_t)(100.0f * logf(1.0f + (float)ph) / logf(1.0f + DV_RATE_FULL) + 0.5f);
        s_dv_tgt[i] = (lv_coord_t)(DV_BAR_W * s_dv_pct[i] / 100);   // anim_cb eases the fill there
        show(s_dv_seg[i], ph != 0);                                 // no packets, no motion
        show(s_dv_row[i], true);
    }
}

static void dev_row_cb(lv_event_t *ev)
{
    int i = (int)(uintptr_t)lv_event_get_user_data(ev);
    if (i >= s_ntalk) return;
    s_dv_sel = s_talk[i];
    s_page_at = lv_tick_get();
    dev_open(true);
}

static void dev_back_cb(lv_event_t *ev)
{
    (void)ev;
    s_page_at = lv_tick_get();
    dev_open(false);
    dev_refresh(true);
}

static const char *BLOCK_BTNS[] = { "CANCEL", "CONFIRM", "" };
EXT_RAM_BSS_ATTR static uint32_t s_block_ip;

static void block_mb_cb(lv_event_t *ev)
{
    lv_obj_t *mb = lv_event_get_current_target(ev);
    const char *b = lv_msgbox_get_active_btn_text(mb);
    bool yes = b && !strcmp(b, "CONFIRM");
    lv_msgbox_close_async(mb);
    if (!yes || !s_block_ip) return;
    char why[96] = "", ip[16];
    fmt_ip(s_block_ip, ip, sizeof(ip));
    block_result_t r = blocklist_add(s_block_ip, BLOCK_SRC, "front panel", why, sizeof(why));
    ESP_LOGW(TAG, "BLOCK DEVICE %s from the panel: result %d%s%s", ip, (int)r, why[0] ? ", " : "", why);
    char body[160];
    if (r == BLOCK_OK || r == BLOCK_UPDATED)
        snprintf(body, sizeof(body), "%s is on the block list. The router drops it within a minute; "
                 "the dashboard can undo it.", ip);
    else
        snprintf(body, sizeof(body), "%s was not blocked: %s", ip,
                 why[0] ? why : r == BLOCK_FULL ? "the block list is full" : "could not save the list");
    lv_obj_t *m = lv_msgbox_create(NULL, r == BLOCK_OK || r == BLOCK_UPDATED ? "BLOCKED" : "NOT BLOCKED",
                                   body, NULL, true);
    lv_obj_set_width(m, 360);
    lcars_style_msgbox(m);
    lv_obj_center(m);
}

static void dev_block_cb(lv_event_t *ev)
{
    (void)ev;
    if (!s_dv_sel.ip) return;
    s_block_ip = s_dv_sel.ip;
    s_page_at = lv_tick_get();
    char name[48], ip[16];
    EXT_RAM_BSS_ATTR static char body[200];
    dev_name(&s_dv_sel, name, sizeof(name));
    fmt_ip(s_dv_sel.ip, ip, sizeof(ip));
    snprintf(body, sizeof(body), "Block %s (%s) from the internet? The router drops it within a minute. "
             "Undo on the dashboard.", name, ip);
    lv_obj_t *mb = lv_msgbox_create(NULL, "BLOCK DEVICE", body, BLOCK_BTNS, false);
    lv_obj_set_width(mb, 360);
    lcars_style_msgbox(mb);
    lv_obj_t *bt = lv_msgbox_get_btns(mb);
    lv_obj_set_size(bt, 320, 40);
    lv_obj_center(mb);
    lv_obj_add_event_cb(mb, block_mb_cb, LV_EVENT_VALUE_CHANGED, NULL);
}

// A rounded LCARS button: a fill with dark 14 px text.
static lv_obj_t *lc_btn(lv_obj_t *p, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h, lv_color_t c,
                        const char *t, lv_event_cb_t cb)
{
    lv_obj_t *b = fill(p, x, y, w, h, c);
    lv_obj_set_style_radius(b, h / 2, 0);
    lv_obj_add_flag(b, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l = text(b, F14, COL_BLACK, 0, 0, 0, t);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
    return b;
}

static void build_dev(lv_obj_t *pg)
{
    s_dv_list = area(pg, 0, 0, 400, 282);
    text(s_dv_list, F12, LCARS_COL(c4), 0, 0, 0, "BUSIEST FIRST | TAP FOR DETAIL");
    for (int i = 0; i < LC_DEVS; i++) {
        lv_obj_t *r = s_dv_row[i] = area(s_dv_list, 0, (lv_coord_t)(16 + i * 30), 400, 30);
        lv_obj_add_flag(r, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(r, dev_row_cb, LV_EVENT_CLICKED, (void *)(uintptr_t)i);
        s_dv_nm[i] = text(r, F14, LCARS_COL(c2), 0, 0, 236, "");
        s_dv_sub[i] = text(r, F12, LCARS_COL(dim), 0, 16, 236, "");
        s_dv_q[i] = text(r, F12, LCARS_COL(c4), DV_BAR_X, 3, DV_BAR_W, "");
        lv_obj_set_style_text_align(s_dv_q[i], LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_t *tr = fill(r, DV_BAR_X, DV_BAR_Y, DV_BAR_W, DV_BAR_H, LCARS_COL(track));   // clips the segment
        s_dv_fill[i] = fill(tr, 0, 0, 0, DV_BAR_H, LCARS_COL(c1));
        s_dv_seg[i] = fill(tr, -DV_SEG_W, 0, DV_SEG_W, DV_BAR_H, LCARS_COL(hi));
        s_dv_pos[i] = (int32_t)rnd(0, DV_BAR_W) * 16;               // the rows do not travel in step
        show(s_dv_seg[i], false);
        fill(r, 0, 29, 400, 1, LCARS_COL(track));
        show(r, false);
    }
    s_dv_det = area(pg, 0, 0, 400, 282);
    s_dd_nm = text(s_dv_det, F20, LCARS_COL(c1), 0, 0, 400, "");
    s_dd_sub = text(s_dv_det, F12, LCARS_COL(c4), 0, 26, 400, "");
    static const char *const K[4] = { "PI-HOLE", "LAST ALLOWED (LEFT THE HOUSE)", "LAST BLOCKED", "ROUTER, OUTBOUND" };
    for (int i = 0; i < 4; i++) {
        text(s_dv_det, F12, LCARS_COL(c4), 0, (lv_coord_t)(48 + i * 32), 0, K[i]);
        s_dd_v[i] = text(s_dv_det, F12, LCARS_COL(c2), 0, (lv_coord_t)(62 + i * 32), 400, "-");
    }
    lc_btn(s_dv_det, 0, 186, 100, 34, LCARS_COL(c4), "BACK", dev_back_cb);
    s_dd_block = lc_btn(s_dv_det, 106, 186, 160, 34, LCARS_COL(accent), "BLOCK DEVICE", dev_block_cb);
    show(s_dv_det, false);
}

// ── Motion ────────────────────────────────────────────────────────────────────
//
// Rob, 2026-11-03: "make it feel like the HAL screens where numbers and codes
// flash out", then "the blinking ... should feel measured", "make them
// somewhat functional, you just are blinking these for any old reason",
// "vary animations ... it should feel organic" and "random times between
// transitions". Colours only: nothing moves or resizes, except a NET gauge
// easing to a new value.
//
// Every effect comes from real activity. fx_sense() runs every FX_SENSE_MS,
// compares the counters the shown page can read with the last run, and
// queues an effect for each element whose counter moved (one entry per
// element: a burst coalesces). FX_LANES lanes play the queue, so two effects
// can run at once on different elements; each lane waits its own random
// FX_GAP_MIN_MS..FX_GAP_MAX_MS after its effect ends, and takes the oldest
// entry whose elements the other lane is not playing. On OPS lane
// FX_WATCH_LANE walks the watch pass only and the other lane plays the
// queue. With nothing happening, nothing moves, except the watch pass.
// Each kind of activity has its own effect and tone, every step's length is
// drawn again each time (a range, or the base value +/- FX_JITTER_PCT), and
// the same effect never plays twice running at the same timing:
//   EF_DECAY   solid, then flashes each dimmer (FX_FLASH_PCT), back to normal: hi
//   EF_GLOW    a slow fade up and back, no blink: c2 (slower on NET and DEV)
//   EF_RIPPLE  the first cell, then the next ones in turn, fading behind: c5
//   EF_TICK    one brighten, held: c4
//   EF_PULSE   two soft swells: hi at FX_PULSE_PEAK %
//   EF_SWEEP   a TRAPS row brightens left to right (dot, tag, bar, track): c5
//   EF_WATCH   a soft glow to FX_WATCH_PEAK %: hi
//   EF_SCAN    a soft ripple, FX_WATCH_PEAK % and fading behind: hi
// The watch pass shows the panel re-reading each listener's counter: every
// FX_WATCH_MIN_MS..FX_WATCH_MAX_MS the next TRAPS row's tag, or the next
// armed WIRES cell's bar (off cells never), in a shuffled order, gets an
// EF_WATCH on a free lane; real hits are taken from the queue first. On OPS
// every FX_OPS_WATCH_MIN_MS..FX_OPS_WATCH_MAX_MS the next cluster of 2 to 5
// neighbouring ports, TRAP and WIRE ones weighted up (ops_watch_plan()),
// gets an EF_WATCH or an EF_SCAN on the watch lane.
// A cell whose normal colour is the effect's tone uses hi instead. The tone
// is reached FX_FLASH_PCT (or the effect's own) % of the way from the cell's
// normal colour (lv_color_mix). The DEV activity bars (anim_cb, ANIM_MS)
// follow the devices' rates. All of it stops, colours restored and the queue
// emptied, on a page change and while an alert view is up or the LCARS panel
// is hidden (the alert stripes are ui.c's); the first sense after that only
// records the counters.

#define FX_SENSE_MS         1000        // how often the counters are compared
#define FX_GAP_MIN_MS       300         // between one effect ending and the next starting
#define FX_GAP_MAX_MS       1500
#define FX_JITTER_PCT       20          // each fixed step: +/- this much, drawn each time
#define FX_SOLID_MS         500         // EF_DECAY: the tone, held
#define FX_FLASHES          3           //   then flashes while dimming
#define FX_FLASH_ON_MS      140
#define FX_FLASH_OFF_MS     140
static const uint8_t FX_FLASH_PCT[FX_FLASHES] = { 100, 65, 35 };   // of the way from normal to the tone
#define FX_GLOW_MIN_MS      600         // EF_GLOW: up and back in all (OPS, WIRES)
#define FX_GLOW_MAX_MS      900
#define FX_GLOW_SLOW_MIN_MS 900         //   on NET and DEV, where a name or value has to be noticed
#define FX_GLOW_SLOW_MAX_MS 1200
#define FX_GLOW_STEPS       12
#define FX_RIPPLE_MIN_MS    80          // EF_RIPPLE: one cell to the next
#define FX_RIPPLE_MAX_MS    120
#define FX_TICK_MS          500         // EF_TICK (NET only)
#define FX_PULSE_MIN_MS     150         // EF_PULSE (NET only): each of its 7 steps, about 1.2 s in all
#define FX_PULSE_MAX_MS     190
#define FX_PULSE_PEAK       80          //   % at the top of a swell
#define FX_SWEEP_MIN_MS     70          // EF_SWEEP: one part of the row to the next
#define FX_SWEEP_MAX_MS     110
#define FX_WATCH_MIN_MS     2500        // the watch pass: from one listener to the next
#define FX_WATCH_MAX_MS     4000
#define FX_WATCH_MS         900         // EF_WATCH: up and back in all (+/- FX_JITTER_PCT)
#define FX_WATCH_PEAK       60          //   % at the top
#define FX_SCAN_MIN_MS      120         // EF_SCAN: one cell to the next
#define FX_SCAN_MAX_MS      180
#define FX_OPS_WATCH_MIN_MS 1500        // OPS watch pass: from one cluster to the next
#define FX_OPS_WATCH_MAX_MS 3500
#define FX_OPS_WATCH_WEIGHT 2           //   a TRAP or WIRE cluster comes up this many times per NET one
#define FX_OPS_SECTIONS     2           // OPS: several ports in one sense light up to this many sections
#define FX_RSSI_DB          3           // NET: an RSSI change this big ticks the access point

#define FX_LANES      2
#define FX_WATCH_LANE 1                 // on OPS this lane walks the watch pass only
#define FX_OBJS     5
#define FX_STEP_MAX 16
#define FX_Q        12
#define ANIM_MS     50
enum { FX_TEXT, FX_BG };
enum { EF_DECAY, EF_GLOW, EF_RIPPLE, EF_TICK, EF_PULSE, EF_SWEEP, EF_WATCH, EF_SCAN, EF_N };

typedef struct {
    lv_timer_t *tm;
    uint32_t    idle_at, gap;                   // the lane's rest after its effect
    lv_obj_t   *o[FX_OBJS];
    int16_t     item[FX_OBJS];
    lv_color_t  base[FX_OBJS], tone[FX_OBJS];   // normal colour (read at the start) and target
    lv_opa_t    base_opa[FX_OBJS];
    uint8_t     part[FX_OBJS], lvl[FX_OBJS];    // lvl: % as painted, 0 = normal
    uint8_t     n;                              // objects; 0 = idle
    uint8_t     plen, lag, steps, st;           // object k runs pct[] lag * k steps late
    uint8_t     pct[FX_STEP_MAX];
    uint16_t    ms[FX_STEP_MAX];                // per step
} fx_t;

typedef struct { uint8_t kind, n; int16_t item[FX_OBJS]; } fxq_t;

EXT_RAM_BSS_ATTR static fx_t     s_fx[FX_LANES];
EXT_RAM_BSS_ATTR static fxq_t    s_q[FX_Q];
EXT_RAM_BSS_ATTR static uint8_t  s_q_head, s_q_n;
EXT_RAM_BSS_ATTR static uint32_t s_sense_at, s_fx_sig[EF_N];
EXT_RAM_BSS_ATTR static uint32_t s_watch_at, s_watch_gap;
EXT_RAM_BSS_ATTR static uint8_t  s_wo[LC_WIRES > LC_TRAPS ? LC_WIRES : LC_TRAPS], s_wo_n, s_wo_i, s_wo_last;
#define OW_MAX (LC_PORTS_MAX * FX_OPS_WATCH_WEIGHT)
EXT_RAM_BSS_ATTR static uint8_t  s_ow_st[OW_MAX], s_ow_len[OW_MAX], s_ow_n, s_ow_i, s_ow_last;   // OPS clusters
static bool s_sn_prime = true;                  // the next sense only records

static uint32_t rnd(uint32_t lo, uint32_t hi) { return lo + esp_random() % (hi - lo + 1); }
static uint16_t jit(uint32_t ms) { return (uint16_t)(ms * rnd(100 - FX_JITTER_PCT, 100 + FX_JITTER_PCT) / 100u); }

static bool fx_busy(lv_obj_t *o)
{
    for (int l = 0; l < FX_LANES; l++)
        for (int k = 0; k < s_fx[l].n; k++) if (s_fx[l].o[k] == o) return true;
    return false;
}

// Items, per page: OPS the port index; TRAPS row * 4 + part (dot, tag, bar,
// track); WIRES cell * 2 + part (bar, name); NET 0..8 values, 9..17 names;
// DEV the row.
static lv_obj_t *fx_obj(int it, uint8_t *part)
{
    *part = FX_TEXT;
    switch (s_cur) {
    case PG_OPS:   return it < s_nports ? s_ports[it].l : NULL;
    case PG_TRAPS: {
        *part = FX_BG;
        lv_obj_t *const o[4] = { s_tr_dot[it / 4], s_tr_tag[it / 4], s_tr_fill[it / 4], s_tr_track[it / 4] };
        if (it % 4 == 2 && lv_obj_get_width(o[2]) <= 0) return NULL;      // no hits on the bar yet
        return o[it % 4];
    }
    case PG_WIRES: if (!(it & 1)) { *part = FX_BG; return s_wi_bar[it / 2]; } return s_wi_nm[it / 2];
    case PG_NET:   return it < 9 ? s_nl_v[it] : s_nl_k[it - 9];
    case PG_DEV:   return s_dv_open || it >= s_ntalk ? NULL : s_dv_nm[it];
    default:       return NULL;
    }
}

// The item's normal colours.
static void fx_rest(int it)
{
    switch (s_cur) {
    case PG_OPS: {
        lc_port_t *p = &s_ports[it];
        p->lit = p->hit;
        lv_obj_set_style_text_color(p->l, grp_col(p->grp), 0);
        lv_obj_set_style_text_opa(p->l, p->hit ? LV_OPA_COVER : DIM_OPA, 0);
        break;
    }
    case PG_TRAPS: {
        int i = it / 4;
        if (it % 4 == 0)      lv_obj_set_style_bg_color(s_tr_dot[i], LCARS_COL(c6), 0);
        else if (it % 4 == 1) lv_obj_set_style_bg_color(s_tr_tag[i], LCARS_COL(c6), 0);
        else if (it % 4 == 2) lv_obj_set_style_bg_color(s_tr_fill[i], LCARS_COL(c1), 0);
        else                  lv_obj_set_style_bg_color(s_tr_track[i], LCARS_COL(track), 0);
        break;
    }
    case PG_WIRES: wire_part_style(it / 2, it & 1); break;
    case PG_NET:
        if (it < 9) lv_obj_set_style_text_color(s_nl_v[it], LCARS_COL(c2), 0);
        else        lv_obj_set_style_text_color(s_nl_k[it - 9], LCARS_COL(c4), 0);
        break;
    case PG_DEV: lv_obj_set_style_text_color(s_dv_nm[it], LCARS_COL(c2), 0); break;
    default: break;
    }
}

static void fx_paint(fx_t *f)
{
    for (int k = 0; k < f->n; k++) {
        int idx = (int)f->st - k * (int)f->lag;
        uint8_t p = idx >= 0 && idx < f->plen ? f->pct[idx] : 0;
        if (p == f->lvl[k]) continue;                   // unchanged: no repaint
        f->lvl[k] = p;
        if (!p) { fx_rest(f->item[k]); continue; }
        lv_color_t c = lv_color_mix(f->tone[k], f->base[k], (lv_opa_t)(p * 255u / 100u));
        if (f->part[k] == FX_BG) lv_obj_set_style_bg_color(f->o[k], c, 0);
        else {
            lv_opa_t b = f->base_opa[k];
            lv_obj_set_style_text_color(f->o[k], c, 0);
            lv_obj_set_style_text_opa(f->o[k], (lv_opa_t)(b + (LV_OPA_COVER - b) * p / 100u), 0);
        }
    }
}

static void fx_end(fx_t *f)
{
    int n = f->n;
    f->n = 0;                           // idle before the restore: ops_refresh's port test
    for (int k = 0; k < n; k++) if (f->lvl[k]) fx_rest(f->item[k]);
    lv_timer_pause(f->tm);
    f->idle_at = lv_tick_get();
    f->gap = rnd(FX_GAP_MIN_MS, FX_GAP_MAX_MS);
}

// Up and back over `steps` steps of `step` ms, to `peak` %.
static void fx_hill(fx_t *f, uint32_t steps, uint32_t step, uint32_t peak)
{
    uint32_t half = steps / 2;
    f->plen = (uint8_t)steps;
    for (uint32_t s = 0; s < steps; s++) {
        f->pct[s] = (uint8_t)(s < half ? (s + 1) * peak / half : (steps - s - 1) * peak / half);
        f->ms[s] = (uint16_t)step;
    }
}

// The effect's shape: its tone, the per-object profile and each step's length.
static uint32_t fx_shape(fx_t *f, uint8_t kind)
{
    static const uint8_t RIPPLE[] = { 100, 60, 25 }, SWEEP[] = { 100, 55, 20 }, SCAN[] = { FX_WATCH_PEAK, 35, 15 };
    _Static_assert(sizeof(SCAN) == sizeof(RIPPLE), "SCAN: as long as RIPPLE (FX_STEP_MAX check)");
    static const uint8_t PULSE[] = { FX_PULSE_PEAK / 2, FX_PULSE_PEAK, FX_PULSE_PEAK / 2, 0,
                                     FX_PULSE_PEAK / 2, FX_PULSE_PEAK, FX_PULSE_PEAK / 2 };
    _Static_assert(1 + 2 * FX_FLASHES <= FX_STEP_MAX && FX_GLOW_STEPS <= FX_STEP_MAX
                   && sizeof(RIPPLE) + FX_OBJS - 1 <= FX_STEP_MAX, "FX_STEP_MAX: too small");
    f->lag = 0;
    switch (kind) {
    case EF_DECAY:
        f->plen = 1 + 2 * FX_FLASHES;
        f->pct[0] = 100;
        f->ms[0] = jit(FX_SOLID_MS);
        for (int k = 0; k < FX_FLASHES; k++) {
            f->pct[1 + 2 * k] = 0;
            f->ms[1 + 2 * k] = jit(FX_FLASH_OFF_MS);
            f->pct[2 + 2 * k] = FX_FLASH_PCT[k];
            f->ms[2 + 2 * k] = jit(FX_FLASH_ON_MS);
        }
        return LCARS_PAL->hi;
    case EF_GLOW: {
        bool slow = s_cur == PG_NET || s_cur == PG_DEV;
        fx_hill(f, FX_GLOW_STEPS, (slow ? rnd(FX_GLOW_SLOW_MIN_MS, FX_GLOW_SLOW_MAX_MS)
                                        : rnd(FX_GLOW_MIN_MS, FX_GLOW_MAX_MS)) / FX_GLOW_STEPS, 100);
        return LCARS_PAL->c2;
    }
    case EF_WATCH:
        fx_hill(f, FX_GLOW_STEPS, jit(FX_WATCH_MS) / FX_GLOW_STEPS, FX_WATCH_PEAK);
        return LCARS_PAL->hi;
    case EF_SCAN:
        f->plen = sizeof(SCAN);
        memcpy(f->pct, SCAN, sizeof(SCAN));
        f->lag = 1;
        for (int s = 0; s < FX_STEP_MAX; s++) f->ms[s] = (uint16_t)rnd(FX_SCAN_MIN_MS, FX_SCAN_MAX_MS);
        return LCARS_PAL->hi;
    case EF_RIPPLE:
    case EF_SWEEP:
        f->plen = sizeof(RIPPLE);
        memcpy(f->pct, kind == EF_RIPPLE ? RIPPLE : SWEEP, sizeof(RIPPLE));
        f->lag = 1;
        for (int s = 0; s < FX_STEP_MAX; s++)
            f->ms[s] = (uint16_t)(kind == EF_RIPPLE ? rnd(FX_RIPPLE_MIN_MS, FX_RIPPLE_MAX_MS)
                                                    : rnd(FX_SWEEP_MIN_MS, FX_SWEEP_MAX_MS));
        return LCARS_PAL->c5;
    case EF_TICK:
        f->plen = 1;
        f->pct[0] = 100;
        f->ms[0] = jit(FX_TICK_MS);
        return LCARS_PAL->c4;
    default:                                            // EF_PULSE
        f->plen = sizeof(PULSE);
        memcpy(f->pct, PULSE, sizeof(PULSE));
        for (int s = 0; s < (int)sizeof(PULSE); s++) f->ms[s] = (uint16_t)rnd(FX_PULSE_MIN_MS, FX_PULSE_MAX_MS);
        return LCARS_PAL->hi;
    }
}

static void fx_play(fx_t *f, const fxq_t *q)
{
    uint8_t n = 0;
    for (int k = 0; k < q->n && n < FX_OBJS; k++) {
        uint8_t part;
        lv_obj_t *o = fx_obj(q->item[k], &part);
        if (!o || fx_busy(o)) continue;                 // the other lane has it
        f->o[n] = o;
        f->item[n] = q->item[k];
        f->part[n] = part;
        f->lvl[n] = 0;
        f->base[n] = part == FX_BG ? lv_obj_get_style_bg_color(o, LV_PART_MAIN)
                                   : lv_obj_get_style_text_color(o, LV_PART_MAIN);
        f->base_opa[n] = lv_obj_get_style_text_opa(o, LV_PART_MAIN);
        n++;
    }
    if (!n) return;
    lv_color_t tone = lv_color_hex(fx_shape(f, q->kind)), hi = LCARS_COL(hi);
    for (int k = 0; k < n; k++) f->tone[k] = f->base[k].full == tone.full ? hi : tone;
    f->steps = (uint8_t)(f->plen + (n - 1) * f->lag);
    uint32_t sig = 0;
    for (int s = 0; s < f->steps; s++) sig = sig * 31u + f->ms[s];
    if (sig == s_fx_sig[q->kind]) { f->ms[0] += 7; sig += 7; }      // never twice at one timing
    s_fx_sig[q->kind] = sig;
    f->st = 0;
    f->n = n;
    fx_paint(f);
    lv_timer_set_period(f->tm, f->ms[0]);
    lv_timer_reset(f->tm);
    lv_timer_resume(f->tm);
}

static void fx_cb(lv_timer_t *t)
{
    fx_t *f = t->user_data;
    if (!f->n) { lv_timer_pause(t); return; }
    if (!s_green || ++f->st >= f->steps) { fx_end(f); return; }
    fx_paint(f);
    lv_timer_set_period(t, f->ms[f->st]);
}

static void fx_stop_all(void)
{
    for (int l = 0; l < FX_LANES; l++) if (s_fx[l].n) fx_end(&s_fx[l]);
    s_q_n = 0;
    s_sn_prime = true;
    s_wo_n = 0;                                 // a fresh watch order, the first one a full wait away
    s_wo_last = 0xff;
    s_watch_at = lv_tick_get();
    s_watch_gap = rnd(FX_OPS_WATCH_MIN_MS, FX_OPS_WATCH_MAX_MS);   // the first wait, on any page
}

// Queue an effect on the shown page; an element already waiting is not
// queued again (a burst coalesces), nor anything once the queue is full.
static void fxq_push(uint8_t kind, const int16_t *item, int n)
{
    if (!s_green || s_sn_prime || n <= 0 || s_q_n >= FX_Q) return;
    for (int k = 0; k < s_q_n; k++) if (s_q[(s_q_head + k) % FX_Q].item[0] == item[0]) return;
    fxq_t *q = &s_q[(s_q_head + s_q_n++) % FX_Q];
    q->kind = kind;
    q->n = (uint8_t)(n > FX_OBJS ? FX_OBJS : n);
    memcpy(q->item, item, sizeof(item[0]) * q->n);
}

static void fxq_one(uint8_t kind, int it) { int16_t v = (int16_t)it; fxq_push(kind, &v, 1); }
static void fxq_two(uint8_t kind, int a, int b) { int16_t v[2] = { (int16_t)a, (int16_t)b }; fxq_push(kind, v, 2); }

// ── Motion: what moved ────────────────────────────────────────────────────────

EXT_RAM_BSS_ATTR static struct {
    uint32_t trap[LC_TRAPS], wire[LC_WIRES];
    uint16_t disc_port[16];
    uint32_t disc[16];
    uint32_t rt_rx, rt_c[7], flow, ph_sync, mt_poll, sd_lines, dc_posted, cam_seq;
    uint8_t  bssid[6];
    int8_t   rssi;
    bool     clock;
    uint8_t  dv_mac[LC_DEVS][6];
    uint32_t dv_pk[LC_DEVS];
    int      dv_n;
} s_sn;
EXT_RAM_BSS_ATTR static pihole_status_t   s_sn_ph;     // PSRAM: large
EXT_RAM_BSS_ATTR static mikrotik_status_t s_sn_mt;

static bool moved(uint32_t cur, uint32_t *prev)
{
    bool m = cur > *prev;
    *prev = cur;
    return m;
}

static int port_idx(uint16_t port)
{
    for (int i = 0; i < s_nports; i++) if (s_ports[i].port == port) return i;
    return -1;
}

// OPS. A port fires on an event that names it or whose trap maps to it
// (s_port_ev, from lcars_event(): MNDP and MAC-Telnet included, as their
// decoys log events; mt_decoy has no packet counter), on discovery packets
// (discovery_port_packets()), router syslog lines on ROUTER_SYSLOG_PORT
// (router_trip_status_t.received) and IPFIX records on ROUTER_IPFIX_PORT
// (router_flow_counters()). One port: EF_DECAY for an event, else EF_GLOW.
// Several in one sense: one EF_RIPPLE over them, then the first one's
// neighbours (the table is 2 columns: i ^ 1 beside, i +/- 2 above and below).
static void sense_ops(void)
{
    uint8_t why[LC_PORTS_MAX] = { 0 };          // 1 packets, 2 an event
    for (int i = 0; i < s_nports; i++) if (s_port_ev[i]) why[i] = 2;
    uint16_t pp[16];
    uint32_t pk[16];
    int n = discovery_port_packets(pp, pk, 16);
    for (int k = 0; k < n; k++) {
        int i = port_idx(pp[k]);
        if (moved(pk[k], &s_sn.disc[k]) && pp[k] == s_sn.disc_port[k] && i >= 0 && !why[i]) why[i] = 1;
        s_sn.disc_port[k] = pp[k];
    }
    router_trip_status_t r;
    router_trip_get_status(&r);
    int i = port_idx(ROUTER_SYSLOG_PORT);
    if (moved(r.received, &s_sn.rt_rx) && i >= 0 && !why[i]) why[i] = 1;
    uint32_t rec, drop;
    router_flow_counters(&rec, &drop);
    i = port_idx(ROUTER_IPFIX_PORT);
    if (moved(rec, &s_sn.flow) && i >= 0 && !why[i]) why[i] = 1;

    int16_t mv[LC_PORTS_MAX];
    int m = 0, ev = 0;
    for (i = 0; i < s_nports; i++) if (why[i]) { mv[m++] = (int16_t)i; ev |= why[i]; }
    if (!m) return;
    if (m == 1) { fxq_push(ev & 2 ? EF_DECAY : EF_GLOW, mv, 1); return; }
    // Several: up to FX_OPS_SECTIONS ripples, so the two lanes can play them
    // at once. A section is a moved port, the other moved ports in its row or
    // the rows next to it, then its neighbours; the next section starts at
    // the first moved port no section has taken.
    bool used[LC_PORTS_MAX] = { 0 };
    for (int sct = 0; sct < FX_OPS_SECTIONS; sct++) {
        int seed = -1;
        for (int k = 0; k < m && seed < 0; k++) if (!used[mv[k]]) seed = mv[k];
        if (seed < 0) break;
        int16_t v[FX_OBJS];
        int n = 0;
        v[n++] = (int16_t)seed;
        used[seed] = true;
        for (int k = 0; k < m && n < FX_OBJS; k++) {
            int p = mv[k], d = p / 2 - seed / 2;
            if (!used[p] && d >= -1 && d <= 1) { v[n++] = (int16_t)p; used[p] = true; }
        }
        const int nb[3] = { seed ^ 1, seed - 2, seed + 2 };
        for (int k = 0; k < 3 && n < FX_OBJS; k++)
            if (nb[k] >= 0 && nb[k] < s_nports && !used[nb[k]]) { v[n++] = (int16_t)nb[k]; used[nb[k]] = true; }
        fxq_push(EF_RIPPLE, v, n);
    }
}

// TRAPS: a row's hits today (s_t.trap[].n, from lcars_event()) went up: an
// EF_SWEEP along the row for a connection; SHELL SESSIONS (shell commands)
// an EF_DECAY on its dot and tag.
static void sense_traps(void)
{
    for (int i = 0; i < LC_TRAPS; i++) {
        if (!moved(s_t.trap[i].n, &s_sn.trap[i])) continue;
        if (i == TR_SHELL) { fxq_two(EF_DECAY, i * 4, i * 4 + 1); continue; }
        int16_t v[4] = { (int16_t)(i * 4), (int16_t)(i * 4 + 1), (int16_t)(i * 4 + 2), (int16_t)(i * 4 + 3) };
        fxq_push(EF_SWEEP, v, 4);
    }
}

// WIRES: a cell's hits today (s_t.wire[].n) went up: EF_DECAY on its bar and
// name. The router cells' names also glow (EF_GLOW) when router_trip's line
// counters for them move: c_login_fail ROUTER LOGIN FAIL, c_mgmt ROUTER MGMT
// PORT, c_psd ROUTER PORT SCAN, c_dns DNS BYPASS, c_dhcp NEW DEVICE, c_login
// and c_change ROUTER CONFIG.
static void sense_wires(void)
{
    bool hit[LC_WIRES];
    for (int i = 0; i < LC_WIRES; i++) {
        hit[i] = moved(s_t.wire[i].n, &s_sn.wire[i]);
        if (hit[i]) fxq_two(EF_DECAY, i * 2, i * 2 + 1);
    }
    router_trip_status_t r;
    router_trip_get_status(&r);
    const uint32_t c[7] = { r.c_login_fail, r.c_mgmt, r.c_psd, r.c_dns, r.c_dhcp, r.c_login, r.c_change };
    const int cell[7] = { WI_ROUTER0, WI_ROUTER0 + 1, WI_ROUTER0 + 2, WI_ROUTER0 + 3, WI_NEWDEV, WI_CONFIG, WI_CONFIG };
    for (int k = 0; k < 7; k++)
        if (moved(c[k], &s_sn.rt_c[k]) && !hit[cell[k]] && s_wi_st[cell[k]] != WS_OFF) fxq_one(EF_GLOW, cell[k] * 2 + 1);
}

// NET: a cell's value and name, when its source updates.
static void sense_net(void)
{
    wifi_ap_record_t ap;
    if (wifi_manager_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        bool roam = memcmp(ap.bssid, s_sn.bssid, 6) != 0;                   // ACCESS POINT: a roam, EF_PULSE
        int d = (int)ap.rssi - s_sn.rssi;
        if (roam) { memcpy(s_sn.bssid, ap.bssid, 6); fxq_two(EF_PULSE, 0, 9); }
        else if (d >= FX_RSSI_DB || d <= -FX_RSSI_DB) fxq_two(EF_TICK, 0, 9);   // or an RSSI change, EF_TICK
        if (roam || d >= FX_RSSI_DB || d <= -FX_RSSI_DB) s_sn.rssi = ap.rssi;
    }
    bool set = time(NULL) >= 1600000000;                                    // CLOCK: SNTP first set it (no
    if (set && !s_sn.clock) fxq_two(EF_PULSE, 1, 10);                       //   sync counter), EF_PULSE
    s_sn.clock = set;
    pihole_get_status(&s_sn_ph);                                            // PI-HOLE: syncs, EF_TICK (no
    if (moved(s_sn_ph.syncs, &s_sn.ph_sync)) fxq_two(EF_TICK, 3, 12);      //   dns_log on this tree)
    mikrotik_get_status(&s_sn_mt);                                          // ROUTER: polls, EF_TICK
    if (moved(s_sn_mt.polls, &s_sn.mt_poll)) fxq_two(EF_TICK, 4, 13);
    uint32_t rec, drop;                                                     // IPFIX: records, EF_GLOW
    router_flow_counters(&rec, &drop);
    if (moved(rec, &s_sn.flow)) fxq_two(EF_GLOW, 5, 14);
    sd_status_t sd;                                                         // MICROSD: lines_written, EF_TICK
    sd_log_status(&sd);
    if (moved(sd.lines_written, &s_sn.sd_lines)) fxq_two(EF_TICK, 6, 15);
    cam_meta_t cm;                                                          // CAMERA: a snapshot (seq), EF_PULSE
    if (cam_last_meta(&cm) && moved(cm.seq, &s_sn.cam_seq)) fxq_two(EF_PULSE, 7, 16);
    discord_status_t dc;                                                    // DISCORD: posted, EF_PULSE
    discord_get_status(&dc);
    if (moved(dc.posted, &s_sn.dc_posted)) fxq_two(EF_PULSE, 8, 17);
}

// DEV: a listed device's packet count (discovery_talker_t.packets, as
// dev_refresh() last read it) went up: EF_GLOW on its name.
static void sense_dev(void)
{
    for (int i = 0; i < s_ntalk; i++) {
        for (int k = 0; k < s_sn.dv_n; k++)
            if (!memcmp(s_sn.dv_mac[k], s_talk[i].mac, 6)) {
                if (s_talk[i].packets > s_sn.dv_pk[k]) fxq_one(EF_GLOW, i);
                break;
            }
    }
    s_sn.dv_n = s_ntalk;
    for (int i = 0; i < s_ntalk; i++) { memcpy(s_sn.dv_mac[i], s_talk[i].mac, 6); s_sn.dv_pk[i] = s_talk[i].packets; }
}

static void fx_sense(void)
{
    switch (s_cur) {
    case PG_OPS:   sense_ops();   break;
    case PG_TRAPS: sense_traps(); break;
    case PG_WIRES: sense_wires(); break;
    case PG_NET:   sense_net();   break;
    case PG_DEV:   sense_dev();   break;
    default: break;
    }
    memset(s_port_ev, 0, sizeof(s_port_ev));
    s_sn_prime = !s_green;                      // under an alert view: keep recording only
}

// True if a lane is playing one of the entry's elements.
static bool fxq_taken(const fxq_t *q)
{
    for (int k = 0; k < q->n; k++) {
        uint8_t part;
        lv_obj_t *o = fx_obj(q->item[k], &part);
        if (o && fx_busy(o)) return true;
    }
    return false;
}

// The watch pass: the next listener in a shuffled order (a new order once
// all have had their turn, never starting with the one just watched), as
// an item: a TRAPS row's tag, an armed WIRES cell's bar. -1: none free.
static void watch_shuffle(int n)
{
    for (int i = 0; i < n; i++) s_wo[i] = (uint8_t)i;
    for (int i = n - 1; i > 0; i--) {
        int j = (int)rnd(0, (uint32_t)i);
        uint8_t x = s_wo[i]; s_wo[i] = s_wo[j]; s_wo[j] = x;
    }
    if (n > 1 && s_wo[0] == s_wo_last) { uint8_t x = s_wo[0]; s_wo[0] = s_wo[1]; s_wo[1] = x; }
    s_wo_n = (uint8_t)n;
    s_wo_i = 0;
}

static int watch_next(void)
{
    int n = s_cur == PG_TRAPS ? LC_TRAPS : s_cur == PG_WIRES ? LC_WIRES : 0;
    for (int tries = 0; tries < n; tries++) {
        if (s_wo_n != n || s_wo_i >= s_wo_n) watch_shuffle(n);
        int i = s_wo[s_wo_i++];
        s_wo_last = (uint8_t)i;
        if (s_cur == PG_WIRES && s_wi_st[i] == WS_OFF) continue;    // off cells never glow
        int it = s_cur == PG_TRAPS ? i * 4 + 1 : i * 2;
        uint8_t part;
        lv_obj_t *o = fx_obj(it, &part);
        if (o && !fx_busy(o)) return it;
    }
    return -1;
}

// OPS watch pass. The table is cut into clusters of 2 to 5 neighbouring
// cells (consecutive in the 2-column table, inside one group; a group of
// one port is a cluster of one), each TRAP and WIRE cluster listed
// FX_OPS_WATCH_WEIGHT times and each NET one once, then shuffled, no
// cluster twice running. A new cut and order once the list is used up.
static void ops_watch_plan(void)
{
    uint8_t st[LC_PORTS_MAX], ln[LC_PORTS_MAX];
    int nc = 0;
    for (int i = 0; i < s_nports;) {
        int end = i;
        while (end < s_nports && s_ports[end].grp == s_ports[i].grp) end++;
        while (i < end) {
            int rem = end - i, len = (int)rnd(2, FX_OBJS);
            if (len > rem) len = rem;
            if (rem - len == 1) len = len < FX_OBJS ? len + 1 : len - 1;   // never leave one behind
            st[nc] = (uint8_t)i;
            ln[nc++] = (uint8_t)len;
            i += len;
        }
    }
    s_ow_n = 0;
    for (int c = 0; c < nc; c++)
        for (int w = s_ports[st[c]].grp == GRP_NET ? 1 : FX_OPS_WATCH_WEIGHT; w > 0 && s_ow_n < OW_MAX; w--) {
            s_ow_st[s_ow_n] = st[c];
            s_ow_len[s_ow_n++] = ln[c];
        }
    for (int i = s_ow_n - 1; i > 0; i--) {
        int j = (int)rnd(0, (uint32_t)i);
        uint8_t a = s_ow_st[i], b = s_ow_len[i];
        s_ow_st[i] = s_ow_st[j]; s_ow_len[i] = s_ow_len[j];
        s_ow_st[j] = a; s_ow_len[j] = b;
    }
    for (int i = 0; i < s_ow_n; i++) {                  // a repeat: swap in a later one
        uint8_t prev = i ? s_ow_st[i - 1] : s_ow_last;
        for (int j = i + 1; j < s_ow_n && s_ow_st[i] == prev; j++) {
            if (s_ow_st[j] == prev) continue;
            uint8_t a = s_ow_st[i], b = s_ow_len[i];
            s_ow_st[i] = s_ow_st[j]; s_ow_len[i] = s_ow_len[j];
            s_ow_st[j] = a; s_ow_len[j] = b;
        }
    }
    s_ow_i = 0;
}

// The next cluster: all its cells glow together (EF_WATCH) or a soft
// ripple runs through them (EF_SCAN), one or the other at random.
static void ops_watch(fx_t *f)
{
    if (s_nports <= 0) return;
    if (s_ow_i >= s_ow_n) ops_watch_plan();
    if (!s_ow_n) return;
    fxq_t q = { .kind = rnd(0, 1) ? EF_WATCH : EF_SCAN, .n = s_ow_len[s_ow_i] };
    s_ow_last = s_ow_st[s_ow_i];
    for (int k = 0; k < q.n; k++) q.item[k] = (int16_t)(s_ow_st[s_ow_i] + k);
    s_ow_i++;
    fx_play(f, &q);
}

static void fx_spawn_cb(lv_timer_t *t)
{
    (void)t;
    if (lv_tick_elaps(s_sense_at) >= FX_SENSE_MS) { s_sense_at = lv_tick_get(); fx_sense(); }
    if (!s_green || s_splash) return;
    bool ops = s_cur == PG_OPS;
    for (int l = 0; l < FX_LANES; l++) {                // real activity first
        fx_t *f = &s_fx[l];
        if ((ops && l == FX_WATCH_LANE) || f->n || lv_tick_elaps(f->idle_at) < f->gap) continue;
        for (int j = 0; j < s_q_n; j++) {
            fxq_t q = s_q[(s_q_head + j) % FX_Q];
            if (fxq_taken(&q)) continue;
            for (int k = j; k + 1 < s_q_n; k++) s_q[(s_q_head + k) % FX_Q] = s_q[(s_q_head + k + 1) % FX_Q];
            s_q_n--;
            fx_play(f, &q);
            break;
        }
    }
    if (lv_tick_elaps(s_watch_at) < s_watch_gap) return;
    if (ops) {                                          // OPS: the watch lane, its own cadence
        if (s_fx[FX_WATCH_LANE].n) return;
        s_watch_at = lv_tick_get();
        s_watch_gap = rnd(FX_OPS_WATCH_MIN_MS, FX_OPS_WATCH_MAX_MS);
        ops_watch(&s_fx[FX_WATCH_LANE]);
        return;
    }
    if (s_cur != PG_TRAPS && s_cur != PG_WIRES) return;
    for (int l = 0; l < FX_LANES; l++) {                // then the watch, on a free lane
        if (s_fx[l].n) continue;
        s_watch_at = lv_tick_get();
        s_watch_gap = rnd(FX_WATCH_MIN_MS, FX_WATCH_MAX_MS);
        int it = watch_next();
        if (it >= 0) {
            fxq_t q = { .kind = EF_WATCH, .n = 1, .item = { (int16_t)it } };
            fx_play(&s_fx[l], &q);
        }
        return;
    }
}

// DEV activity bars: each tick the fill moves a third of the way to its
// target (at least 1 px); every DV_SEG_MS the segment moves by the time
// passed at its row's speed, and re-enters from the left after the end.
static void dev_bars(void)
{
    uint32_t dt = lv_tick_elaps(s_dv_seg_at);
    bool move = dt >= DV_SEG_MS;
    if (move) s_dv_seg_at = lv_tick_get();
    if (dt > 4 * DV_SEG_MS) dt = DV_SEG_MS;                 // back from another page: no jump
    for (int i = 0; i < LC_DEVS && i < s_ntalk; i++) {
        lv_coord_t w = lv_obj_get_width(s_dv_fill[i]), d = s_dv_tgt[i] - w;
        if (d) {
            lv_coord_t step = d / 3;
            if (!step) step = d > 0 ? 1 : -1;
            lv_obj_set_width(s_dv_fill[i], w + step);
        }
        if (!move || lv_obj_has_flag(s_dv_seg[i], LV_OBJ_FLAG_HIDDEN)) continue;
        uint32_t pxs = DV_SEG_MIN_PXS + (DV_SEG_MAX_PXS - DV_SEG_MIN_PXS) * s_dv_pct[i] / 100u;
        s_dv_pos[i] += (int32_t)(pxs * 16u * dt / 1000u);
        if (s_dv_pos[i] >= DV_BAR_W * 16) s_dv_pos[i] -= (DV_BAR_W + DV_SEG_W) * 16;
        lv_coord_t x = (lv_coord_t)(s_dv_pos[i] / 16);
        if (x != lv_obj_get_style_x(s_dv_seg[i], LV_PART_MAIN)) lv_obj_set_x(s_dv_seg[i], x);
    }
}

// NET gauges: a third of the way to the target each tick (at least 1 px),
// so empty to full takes about 12 ticks (0.6 s).
static void gauges_ease(void)
{
    for (int i = 0; i < G_N; i++) {
        lv_coord_t h = lv_obj_get_height(s_g_fill[i]), d = s_g_tgt[i] - h;
        if (!d) continue;
        lv_coord_t step = d / 3;
        if (!step) step = d > 0 ? 1 : -1;
        h += step;
        lv_obj_set_height(s_g_fill[i], h);
        lv_obj_set_y(s_g_fill[i], G_H - h);
    }
}

static void anim_cb(lv_timer_t *t)
{
    (void)t;
    if (!s_green || s_splash) return;
    if (s_cur == PG_NET) gauges_ease();
    else if (s_cur == PG_DEV && !s_dv_open) dev_bars();
}

// ── Pages ─────────────────────────────────────────────────────────────────────

static void page_refresh(bool force)
{
    switch (s_cur) {
    case PG_OPS:   ops_refresh(force);   break;
    case PG_TRAPS: traps_refresh(force); break;
    case PG_WIRES: wires_refresh(force); break;
    case PG_NET:   net_refresh(force);   break;
    case PG_DEV:   dev_refresh(force);   break;
    default: break;
    }
}

static void page_show(int p)
{
    if (p < 0 || p >= PAGES) p = PG_OPS;
    fx_stop_all();
    if (p == PG_DEV && s_cur != PG_DEV) { s_dv_open = false; show(s_dv_list, true); show(s_dv_det, false); }
    s_cur = p;
    s_page_at = lv_tick_get();
    for (int i = 0; i < PAGES; i++) show(s_page[i], i == p);
    marks_update();
    title_set(ALARM_COND_GREEN);
    page_refresh(true);
    EXT_RAM_BSS_ATTR static bool measured[PAGES];            // the first show of each page after boot
    static const char *const WHAT[PAGES] = {
        "LCARS OPS, scan line and port clusters", "LCARS TRAPS, watch pass and row sweeps",
        "LCARS TRIPWIRES, watch pass and cell flashes", "LCARS NET, gauges and label flashes",
        "LCARS DEVICES, activity bars",
    };
    if (!measured[p] && !s_splash) {
        measured[p] = true;
        ui_refr_measure(WHAT[p]);
    }
}

static void fast_cb(lv_timer_t *t)
{
    (void)t;
    if (!s_green || s_splash || s_cur != PG_OPS) return;
    s_scan_x = (s_scan_x + SCAN_STEP) % CH_W;
    lv_obj_set_x(s_scan, (lv_coord_t)(CH_X + s_scan_x));
}

static void slow_cb(lv_timer_t *t)
{
    (void)t;
    if (!lv_obj_has_flag(s_root, LV_OBJ_FLAG_HIDDEN)) {
        char b[12];
        fmt_hm((uint32_t)time(NULL), b, sizeof(b));
        set_text(s_clock, b);
    }
    if (!s_green || s_splash) return;
    if (s_auto && lv_tick_elaps(s_page_at) >= (uint32_t)settings_get()->panel_rotate_s * 1000u) { page_show((s_cur + 1) % PAGES); return; }
    if (lv_tick_elaps(s_data_at) >= DATA_MS) { s_data_at = lv_tick_get(); page_refresh(false); }
    if (s_cur == PG_OPS && lv_tick_elaps(s_focus_at) >= FOCUS_MS) {
        s_focus_at = lv_tick_get();
        s_focus = (s_focus + 1) % 4;
        focus_update();
    }
}

// ── Boot splash ───────────────────────────────────────────────────────────────
//
// At every boot and on a switch to this style (lcars_view() showing GREEN on
// a hidden panel), from docs/mockups/about-boot.html: the logo (native size,
// centred, its foot at y 240) and "SHADOWSENTRY S3" fade in, hold, fade out;
// the frame's pieces roll in from their edges SP_PIECE_GAP_MS apart; then the
// page fades in a band at a time (a whole-content fade would be one 400 x 282
// repaint a frame, about 113k px; a band is a quarter of that). Every motion
// is an lv_anim on position or opacity, at the display's 30 ms refresh. Any
// alert, or the dashboard style, cuts it short (splash_stop()).
//
// At boot the card is waited for (up to SP_CARD_WAIT_MS) so an uploaded logo
// can show; the logo is decoded once, here, before the fade.

#define SP_CARD_WAIT_MS 1500
#define SP_LOGO_FADE_MS 700
#define SP_LOGO_HOLD_MS 1500
#define SP_LOGO_FOOT_Y  240
#define SP_CAP_Y        246
#define SP_PIECE_GAP_MS 60
#define SP_PIECE_MS     280
#define SP_BANDS        4
#define SP_BAND_MS      120

EXT_RAM_BSS_ATTR static lv_obj_t   *s_sp_logo, *s_sp_cap, *s_sp_band[SP_BANDS];
EXT_RAM_BSS_ATTR static lv_timer_t *s_sp_wait;
EXT_RAM_BSS_ATTR static uint32_t    s_sp_at;

// v 0..256: from the piece's edge (0) to its place (256).
static void sp_piece_cb(void *var, int32_t v)
{
    sp_piece_t *p = var;
    lv_obj_set_style_translate_x(p->o, (lv_coord_t)(p->dx * (256 - v) / 256), 0);
    lv_obj_set_style_translate_y(p->o, (lv_coord_t)(p->dy * (256 - v) / 256), 0);
    lv_obj_set_style_opa(p->o, (lv_opa_t)(v > 255 ? 255 : v), 0);
}

static void sp_logo_cb(void *var, int32_t v)
{
    (void)var;
    lv_obj_set_style_opa(s_sp_logo, (lv_opa_t)v, 0);
    lv_obj_set_style_opa(s_sp_cap, (lv_opa_t)v, 0);
}

static void sp_band_cb(void *var, int32_t v) { lv_obj_set_style_bg_opa(var, (lv_opa_t)v, 0); }

static void sp_anim(void *var, lv_anim_exec_xcb_t cb, int32_t from, int32_t to, uint32_t ms, uint32_t delay,
                    lv_anim_ready_cb_t ready)
{
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, var);
    lv_anim_set_exec_cb(&a, cb);
    lv_anim_set_values(&a, from, to);
    lv_anim_set_time(&a, ms);
    lv_anim_set_delay(&a, delay);
    lv_anim_set_path_cb(&a, lv_anim_path_ease_out);
    if (ready) lv_anim_set_ready_cb(&a, ready);
    lv_anim_start(&a);
}

// Everything in its final place, the anims gone.
static void sp_finish(void)
{
    lv_timer_pause(s_sp_wait);
    lv_anim_del(&s_sp_logo, NULL);
    show(s_sp_logo, false);
    show(s_sp_cap, false);
    for (int i = 0; i < s_sp_n; i++) {
        lv_anim_del(&s_sp[i], NULL);
        sp_piece_cb(&s_sp[i], 256);
    }
    for (int k = 0; k < SP_BANDS; k++) {
        lv_anim_del(s_sp_band[k], NULL);
        show(s_sp_band[k], false);
    }
    s_splash = false;
    fx_stop_all();                              // nothing sensed under the splash plays now
    s_page_at = lv_tick_get();                  // AUTO counts from here
    s_sn_prime = true;                          // the motion's first sense only records
}

// Each band hides itself as it ends, so no frame repaints more than one band;
// the last ends the splash.
static void sp_band_done_cb(lv_anim_t *a)
{
    show(a->var, false);
    if (a->var != s_sp_band[SP_BANDS - 1]) return;
    ESP_LOGI(TAG, "Splash done in %u ms", (unsigned)lv_tick_elaps(s_sp_at));
    sp_finish();
}

static void sp_logo_done_cb(lv_anim_t *a)
{
    (void)a;
    show(s_sp_logo, false);
    show(s_sp_cap, false);
    for (int i = 0; i < s_sp_n; i++)
        sp_anim(&s_sp[i], sp_piece_cb, 0, 256, SP_PIECE_MS, (uint32_t)i * SP_PIECE_GAP_MS, NULL);
    uint32_t t = (uint32_t)(s_sp_n - 1) * SP_PIECE_GAP_MS + SP_PIECE_MS;
    for (int k = 0; k < SP_BANDS; k++)
        sp_anim(s_sp_band[k], sp_band_cb, LV_OPA_COVER, LV_OPA_TRANSP, SP_BAND_MS, t + (uint32_t)k * SP_BAND_MS,
                sp_band_done_cb);
    ui_refr_measure("LCARS splash, frame roll-in and content bands");
}

static void sp_logo_start(void)
{
    const lv_img_dsc_t *d = ui_logo_get();
    if (d) {
        lv_img_set_src(s_sp_logo, d);
        lv_coord_t y = SP_LOGO_FOOT_Y - (lv_coord_t)d->header.h;
        lv_obj_set_pos(s_sp_logo, (480 - (lv_coord_t)d->header.w) / 2, y < 0 ? 0 : y);
        show(s_sp_logo, true);
    }
    show(s_sp_cap, true);
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, &s_sp_logo);
    lv_anim_set_exec_cb(&a, sp_logo_cb);
    lv_anim_set_values(&a, LV_OPA_TRANSP, LV_OPA_COVER);
    lv_anim_set_time(&a, SP_LOGO_FADE_MS);
    lv_anim_set_playback_delay(&a, SP_LOGO_HOLD_MS);
    lv_anim_set_playback_time(&a, SP_LOGO_FADE_MS);
    lv_anim_set_ready_cb(&a, sp_logo_done_cb);
    lv_anim_start(&a);
    ui_refr_measure("LCARS splash, logo fade");
}

static void sp_wait_cb(lv_timer_t *t)
{
    sd_status_t sd;
    sd_log_status(&sd);
    if (!sd.mounted && lv_tick_elaps(s_sp_at) < SP_CARD_WAIT_MS) return;
    lv_timer_pause(t);
    sp_logo_start();
}

static void splash_start(void)
{
    s_splash = true;
    s_sp_at = lv_tick_get();
    for (int i = 0; i < s_sp_n; i++) sp_piece_cb(&s_sp[i], 0);
    for (int k = 0; k < SP_BANDS; k++) {
        lv_obj_set_style_bg_opa(s_sp_band[k], LV_OPA_COVER, 0);
        show(s_sp_band[k], true);
    }
    lv_obj_set_style_opa(s_sp_logo, LV_OPA_TRANSP, 0);
    lv_obj_set_style_opa(s_sp_cap, LV_OPA_TRANSP, 0);
    if (ui_logo_tried()) sp_logo_start();
    else { lv_timer_reset(s_sp_wait); lv_timer_resume(s_sp_wait); }
}

static void splash_stop(void)
{
    if (s_splash) sp_finish();
}

static void build_splash(void)
{
    s_sp_logo = lv_img_create(s_root);
    show(s_sp_logo, false);
    s_sp_cap = text(s_root, F12, LCARS_COL(c4), 0, SP_CAP_Y, 480, "SHADOWSENTRY S3");
    lv_obj_set_style_text_align(s_sp_cap, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_letter_space(s_sp_cap, 4, 0);
    show(s_sp_cap, false);
    // A quarter of the content each, over the pages and the alert box.
    for (int k = 0; k < SP_BANDS; k++) {
        lv_coord_t y0 = (lv_coord_t)(LCARS_CONTENT_H * k / SP_BANDS), y1 = (lv_coord_t)(LCARS_CONTENT_H * (k + 1) / SP_BANDS);
        s_sp_band[k] = fill(s_content, 0, y0, LCARS_CONTENT_W, y1 - y0, COL_BLACK);
        show(s_sp_band[k], false);
    }
    s_sp_wait = lv_timer_create(sp_wait_cb, 50, NULL);
    lv_timer_pause(s_sp_wait);
}

// ── Public ────────────────────────────────────────────────────────────────────

void lcars_build(lv_obj_t *scr)
{
    ports_init();
    names_init();
    s_root = fill(scr, 0, 0, 480, 320, COL_BLACK);
    build_frame();
    s_content = area(s_root, LCARS_CONTENT_X, LCARS_CONTENT_Y, LCARS_CONTENT_W, LCARS_CONTENT_H);
    for (int i = 0; i < PAGES; i++) {
        s_page[i] = area(s_content, 0, 0, LCARS_CONTENT_W, LCARS_CONTENT_H);
        show(s_page[i], false);
    }
    build_ops(s_page[PG_OPS]);
    build_traps(s_page[PG_TRAPS]);
    build_wires(s_page[PG_WIRES]);
    build_net(s_page[PG_NET]);
    build_dev(s_page[PG_DEV]);
    s_alert = fill(s_content, 0, 0, LCARS_CONTENT_W, LCARS_CONTENT_H, COL_BLACK);
    show(s_alert, false);
    subsys_build(s_root, subsys_back);
    build_splash();
    show(s_root, false);
    lv_timer_create(fast_cb, SCAN_MS, NULL);
    for (int l = 0; l < FX_LANES; l++) {
        s_fx[l].tm = lv_timer_create(fx_cb, 60, &s_fx[l]);
        lv_timer_pause(s_fx[l].tm);
    }
    lv_timer_create(fx_spawn_cb, 100, NULL);
    lv_timer_create(anim_cb, ANIM_MS, NULL);
    lv_timer_create(slow_cb, 1000, NULL);
    ESP_LOGI(TAG, "Built: %d ports (%d pages), AUTO every %u s", s_nports, PAGES, (unsigned)settings_get()->panel_rotate_s);
}

lv_obj_t *lcars_alert_box(void) { return s_alert; }

void lcars_view(alarm_cond_t c, bool on)
{
    bool green = on && c == ALARM_COND_GREEN;
    if (c == ALARM_COND_GREEN && s_prev_cond != ALARM_COND_GREEN) {  // an incident just closed
        s_secured_cond = s_prev_cond;
        s_secured_at = lv_tick_get();
    } else if (c != ALARM_COND_GREEN) {
        s_secured_cond = ALARM_COND_GREEN;
    }
    s_prev_cond = c;
    bool was_on = !lv_obj_has_flag(s_root, LV_OBJ_FLAG_HIDDEN);
    if (!green) {
        fx_stop_all();                          // the motion pauses under an alert view
        splash_stop();                          // an alert cuts the splash short
        subsys_close(false);                    // and the about screen gives way to it
    }
    show(s_root, on);
    if (!on) { s_green = false; return; }
    show(s_rail, green);
    show(s_alert, !green);
    if (green) {
        if (subsys_shown()) return;             // RETURN brings the page back
        if (!was_on) s_splash = true;           // set first: page_show() then skips its measurement
        if (!s_green) { s_green = true; page_show(s_cur); }
        if (!was_on) splash_start();            // boot, or a switch to this style
        return;
    }
    s_green = false;
    for (int i = 0; i < PAGES; i++) show(s_page[i], false);
    title_set(c);
}
