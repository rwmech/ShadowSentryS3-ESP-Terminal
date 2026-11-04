// Block list for the router to pull. See blocklist.h. Fork addition, Robert Mech.

#include "blocklist.h"
#include "router_trip.h"        // router_trip_parse_ips(), router_trip_router_ip(), ROUTER_* config
#include "mikrotik_watch.h"     // mikrotik_watch_router_ip()
#include "pihole.h"
#include "settings.h"
#include "sd_log.h"
#include "notify.h"
#include "json_esc.h"
#include "wifi_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "BLOCK";

#define NVS_NS      "block"
#define NVS_KEY     "list"

static block_entry_t    *s_list;           // PSRAM, BLOCK_MAX
static int               s_n;
static SemaphoreHandle_t s_lock;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t          s_served, s_last, s_refused;   // under s_mux

static void ip_s(uint32_t ip, char *b, size_t n) { ip4_addr_t a = { .addr = ip }; ip4addr_ntoa_r(&a, b, (int)n); }

const char *blocklist_kind_key(uint8_t kind) { return kind == BLOCK_SRC ? "src" : "dst"; }

bool blocklist_kind_parse(const char *s, block_kind_t *out)
{
    if (!s) return false;
    if (!strcmp(s, "dst")) { *out = BLOCK_DST; return true; }
    if (!strcmp(s, "src")) { *out = BLOCK_SRC; return true; }
    return false;
}

void blocklist_init(void)
{
    s_list = heap_caps_calloc(BLOCK_MAX, sizeof(block_entry_t), MALLOC_CAP_SPIRAM);
    s_lock = xSemaphoreCreateMutex();
    if (!s_list || !s_lock) { ESP_LOGE(TAG, "Block list off: out of memory"); free(s_list); s_list = NULL; return; }
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = BLOCK_MAX * sizeof(block_entry_t);
        if (nvs_get_blob(h, NVS_KEY, s_list, &len) == ESP_OK && len % sizeof(block_entry_t) == 0) {
            s_n = (int)(len / sizeof(block_entry_t));
            for (int i = 0; i < s_n; i++) {
                s_list[i].note[BLOCK_NOTE_MAX - 1] = '\0';
                if (s_list[i].kind > BLOCK_SRC) s_list[i].kind = BLOCK_DST;
            }
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "Block list: %d of %d entries (served to the router at /routeros/block.txt)", s_n, BLOCK_MAX);
}

static esp_err_t save(void)
{
    nvs_handle_t h;
    esp_err_t r = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (r != ESP_OK) return r;
    r = s_n ? nvs_set_blob(h, NVS_KEY, s_list, (size_t)s_n * sizeof(block_entry_t)) : nvs_erase_key(h, NVS_KEY);
    if (r == ESP_ERR_NVS_NOT_FOUND) r = ESP_OK;
    if (r == ESP_OK) r = nvs_commit(h);
    nvs_close(h);
    return r;
}

// ── Never-block ───────────────────────────────────────────────────────────────

typedef struct { uint32_t ip; const char *why; } nb_t;

// The addresses known right now. out holds at least 8 + 2 * SETTINGS_ADMIN_ALLOW_MAX... entries.
static int never_known(nb_t *out, int max)
{
    int n = 0;
#define ADD(a, w) do { uint32_t a_ = (a); if (a_ && n < max) { out[n].ip = a_; out[n].why = (w); n++; } } while (0)
    esp_netif_t *en = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (en && esp_netif_get_ip_info(en, &info) == ESP_OK && info.ip.addr) {
        ADD(info.ip.addr, "this board");
        ADD(info.gw.addr, "the gateway");
        if (info.netmask.addr && info.netmask.addr != 0xffffffffu)
            ADD(info.ip.addr | ~info.netmask.addr, "the subnet's broadcast address");
    }
    ADD(router_trip_router_ip(), "the router");
    ADD(mikrotik_watch_router_ip(), "the router (MikroTik URL)");
    uint32_t tmp[BLOCK_NEVER_EXTRA];
    int k = router_trip_parse_ips(ROUTER_PIHOLE_IP, tmp, 1);
    if (k) ADD(tmp[0], "the Pi-hole");
    pihole_status_t *ps = heap_caps_malloc(sizeof(*ps), MALLOC_CAP_SPIRAM);
    if (ps) {
        pihole_get_status(ps);
        if (ps->ip[0] && router_trip_parse_ips(ps->ip, tmp, 1)) ADD(tmp[0], "the Pi-hole");
        free(ps);
    }
    const settings_t *st = settings_get();
    int na = st->admin_allow_n;
    if (na < 0 || na > SETTINGS_ADMIN_ALLOW_MAX) na = 0;
    for (int i = 0; i < na; i++) ADD(st->admin_allow[i], "on the admin allowlist");
    k = router_trip_parse_ips(ROUTER_ADMIN_IPS, tmp, ROUTER_ADMIN_MAX);
    for (int i = 0; i < k; i++) ADD(tmp[i], "an admin address (ROUTER_ADMIN_IPS)");
    k = router_trip_parse_ips(ROUTER_NEVER_BLOCK, tmp, BLOCK_NEVER_EXTRA);
    for (int i = 0; i < k; i++) ADD(tmp[i], "on ROUTER_NEVER_BLOCK");
#undef ADD
    return n;
}

#define NEVER_CAP (8 + SETTINGS_ADMIN_ALLOW_MAX + ROUTER_ADMIN_MAX + BLOCK_NEVER_EXTRA)

bool blocklist_never(uint32_t ip, char *why, size_t len)
{
    const uint8_t *b = (const uint8_t *)&ip;        // network order
    const char *w = NULL;
    if (b[0] == 0)            w = "0.0.0.0/8 is not an address to block";
    else if (b[0] == 127)     w = "a loopback address";
    else if (b[0] >= 224)     w = "a multicast, reserved or broadcast address";
    if (!w) {
        nb_t nb[NEVER_CAP];
        int n = never_known(nb, NEVER_CAP);
        for (int i = 0; i < n && !w; i++) if (nb[i].ip == ip) w = nb[i].why;
    }
    if (w && why && len) {
        char a[16];
        ip_s(ip, a, sizeof(a));
        snprintf(why, len, "%s is %s: never blocked", a, w);
    }
    return w != NULL;
}

int blocklist_never_list(uint32_t *ip, const char **why, int max)
{
    nb_t nb[NEVER_CAP];
    int n = never_known(nb, NEVER_CAP), o = 0;
    for (int i = 0; i < n && o < max; i++) {
        bool dup = false;
        for (int k = 0; k < o && !dup; k++) dup = ip[k] == nb[i].ip;
        if (dup) continue;
        ip[o] = nb[i].ip;
        why[o] = nb[i].why;
        o++;
    }
    return o;
}

// ── Echo: card and Discord ────────────────────────────────────────────────────

static void echo(const char *event, uint32_t ip, uint8_t kind, const char *note)
{
    char a[16], nj[2 * BLOCK_NOTE_MAX + 8];
    ip_s(ip, a, sizeof(a));
    json_esc(note ? note : "", BLOCK_NOTE_MAX, nj, sizeof(nj));
    uint32_t ts = (uint32_t)time(NULL);
    char *l = heap_caps_malloc(256, MALLOC_CAP_SPIRAM);
    if (l) {
        int n = snprintf(l, 256, "{\"kind\":\"block\",\"ts\":%lu,\"event\":\"%s\",\"ip\":\"%s\",\"block\":\"%s\","
                         "\"note\":\"%s\",\"by\":\"dashboard\"}\n",
                         (unsigned long)ts, event, a, blocklist_kind_key(kind), nj);
        if (n > 0 && n < 256) sd_log_line(l, (size_t)n);
        else free(l);
    }
    char title[NOTIFY_TITLE_MAX], text[NOTIFY_TEXT_MAX];
    bool add = !strcmp(event, "add");
    snprintf(title, sizeof(title), "Block %s: %s %s", add ? "added" : "removed", blocklist_kind_key(kind), a);
    snprintf(text, sizeof(text), "%s%s\nThe router's scheduler picks it up within a minute (tools/routeros/blocklist.rsc).",
             kind == BLOCK_SRC ? "The device's traffic through the router" : "Traffic from the LAN to this address",
             add ? " is dropped." : " is no longer dropped.");
    if (note && note[0]) {
        size_t n = strlen(text);
        snprintf(text + n, sizeof(text) - n, "\nNote: %s", note);
    }
    notify_send(NOTIFY_BLOCK, title, text, add ? NOTIFY_WARN : NOTIFY_INFO);
}

// ── Add, remove, read ─────────────────────────────────────────────────────────

static bool note_ok(const char *s)
{
    if (!s) return true;
    size_t n = strlen(s);
    if (n >= BLOCK_NOTE_MAX) return false;
    for (size_t i = 0; i < n; i++) if (s[i] < 0x20 || s[i] > 0x7e) return false;
    return true;
}

block_result_t blocklist_add(uint32_t ip, block_kind_t kind, const char *note, char *why, size_t len)
{
    if (why && len) why[0] = '\0';
    if (!s_list) { if (why) snprintf(why, len, "block list not available"); return BLOCK_SAVE; }
    if (!note_ok(note)) { if (why) snprintf(why, len, "note: at most 40 printable ASCII characters"); return BLOCK_BAD; }
    if (blocklist_never(ip, why, len)) return BLOCK_NEVER;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int k = -1;
    for (int i = 0; i < s_n; i++) if (s_list[i].ip == ip && s_list[i].kind == kind) k = i;
    if (k < 0 && s_n >= BLOCK_MAX) {
        xSemaphoreGive(s_lock);
        if (why) snprintf(why, len, "the block list is full (%d entries)", BLOCK_MAX);
        return BLOCK_FULL;
    }
    block_entry_t old = { 0 };
    bool fresh = k < 0;
    if (fresh) k = s_n++; else old = s_list[k];
    s_list[k].ip = ip;
    s_list[k].kind = (uint8_t)kind;
    s_list[k].ts = (uint32_t)time(NULL);
    strlcpy(s_list[k].note, note ? note : "", sizeof(s_list[k].note));
    esp_err_t r = save();
    if (r != ESP_OK) {                              // put it back as it was
        if (fresh) s_n--; else s_list[k] = old;
        xSemaphoreGive(s_lock);
        if (why) snprintf(why, len, "not saved: %s", esp_err_to_name(r));
        return BLOCK_SAVE;
    }
    xSemaphoreGive(s_lock);
    char a[16];
    ip_s(ip, a, sizeof(a));
    ESP_LOGW(TAG, "%s %s %s", fresh ? "Blocked" : "Block updated:", blocklist_kind_key(kind), a);
    if (fresh) echo("add", ip, (uint8_t)kind, note);
    return fresh ? BLOCK_OK : BLOCK_UPDATED;
}

block_result_t blocklist_remove(uint32_t ip, block_kind_t kind)
{
    if (!s_list) return BLOCK_SAVE;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int k = -1;
    for (int i = 0; i < s_n; i++) if (s_list[i].ip == ip && s_list[i].kind == kind) k = i;
    if (k < 0) { xSemaphoreGive(s_lock); return BLOCK_NOT_FOUND; }
    block_entry_t gone = s_list[k];
    memmove(&s_list[k], &s_list[k + 1], (size_t)(s_n - k - 1) * sizeof(block_entry_t));
    s_n--;
    if (save() != ESP_OK) {                         // put it back
        memmove(&s_list[k + 1], &s_list[k], (size_t)(s_n - k) * sizeof(block_entry_t));
        s_list[k] = gone;
        s_n++;
        xSemaphoreGive(s_lock);
        return BLOCK_SAVE;
    }
    xSemaphoreGive(s_lock);
    char a[16];
    ip_s(ip, a, sizeof(a));
    ESP_LOGW(TAG, "Unblocked %s %s", blocklist_kind_key(kind), a);
    echo("remove", ip, (uint8_t)kind, gone.note);
    return BLOCK_OK;
}

int blocklist_get(block_entry_t *out, int max)
{
    if (!s_list) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int n = s_n < max ? s_n : max;
    memcpy(out, s_list, (size_t)n * sizeof(block_entry_t));
    xSemaphoreGive(s_lock);
    return n;
}

size_t blocklist_text(char *buf, size_t cap)
{
    if (!s_list || !cap) return 0;
    size_t o = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_n; i++) {
        char a[16];
        ip_s(s_list[i].ip, a, sizeof(a));
        int w = snprintf(buf + o, cap - o, "%s %s\n", blocklist_kind_key(s_list[i].kind), a);
        if (w < 0 || (size_t)w >= cap - o) { o = (size_t)-1; break; }   // never a cut list: the router would unblock
        o += (size_t)w;
    }
    xSemaphoreGive(s_lock);
    return o;
}

void blocklist_note_fetch(bool served)
{
    // time() takes a newlib lock, which aborts inside a critical section when
    // contended (the 2026-11-04 panic, in router_trip.c), so read it first.
    uint32_t now = (uint32_t)time(NULL);
    portENTER_CRITICAL(&s_mux);
    if (served) { s_served++; s_last = now; }
    else s_refused++;
    portEXIT_CRITICAL(&s_mux);
}

void blocklist_fetch_stats(uint32_t *served, uint32_t *last, uint32_t *refused)
{
    portENTER_CRITICAL(&s_mux);
    *served = s_served;
    *last = s_last;
    *refused = s_refused;
    portEXIT_CRITICAL(&s_mux);
}
