// Router integrity: snapshot and diff of the router's configuration over the
// read-only REST client, with routeros-scanner's static checks. See
// mikrotik_watch.h. Fork addition, Robert Mech.
//
// The static checks are ported from microsoft/routeros-scanner, the .py files in commands
// (Copyright (c) Microsoft Corporation, MIT License; THIRD_PARTY_NOTICES).
//
// Threading: mikrotik_watch_tick() runs on the mikrotik task (PSRAM stack),
// which owns the record sets. The status JSON is built under s_lock by any
// task. Events go to log_store_append() on a helper task with an internal
// stack (SPIFFS), fed by a small PSRAM queue.

#include "mikrotik_watch.h"
#include "mikrotik.h"
#include "router_trip.h"        // router_trip_syslog_live(): syslog covers logins
#include "settings.h"
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "json_esc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "RTRWATCH";

#define MW_NVS_NS        "mikrotik"
#define MW_NVS_KEY       "watch"
#define MW_LIST_BYTES    (256 * 1024)
#define MW_STAGGER_S     12          // between menus in one pass
#define MW_EV_DEPTH      8
#define MW_EV_STACK      4096        // log_store_append and its listeners, internal
#define MW_COMBOS        32          // user, address, service seen logging in
#define MW_FAIL_BURST    3           // login failures in one check that make an event

// ── Checks ────────────────────────────────────────────────────────────────────

enum { K_LIST, K_SINGLE, K_LOG, K_ACTIVE };
enum { F_NONE, F_TUNNEL };

typedef void (*finder_t)(const mikrotik_row_t *r, char *out, size_t len);

static void find_scheduler(const mikrotik_row_t *r, char *out, size_t len);
static void find_user(const mikrotik_row_t *r, char *out, size_t len);
static void find_nat(const mikrotik_row_t *r, char *out, size_t len);
static void find_service(const mikrotik_row_t *r, char *out, size_t len);
static void find_enabled(const mikrotik_row_t *r, char *out, size_t len);
static void find_dns(const mikrotik_row_t *r, char *out, size_t len);

typedef struct {
    const char *key, *title, *code, *path, *noun, *name_key, *by_key;
    uint8_t     kind, filter;
    finder_t    find;
} check_t;

// Field names from the RouterOS 7.24/7.25 CLI reference; a field a router
// does not have is simply absent from its reply, a menu it does not have
// answers 400 or 404 and the check is marked missing.
static const check_t CHECKS[] = {
    { "scheduler", "Router scheduler", "55-01",
      "/system/scheduler?.proplist=.id,name,on-event,start-date,start-time,interval,owner,policy,disabled",
      "scheduler entry", "name", "owner", K_LIST, F_NONE, find_scheduler },
    { "script", "Router script", "55-01",
      "/system/script?.proplist=.id,name,owner,policy,dont-require-permissions,source",
      "script", "name", "owner", K_LIST, F_NONE, NULL },
    { "user", "Router users", "55-02", "/user?.proplist=.id,name,group,address,disabled",
      "user", "name", NULL, K_LIST, F_NONE, find_user },
    { "group", "Router user groups", "55-02", "/user/group?.proplist=.id,name,policy",
      "user group", "name", NULL, K_LIST, F_NONE, NULL },
    { "ssh_keys", "Router SSH keys", "55-02", "/user/ssh-keys?.proplist=.id,user,key-type,bits,info,key-owner",
      "SSH key", "user", NULL, K_LIST, F_NONE, NULL },
    { "socks", "Router SOCKS", "55-03", "/ip/socks?.proplist=enabled,port,version,auth-method",
      "SOCKS server", NULL, NULL, K_SINGLE, F_NONE, find_enabled },
    { "proxy", "Router web proxy", "55-03", "/ip/proxy?.proplist=enabled,port,parent-proxy",
      "web proxy", NULL, NULL, K_SINGLE, F_NONE, find_enabled },
    { "nat", "Router NAT", "55-04",
      "/ip/firewall/nat?.proplist=.id,chain,action,protocol,src-address,dst-address,dst-port,in-interface,"
      "to-addresses,to-ports,disabled,dynamic,comment",
      "NAT rule", "comment", NULL, K_LIST, F_NONE, find_nat },
    { "service", "Router services", "55-05",
      "/ip/service?.proplist=.id,name,port,address,available-from,disabled,certificate,tls-version",
      "service", "name", NULL, K_LIST, F_NONE, find_service },
    { "filter", "Router firewall input", "55-06",
      "/ip/firewall/filter?chain=input&.proplist=.id,chain,action,protocol,src-address,src-address-list,dst-port,"
      "in-interface,in-interface-list,connection-state,disabled,dynamic,comment",
      "input rule", "comment", NULL, K_LIST, F_NONE, NULL },
    { "dns", "Router DNS", "55-07", "/ip/dns?.proplist=servers,allow-remote-requests,use-doh-server,verify-doh-cert",
      "DNS settings", NULL, NULL, K_SINGLE, F_NONE, find_dns },
    { "dns_static", "Router DNS static", "55-07",
      "/ip/dns/static?.proplist=.id,name,regexp,type,address,cname,forward-to,disabled,dynamic",
      "static DNS entry", "name", NULL, K_LIST, F_NONE, NULL },
    { "tunnel", "Router tunnels", "55-08", "/interface?.proplist=.id,name,type,disabled,dynamic",
      "tunnel interface", "name", NULL, K_LIST, F_TUNNEL, NULL },
    { "logging", "Router logging", "55-09", "/system/logging?.proplist=.id,topics,action,prefix,disabled",
      "logging rule", "topics", NULL, K_LIST, F_NONE, NULL },
    { "log_action", "Router log actions", "55-09",
      "/system/logging/action?.proplist=.id,name,target,remote,remote-port,src-address,remote-log-format",
      "logging action", "name", NULL, K_LIST, F_NONE, NULL },
    { "login_log", "Router logins", "55-10", "/log?.proplist=.id,time,topics,message",
      "login", NULL, NULL, K_LOG, F_NONE, NULL },
    { "active", "Router sessions", "55-10", "/user/active?.proplist=.id,name,address,via",
      "session", NULL, NULL, K_ACTIVE, F_NONE, NULL },
    { "package", "Router packages", "55-11", "/system/package?.proplist=.id,name,version,disabled",
      "package", "name", NULL, K_LIST, F_NONE, NULL },
    { "version", "Router version", "55-11", "/system/resource?.proplist=version",
      "RouterOS version", NULL, NULL, K_SINGLE, F_NONE, NULL },
    { "firmware", "Router firmware", "55-11",
      "/system/routerboard?.proplist=model,current-firmware,upgrade-firmware",
      "RouterBOOT firmware", NULL, NULL, K_SINGLE, F_NONE, NULL },
};
#define CHECK_N ((int)(sizeof(CHECKS) / sizeof(CHECKS[0])))

// ── State ─────────────────────────────────────────────────────────────────────

typedef struct {
    char     id[12];
    uint32_t hash;
    char     name[28];
    char     by[16];
    char     find[40];          // the static check's finding, "" none
} rec_t;

typedef struct {
    bool     valid;
    uint16_t n;
    rec_t    r[MIKROTIK_WATCH_RECS];
} recset_t;

enum { CS_NEW, CS_OK, CS_CHANGED, CS_DRIFT, CS_MISSING, CS_ERROR, CS_UNARMED };
static const char *const CS_KEY[] = { "pending", "ok", "changed", "drift", "missing", "error", "not_armed" };

typedef struct {
    uint8_t  state;
    bool     hidden_source;     // script source not in the reply
    bool     truncated;         // more than MIKROTIK_WATCH_RECS records
    bool     have_digest;       // NVS holds the armed digest
    bool     digest_checked;    // compared with it once since boot
    uint16_t changes;           // records differing from the armed baseline
    uint16_t nvs_count;
    uint32_t nvs_digest;
    uint32_t last;              // unix time of the last check
    int64_t  due_s;             // uptime s the next check is due
    char     findings[96];
    recset_t armed, seen;
} cstate_t;

typedef struct {
    uint32_t armed_at;
    uint8_t  n;
    struct { uint32_t digest; uint16_t count; uint16_t _pad; } m[CHECK_N];
} nvs_blob_t;

typedef struct {
    cstate_t c[CHECK_N];
    recset_t cur;
    uint32_t combo[MW_COMBOS];  // FNV of "user|address|via"
    uint8_t  n_combo;
    bool     combos_learned, log_learned;
    uint32_t log_last;          // highest log .id seen
    uint16_t fails;
    char     fail_msg[64];
    attack_log_t ev;
} mw_t;

static mw_t             *W;
static SemaphoreHandle_t s_lock;
static QueueHandle_t     s_evq;
static volatile bool     s_ev_running;
static portMUX_TYPE      s_ev_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool     s_arm_req;
static bool              s_arming, s_armed;
static int               s_arm_next;        // next check in an arming pass
static uint32_t          s_armed_at, s_last_check;

static int64_t up_s(void) { return esp_timer_get_time() / 1000000LL; }
static bool lock(int ms);

static uint32_t fnv(uint32_t h, const char *s)
{
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

static void cut(char *dst, size_t cap, const char *src)
{
    size_t o = 0;
    for (; *src && o + 1 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c >= 0x20 && c <= 0x7e && c != '\'' && c != '"' && c != '`') dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

static bool truthy(const char *v) { return !strcmp(v, "true") || !strcmp(v, "yes"); }

// ── routeros-scanner checks (its commands directory, MIT) ─────────────────────

// scheduler.py: a task named u<digits>, or one whose on-event fetches from the web.
static void find_scheduler(const mikrotik_row_t *r, char *out, size_t len)
{
    const char *name = mikrotik_row_get(r, "name"), *ev = mikrotik_row_get(r, "on-event");
    bool u = (name[0] == 'u' || name[0] == 'U') && name[1];
    for (const char *p = name + 1; u && *p; p++) u = isdigit((unsigned char)*p) != 0;
    if (u) snprintf(out, len, "named u<digits>, as malware names its tasks");
    else if (strstr(ev, "/tool fetch") || strstr(ev, "url") || strstr(ev, "http")) snprintf(out, len, "fetches from the web");
}

// users.py: the default admin in group full; a user with no allowed address.
static void find_user(const mikrotik_row_t *r, char *out, size_t len)
{
    if (!strcmp(mikrotik_row_get(r, "name"), "admin") && !strcmp(mikrotik_row_get(r, "group"), "full"))
        snprintf(out, len, "the default admin, group full");
    else if (!mikrotik_row_get(r, "address")[0])
        snprintf(out, len, "no allowed address");
}

static bool ip_public(const char *s)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255) return false;
    if (a == 10 || a == 127 || a == 0 || a >= 224 || (a == 172 && (b & 0xF0) == 16) || (a == 192 && b == 168) ||
        (a == 169 && b == 254) || (a == 100 && (b & 0xC0) == 64)) return false;
    return true;
}

// fwnat.py: dst-nat from a public address to a public address.
static void find_nat(const mikrotik_row_t *r, char *out, size_t len)
{
    if (!strcmp(mikrotik_row_get(r, "action"), "dst-nat") && ip_public(mikrotik_row_get(r, "dst-address")) &&
        ip_public(mikrotik_row_get(r, "to-addresses")))
        snprintf(out, len, "dst-nat between public addresses");
}

// ports.py: a service off its default port.
static void find_service(const mikrotik_row_t *r, char *out, size_t len)
{
    static const struct { const char *name; int port; } DEF[] = {
        { "telnet", 23 }, { "ftp", 21 }, { "www", 80 }, { "ssh", 22 }, { "www-ssl", 443 },
        { "api", 8728 }, { "winbox", 8291 }, { "api-ssl", 8729 },
    };
    const char *name = mikrotik_row_get(r, "name"), *port = mikrotik_row_get(r, "port");
    for (size_t i = 0; i < sizeof(DEF) / sizeof(DEF[0]); i++) {
        if (strcmp(DEF[i].name, name) || !port[0]) continue;
        if (atoi(port) != DEF[i].port) snprintf(out, len, "port %d, not the default %d", atoi(port), DEF[i].port);
        return;
    }
}

// socks.py, proxy.py: enabled at all.
static void find_enabled(const mikrotik_row_t *r, char *out, size_t len)
{
    if (truthy(mikrotik_row_get(r, "enabled"))) snprintf(out, len, "enabled");
}

// dns.py: the router answers DNS for others (allow-remote-requests).
static void find_dns(const mikrotik_row_t *r, char *out, size_t len)
{
    if (truthy(mikrotik_row_get(r, "allow-remote-requests"))) snprintf(out, len, "answers remote DNS requests");
}

// ── Events ────────────────────────────────────────────────────────────────────

static void ev_task(void *arg)
{
    (void)arg;
    attack_log_t *e = heap_caps_malloc(sizeof(*e), MALLOC_CAP_SPIRAM);
    for (;;) {
        bool got = e && xQueueReceive(s_evq, e, pdMS_TO_TICKS(2000)) == pdTRUE;
        if (!got) {
            portENTER_CRITICAL(&s_ev_mux);
            bool empty = !e || uxQueueMessagesWaiting(s_evq) == 0;
            if (empty) s_ev_running = false;
            portEXIT_CRITICAL(&s_ev_mux);
            if (empty) break;
            continue;
        }
        log_store_append(e);        // ring, SD, dashboard, panel, Discord, alarm
        telegram_notify(e);         // gated by its own settings and the alert mask
    }
    free(e);
    vTaskDelete(NULL);
}

uint32_t mikrotik_watch_router_ip(void)
{
    settings_t *s = heap_caps_malloc(sizeof(*s), MALLOC_CAP_SPIRAM);
    if (!s) return 0;
    settings_copy(s);
    const char *u = s->mikrotik_url;
    u += !strncmp(u, "https://", 8) ? 8 : !strncmp(u, "http://", 7) ? 7 : 0;
    unsigned a, b, c, d;
    uint32_t ip = 0;
    if (sscanf(u, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        uint8_t q[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
        memcpy(&ip, q, 4);
    }
    memset(s, 0, sizeof(*s));
    free(s);
    return ip;
}

// "[55-01] <detail>": describe.c takes the code from the prefix.
static void event(const check_t *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void event(const check_t *k, const char *fmt, ...)
{
    attack_log_t *e = &W->ev;
    memset(e, 0, sizeof(*e));
    e->timestamp = (uint32_t)time(NULL);
    e->type = ATTACK_ROUTER;
    e->src_ip = mikrotik_watch_router_ip();
    if (e->src_ip) wifi_manager_lookup_mac(e->src_ip, e->src_mac);
    int n = snprintf(e->payload, sizeof(e->payload), "[%s] ", k->code);
    va_list ap;
    va_start(ap, fmt);
    if (n > 0 && n < (int)sizeof(e->payload)) vsnprintf(e->payload + n, sizeof(e->payload) - (size_t)n, fmt, ap);
    va_end(ap);
    ESP_LOGW(TAG, "%s", e->payload);
    if (!mikrotik_watch_post(e)) ESP_LOGW(TAG, "event dropped (queue full)");
}

// The helper's queue, made by whoever posts first (this module's load, or the
// router tripwires' task when MikroTik is off).
static QueueHandle_t ev_queue(void)
{
    QueueHandle_t q = __atomic_load_n(&s_evq, __ATOMIC_ACQUIRE);
    if (q) return q;
    QueueHandle_t n = xQueueCreateWithCaps(MW_EV_DEPTH, sizeof(attack_log_t), MALLOC_CAP_SPIRAM);
    if (!n) return NULL;
    QueueHandle_t exp = NULL;
    if (!__atomic_compare_exchange_n(&s_evq, &exp, n, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        vQueueDeleteWithCaps(n);
        return exp;
    }
    return n;
}

bool mikrotik_watch_post(const attack_log_t *e)
{
    QueueHandle_t q = ev_queue();
    if (!e || !q || xQueueSend(q, e, 0) != pdTRUE) return false;
    portENTER_CRITICAL(&s_ev_mux);
    bool start = !s_ev_running;
    if (start) s_ev_running = true;
    portEXIT_CRITICAL(&s_ev_mux);
    if (start && xTaskCreatePinnedToCore(ev_task, "rtr_ev", MW_EV_STACK, NULL, 2, NULL, 1) != pdPASS) {
        s_ev_running = false;
        ESP_LOGW(TAG, "event helper not started: out of memory");
    }
    return true;
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

static bool is_counter(const char *k)
{
    static const char *const C[] = { ".id", "run-count", "next-run", "last-started", "bytes", "packets",
                                     "uptime", "invalid", "dynamic" };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) if (!strcmp(C[i], k)) return true;
    return false;
}

static bool tunnel_type(const char *t)
{
    static const char *const T[] = { "-out", "tunnel", "gre", "eoip", "ipip", "wg", "wireguard", "vxlan", "6to4", "l2tp", "sstp", "ovpn", "pptp" };
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) if (strstr(t, T[i])) return true;
    return false;
}

typedef struct { const check_t *k; cstate_t *c; bool saw_source, saw_script; } snap_ctx_t;

static bool snap_cb(void *ctx, const mikrotik_row_t *r)
{
    snap_ctx_t *x = ctx;
    const check_t *k = x->k;
    if (k->filter == F_TUNNEL && !tunnel_type(mikrotik_row_get(r, "type"))) return true;
    if (truthy(mikrotik_row_get(r, "dynamic"))) return true;    // UPnP rules, l2tp-in sessions: not configuration
    recset_t *s = &W->cur;
    if (s->n >= MIKROTIK_WATCH_RECS) { x->c->truncated = true; return true; }
    rec_t *o = &s->r[s->n++];
    memset(o, 0, sizeof(*o));
    if (k->kind == K_SINGLE) strlcpy(o->id, "-", sizeof(o->id));
    else cut(o->id, sizeof(o->id), mikrotik_row_get(r, ".id"));
    uint32_t h = 2166136261u;
    for (int i = 0; i < r->n; i++) {
        if (is_counter(r->kv[i].k)) continue;
        h = fnv(h, r->kv[i].k);
        h = (h ^ r->kv[i].hash) * 16777619u;
    }
    o->hash = h ? h : 1;
    if (k->name_key) cut(o->name, sizeof(o->name), mikrotik_row_get(r, k->name_key));
    if (!o->name[0] && k->kind == K_LIST) {             // NAT and filter rules often have no comment
        const char *a = mikrotik_row_get(r, "action"), *p = mikrotik_row_get(r, "dst-port");
        if (a[0]) snprintf(o->name, sizeof(o->name), "%.12s%s%.10s", a, p[0] ? " port " : "", p);
        else strlcpy(o->name, o->id, sizeof(o->name));
    }
    if (k->by_key) cut(o->by, sizeof(o->by), mikrotik_row_get(r, k->by_key));
    if (k->find) k->find(r, o->find, sizeof(o->find));
    if (!strcmp(k->key, "script")) {
        x->saw_script = true;
        for (int i = 0; i < r->n; i++) if (!strcmp(r->kv[i].k, "source")) x->saw_source = true;
    }
    return true;
}

// Order-independent digest of a set: what NVS keeps.
static uint32_t digest(const recset_t *s)
{
    uint32_t d = 0;
    for (int i = 0; i < s->n; i++) d += fnv(2166136261u, s->r[i].id) * 2654435761u ^ s->r[i].hash;
    return d;
}

static const rec_t *find_id(const recset_t *s, const char *id)
{
    for (int i = 0; s->valid && i < s->n; i++) if (!strcmp(s->r[i].id, id)) return &s->r[i];
    return NULL;
}

static void single_fields(const rec_t *r, char *out, size_t len, const mikrotik_row_t *row)
{
    (void)r;
    out[0] = '\0';
    if (!row) return;
    static const char *const K[] = { "enabled", "port", "servers", "allow-remote-requests", "version",
                                     "current-firmware", "upgrade-firmware" };
    for (size_t i = 0; i < sizeof(K) / sizeof(K[0]); i++) {
        const char *v = mikrotik_row_get(row, K[i]);
        if (!v[0]) continue;
        char one[48], vv[28];
        cut(vv, sizeof(vv), v);
        snprintf(one, sizeof(one), "%s%s=%s", out[0] ? " " : "", K[i], vv);
        strlcat(out, one, len);
    }
}

// The last single-object row, for its fields in the event text.
static mikrotik_row_t *s_single_row;
static bool single_cb(void *ctx, const mikrotik_row_t *r)
{
    snap_cb(ctx, r);
    if (s_single_row) *s_single_row = *r;
    return false;
}

static void findings(cstate_t *c)
{
    c->findings[0] = '\0';
    int n = 0;
    for (int i = 0; i < W->cur.n; i++) {
        const rec_t *r = &W->cur.r[i];
        if (!r->find[0]) continue;
        if (!n) snprintf(c->findings, sizeof(c->findings), "%s: %s", r->name[0] ? r->name : r->id, r->find);
        n++;
    }
    if (n > 1) {
        char more[24];
        snprintf(more, sizeof(more), " (+%d more)", n - 1);
        strlcat(c->findings, more, sizeof(c->findings));
    }
}

// Compare the snapshot in W->cur with what was seen last, raise events, and
// update the state against the armed baseline. Under s_lock.
static void diff(const check_t *k, cstate_t *c, const mikrotik_row_t *single)
{
    recset_t *cur = &W->cur, *seen = &c->seen, *armed = &c->armed;
    cur->valid = true;
    int raised = 0, more = 0;
    char extra[64];

    if (s_armed && !armed->valid && c->have_digest && !c->digest_checked) {
        c->digest_checked = true;
        // After a reboot: only the digest survived.
        if (digest(cur) == c->nvs_digest && cur->n == c->nvs_count) {
            *armed = *cur;
        } else {
            event(k, "%s differs from the armed baseline (%u records now, %u then); detail is not kept over a reboot",
                  k->title + 7, (unsigned)cur->n, (unsigned)c->nvs_count);
            c->state = CS_DRIFT;
        }
        *seen = *cur;
    } else if (s_armed && seen->valid) {
        for (int i = 0; i < cur->n; i++) {
            const rec_t *r = &cur->r[i], *was = find_id(seen, r->id), *base = find_id(armed, r->id);
            if (was && was->hash == r->hash) continue;
            if (base && base->hash == r->hash) continue;        // back to the armed state
            if (raised >= MIKROTIK_WATCH_EVENTS) { more++; continue; }
            extra[0] = '\0';
            if (r->find[0]) snprintf(extra, sizeof(extra), "; %s", r->find);
            if (k->kind == K_SINGLE) {
                char f[80];
                single_fields(r, f, sizeof(f), single);
                event(k, "%s changed%s%s%s", k->noun, f[0] ? ": " : "", f, extra);
            } else if (!was) {
                event(k, "new %s '%s' added%s%s%s", k->noun, r->name, r->by[0] ? " by " : "", r->by, extra);
            } else {
                event(k, "%s '%s' changed%s%s%s", k->noun, r->name, r->by[0] ? ", owner " : "", r->by, extra);
            }
            raised++;
        }
        for (int i = 0; i < seen->n; i++) {
            const rec_t *r = &seen->r[i];
            if (find_id(cur, r->id)) continue;
            if (armed->valid && !find_id(armed, r->id)) continue;   // was never in the baseline
            if (raised >= MIKROTIK_WATCH_EVENTS) { more++; continue; }
            event(k, "%s '%s' removed", k->noun, r->name);
            raised++;
        }
        if (more) event(k, "%s: %d more changes", k->title + 7, more);
        *seen = *cur;
    } else {
        *seen = *cur;
    }

    // Against the armed baseline.
    if (!s_armed) { c->state = CS_UNARMED; c->changes = 0; return; }
    if (!armed->valid) return;                                  // drift since the reboot, stays
    uint16_t ch = 0;
    for (int i = 0; i < cur->n; i++) {
        const rec_t *b = find_id(armed, cur->r[i].id);
        if (!b || b->hash != cur->r[i].hash) ch++;
    }
    for (int i = 0; i < armed->n; i++) if (!find_id(cur, armed->r[i].id)) ch++;
    c->changes = ch;
    c->state = ch ? CS_CHANGED : CS_OK;
}

// ── Logins (55-10) ────────────────────────────────────────────────────────────

static bool combo_seen(uint32_t h)
{
    for (int i = 0; i < W->n_combo; i++) if (W->combo[i] == h) return true;
    if (W->n_combo >= MW_COMBOS) { memmove(W->combo, W->combo + 1, (MW_COMBOS - 1) * sizeof(W->combo[0])); W->n_combo--; }
    W->combo[W->n_combo++] = h;
    return false;
}

static uint32_t combo_hash(const char *user, const char *addr, const char *via)
{
    uint32_t h = fnv(2166136261u, user);
    h = fnv(h ^ '|', addr);
    return fnv(h ^ '|', via);
}

typedef struct { const check_t *k; bool learn; uint32_t max_id; int events; } log_ctx_t;

// RouterOS log lines: "login failure for user X from A via S" (system, error,
// critical) and "user X logged in from A via S" (system, info, account).
static bool log_cb(void *ctx, const mikrotik_row_t *r)
{
    log_ctx_t *x = ctx;
    const char *id = mikrotik_row_get(r, ".id");
    uint32_t n = (uint32_t)strtoul(id[0] == '*' ? id + 1 : id, NULL, 16);
    if (n > x->max_id) x->max_id = n;
    if (n <= W->log_last && !x->learn) return true;
    const char *m = mikrotik_row_get(r, "message");
    char user[24] = "", addr[40] = "", via[16] = "";
    if (strstr(m, "login failure for user ")) {
        if (!x->learn) {
            W->fails++;
            cut(W->fail_msg, sizeof(W->fail_msg), m);
        }
    } else if (sscanf(m, "user %23s logged in from %39s via %15s", user, addr, via) == 3) {
        bool fresh = !combo_seen(combo_hash(user, addr, via));
        if (fresh && !x->learn && x->events < MIKROTIK_WATCH_EVENTS && !router_trip_syslog_live()) {
            char u[24], a[40], v[16];
            cut(u, sizeof(u), user); cut(a, sizeof(a), addr); cut(v, sizeof(v), via);
            event(x->k, "login as %s from %s via %s, a new address or service", u, a, v);
            x->events++;
        }
    }
    return true;
}

static bool active_cb(void *ctx, const mikrotik_row_t *r)
{
    log_ctx_t *x = ctx;
    char u[24], a[40], v[16];
    cut(u, sizeof(u), mikrotik_row_get(r, "name"));
    cut(a, sizeof(a), mikrotik_row_get(r, "address"));
    cut(v, sizeof(v), mikrotik_row_get(r, "via"));
    bool fresh = !combo_seen(combo_hash(u, a, v));
    if (fresh && !x->learn && x->events < MIKROTIK_WATCH_EVENTS && !router_trip_syslog_live()) {
        event(x->k, "session %s from %s via %s, a new address or service", u, a, v);
        x->events++;
    }
    return true;
}

// ── One check ─────────────────────────────────────────────────────────────────

static void run_check(int i)
{
    const check_t *k = &CHECKS[i];
    cstate_t *c = &W->c[i];
    uint32_t rows = 0;
    int st;
    if (k->kind == K_LOG || k->kind == K_ACTIVE) {
        log_ctx_t x = { .k = k, .learn = k->kind == K_LOG ? !W->log_learned : !W->combos_learned };
        if (k->kind == K_LOG) W->fails = 0;
        st = mikrotik_rest_get(k->path, k->kind == K_LOG ? log_cb : active_cb, &x, MW_LIST_BYTES, &rows);
        if (st == 200 && k->kind == K_LOG) {
            if (x.max_id < W->log_last) W->log_last = 0;          // the router rebooted: ids start again
            else W->log_last = x.max_id;
            W->log_learned = true;
            if (W->fails >= MW_FAIL_BURST && !router_trip_syslog_live()) event(k, "%u login failures since the last check (last: %s)", (unsigned)W->fails, W->fail_msg);
        }
        if (st == 200 && k->kind == K_ACTIVE) W->combos_learned = true;
        if (lock(1000)) {
            c->state = st == 200 ? CS_OK : (st == 400 || st == 404) ? CS_MISSING : CS_ERROR;
            c->last = (uint32_t)time(NULL);
            c->seen.n = (uint16_t)rows;
            xSemaphoreGive(s_lock);
        }
        return;
    }

    W->cur.n = 0;
    W->cur.valid = false;
    snap_ctx_t x = { .k = k, .c = c };
    c->truncated = false;
    mikrotik_row_t *row = NULL;
    if (k->kind == K_SINGLE) {
        row = heap_caps_malloc(sizeof(*row), MALLOC_CAP_SPIRAM);
        if (row) row->n = 0;
        s_single_row = row;
        st = mikrotik_rest_get(k->path, single_cb, &x, 16 * 1024, &rows);
        s_single_row = NULL;
    } else {
        st = mikrotik_rest_get(k->path, snap_cb, &x, MW_LIST_BYTES, &rows);
    }
    if (!lock(1000)) { free(row); return; }
    c->last = (uint32_t)time(NULL);
    if (st == 200) {
        c->hidden_source = x.saw_script && !x.saw_source;
        findings(c);
        if (s_arming) {
            W->cur.valid = true;
            c->armed = W->cur;
            c->seen = W->cur;
            c->nvs_digest = digest(&W->cur);
            c->nvs_count = W->cur.n;
            c->have_digest = true;
            c->changes = 0;
            c->digest_checked = true;
            c->state = CS_OK;
        } else {
            diff(k, c, row);
        }
    } else if (st == 400 || st == 404) {
        c->state = CS_MISSING;                  // no such menu on this router
    } else {
        c->state = CS_ERROR;
    }
    xSemaphoreGive(s_lock);
    free(row);
}

// ── Public ────────────────────────────────────────────────────────────────────

static bool lock(int ms) { return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(ms)) == pdTRUE; }

void mikrotik_watch_load(void)
{
    if (W) return;
    W = heap_caps_calloc(1, sizeof(*W), MALLOC_CAP_SPIRAM);
    s_lock = xSemaphoreCreateMutex();
    if (!W || !s_lock || !ev_queue()) { ESP_LOGE(TAG, "Not started: out of memory"); free(W); W = NULL; return; }
    nvs_blob_t b;
    size_t n = sizeof(b);
    nvs_handle_t h;
    if (nvs_open(MW_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, MW_NVS_KEY, &b, &n) == ESP_OK && n == sizeof(b) && b.n == CHECK_N && b.armed_at) {
            s_armed = true;
            s_armed_at = b.armed_at;
            for (int i = 0; i < CHECK_N; i++) {
                W->c[i].have_digest = true;
                W->c[i].nvs_digest = b.m[i].digest;
                W->c[i].nvs_count = b.m[i].count;
            }
        }
        nvs_close(h);
    }
    int64_t now = up_s();
    for (int i = 0; i < CHECK_N; i++) {
        W->c[i].state = s_armed ? CS_NEW : CS_UNARMED;
        W->c[i].due_s = now + 60 + i * MW_STAGGER_S;            // after the first host poll
    }
    ESP_LOGI(TAG, "Router integrity: %d checks, %u B in PSRAM, baseline %s", CHECK_N, (unsigned)sizeof(*W),
             s_armed ? "armed" : "not armed");
}

bool mikrotik_watch_arm(void)
{
    if (!W || !mikrotik_running()) return false;
    s_arm_req = true;
    return true;
}

static void arm_commit(void)
{
    nvs_blob_t b;
    memset(&b, 0, sizeof(b));
    b.armed_at = (uint32_t)time(NULL);
    b.n = CHECK_N;
    if (lock(1000)) {
        for (int i = 0; i < CHECK_N; i++) {
            b.m[i].digest = W->c[i].nvs_digest;
            b.m[i].count = W->c[i].nvs_count;
        }
        s_armed = true;
        s_armed_at = b.armed_at;
        s_arming = false;
        xSemaphoreGive(s_lock);
    }
    mikrotik_nvs_save(MW_NVS_KEY, &b, sizeof(b));
    ESP_LOGW(TAG, "Router baseline armed");
}

void mikrotik_watch_tick(void)
{
    if (!W) return;
    int64_t now = up_s();
    if (s_arm_req && !s_arming) {
        s_arm_req = false;
        s_arming = true;
        s_arm_next = 0;
        ESP_LOGI(TAG, "Arming the router baseline: one pass over %d menus", CHECK_N);
    }
    if (s_arming) {
        while (s_arm_next < CHECK_N && (CHECKS[s_arm_next].kind == K_LOG || CHECKS[s_arm_next].kind == K_ACTIVE)) s_arm_next++;
        if (s_arm_next < CHECK_N) { run_check(s_arm_next); W->c[s_arm_next].due_s = now + MIKROTIK_POLL_S; s_arm_next++; return; }
        arm_commit();
        return;
    }
    for (int i = 0; i < CHECK_N; i++) {
        if (now < W->c[i].due_s) continue;
        run_check(i);
        W->c[i].due_s = now + MIKROTIK_POLL_S;
        s_last_check = (uint32_t)time(NULL);
        return;                                 // one request per tick
    }
}

unsigned mikrotik_watch_json(char *buf, unsigned cap)
{
    if (!cap) return 0;
    buf[0] = '\0';
    unsigned n = 0;
    bool full = false;
#define PUT(...) do { if (!full) { int w_ = snprintf(buf + n, cap - n, __VA_ARGS__); \
                     if (w_ < 0 || (unsigned)w_ >= cap - n) full = true; else n += (unsigned)w_; } } while (0)
    PUT("{\"running\":%s,\"armed\":%s,\"arming\":%s,\"armed_at\":%lu,\"last_check\":%lu,\"checks\":[",
        W ? "true" : "false", s_armed ? "true" : "false", (s_arming || s_arm_req) ? "true" : "false",
        (unsigned long)s_armed_at, (unsigned long)s_last_check);
    if (W && lock(200)) {
        for (int i = 0; i < CHECK_N; i++) {
            const check_t *k = &CHECKS[i];
            const cstate_t *c = &W->c[i];
            char fj[200];
            json_esc(c->findings, sizeof(c->findings), fj, sizeof(fj));
            const char *note = c->hidden_source ? "script source not readable by this user: diffing name, owner and policy only" :
                               c->truncated ? "more records than the 64 kept" :
                               c->state == CS_MISSING ? "this router has no such menu" :
                               c->state == CS_DRIFT ? "changed since arming; re-arm after checking it" :
                               (k->kind == K_LOG || k->kind == K_ACTIVE) ? "always on, no baseline" : "";
            PUT("%s{\"key\":\"%s\",\"title\":\"%s\",\"code\":\"%s\",\"state\":\"%s\",\"records\":%u,"
                "\"armed_records\":%u,\"changes\":%u,\"last\":%lu,\"note\":\"%s\",\"findings\":\"%s\"}",
                i ? "," : "", k->key, k->title, k->code, CS_KEY[c->state], (unsigned)c->seen.n,
                (unsigned)(c->armed.valid ? c->armed.n : c->nvs_count), (unsigned)c->changes,
                (unsigned long)c->last, note, fj);
        }
        xSemaphoreGive(s_lock);
    }
    PUT("]}");
#undef PUT
    return full ? 0 : n;
}
