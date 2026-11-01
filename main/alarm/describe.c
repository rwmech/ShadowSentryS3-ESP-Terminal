#include "describe.h"
#include "http_engine.h"
#include "tripwire.h"
#include "wifi_manager.h"
#include "lwip/ip4_addr.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Headlines and tiers (see describe.h). Every parse below works on a bounded,
// NUL-terminated copy of the payload and fails soft: a payload that does not
// match its expected shape gets the generic headline for its type.

#define TOK_MAX     24      // a quoted command or user name
#define PATH_MAX_Q  32      // a quoted path

// ── Codes ─────────────────────────────────────────────────────────────────────

// The code table, in code order. HTTP rows carry the engine's label key and
// tripwire rows the service name; the lookups below match on those.
typedef struct {
    const char *code;
    const char *name;
    uint8_t     tier;
    const char *key;        // HTTP label key or tripwire service, else NULL
} code_row_t;

static const code_row_t CODES[] = {
    { "17-01", "ARP sweep",          TIER_SEV2, NULL },
    { "17-02", "Port scan",          TIER_SEV1, NULL },
    { "17-03", "Probe",              TIER_SEV2, NULL },
    { "17-04", "Scan ended",         TIER_SEV2, NULL },
    { "20-01", "SSH login",          TIER_SEV1, NULL },
    { "20-02", "Telnet login",       TIER_SEV1, NULL },
    { "20-03", "FTP login",          TIER_SEV1, NULL },
    { "20-04", "RTSP auth",          TIER_SEV1, NULL },
    { "20-05", "Shell command",      TIER_SEV1, NULL },
    { "20-06", "Shell session",      TIER_SEV1, NULL },
    { "30-01", "Web login",          TIER_SEV1, "login_post" },
    { "30-02", "Web dotfile",        TIER_SEV2, "dotfile_path" },
    { "30-03", "Web traversal",      TIER_SEV2, "dotdot_path" },
    { "30-04", "Web odd method",     TIER_SEV2, "odd_method" },
    { "30-05", "Web oversize",       TIER_SEV2, "oversize" },
    { "30-06", "Web non-HTTP",       TIER_SEV2, "non_http" },
    { "30-07", "Web scanner",        TIER_SEV2, "scanner_ua" },
    { "30-08", "Web script",         TIER_SEV2, "library_ua" },
    { "30-09", "Web request",        TIER_SEV2, "unclassified" },
    { "40-01", "ADB",                TIER_SEV1, NULL },
    { "40-02", "RDP tripwire",       TIER_SEV1, "RDP" },
    { "40-03", "VNC tripwire",       TIER_SEV1, "VNC" },
    { "40-04", "SMB tripwire",       TIER_SEV1, "SMB" },
    { "40-05", "Redis tripwire",     TIER_SEV1, "Redis" },
    { "40-06", "MySQL tripwire",     TIER_SEV1, "MySQL" },
    { "40-07", "MSSQL tripwire",     TIER_SEV1, "MSSQL" },
    { "40-08", "JetDirect tripwire", TIER_SEV1, "JetDirect" },
    { "40-09", "Tripwire",           TIER_SEV1, NULL },     // a service added later
    { "50-01", "ARP spoof",          TIER_SEV1, NULL },
    { "50-02", "Wi-Fi deauth",       TIER_SEV1, NULL },
    // Router integrity (admin/mikrotik_watch.c): critical and high are SEV1, medium SEV2.
    { "55-01", "Router scheduler",   TIER_SEV1, NULL },
    { "55-02", "Router users",       TIER_SEV1, NULL },
    { "55-03", "Router proxy",       TIER_SEV1, NULL },
    { "55-04", "Router NAT",         TIER_SEV1, NULL },
    { "55-05", "Router service",     TIER_SEV1, NULL },
    { "55-06", "Router firewall",    TIER_SEV1, NULL },
    { "55-07", "Router DNS",         TIER_SEV1, NULL },
    { "55-08", "Router tunnel",      TIER_SEV1, NULL },
    { "55-09", "Router logging",     TIER_SEV1, NULL },
    { "55-10", "Router login",       TIER_SEV2, NULL },
    { "55-11", "Router version",     TIER_SEV2, NULL },
    { "60-01", "LAN discovery",      TIER_SEV3, NULL },
    { "60-02", "New device on network", TIER_SEV3, NULL },
};
#define CODE_N ((int)(sizeof(CODES) / sizeof(CODES[0])))

enum {      // indexes into CODES, for the fixed per-type picks
    C_ARP_SWEEP, C_PORT_SCAN, C_PROBE, C_SCAN_ENDED,
    C_SSH, C_TELNET, C_FTP, C_RTSP, C_SHELL_CMD, C_SHELL_SESSION,
    C_WEB_LOGIN, C_WEB_FIRST = C_WEB_LOGIN, C_WEB_UNCLASSIFIED = C_WEB_LOGIN + 8,
    C_ADB, C_TRIP_FIRST, C_TRIP_OTHER = C_TRIP_FIRST + 7,
    C_ARP_SPOOF, C_WIFI_DEAUTH, C_ROUTER_FIRST, C_ROUTER_LAST = C_ROUTER_FIRST + 10,
    C_DISCOVERY, C_NEW_DEVICE, C_COUNT
};
_Static_assert(C_COUNT == sizeof(CODES) / sizeof(CODES[0]), "describe.c: CODES[] and its index enum disagree");

static const code_row_t UNKNOWN = { "00-00", "Event", TIER_SEV2, NULL };

static const char *payload_str(const attack_log_t *e, char *buf, size_t len)
{
    size_t n = strnlen(e->payload, sizeof(e->payload));
    if (n >= len) n = len - 1;
    memcpy(buf, e->payload, n);
    buf[n] = '\0';
    return buf;
}

static const code_row_t *row_by_key(int first, int last, const char *key)
{
    for (int i = first; key && i <= last; i++)
        if (CODES[i].key && !strcmp(CODES[i].key, key)) return &CODES[i];
    return NULL;
}

static const code_row_t *code_row(const attack_log_t *e)
{
    if (!e) return &UNKNOWN;
    char p[sizeof(e->payload) + 1];
    switch (e->type) {
    case ATTACK_ARP_SWEEP:
        payload_str(e, p, sizeof(p));
        return &CODES[strncmp(p, "ARP sweep ended", 15) ? C_ARP_SWEEP : C_SCAN_ENDED];
    case ATTACK_SCAN:
        payload_str(e, p, sizeof(p));
        return &CODES[strncmp(p, "Scan ended", 10) ? C_PORT_SCAN : C_SCAN_ENDED];
    case ATTACK_PROBE:     return &CODES[C_PROBE];
    case ATTACK_SSH:       return &CODES[C_SSH];
    case ATTACK_TELNET:    return &CODES[C_TELNET];
    case ATTACK_FTP:       return &CODES[C_FTP];
    case ATTACK_RTSP:      return &CODES[C_RTSP];
    case ATTACK_SHELL:
        payload_str(e, p, sizeof(p));
        return &CODES[strncmp(p, "shell session", 13) ? C_SHELL_CMD : C_SHELL_SESSION];
    case ATTACK_HTTP: {
        payload_str(e, p, sizeof(p));
        const code_row_t *r = row_by_key(C_WEB_FIRST, C_WEB_UNCLASSIFIED, http_engine_category_key(p));
        if (r) return r;
        // Upstream's single-port trap: a POST carries credentials.
        return &CODES[strncmp(p, "POST ", 5) ? C_WEB_UNCLASSIFIED : C_WEB_LOGIN];
    }
    case ATTACK_ADB:       return &CODES[C_ADB];
    case ATTACK_TRIPWIRE: {
        payload_str(e, p, sizeof(p));
        const code_row_t *r = row_by_key(C_TRIP_FIRST, C_TRIP_OTHER - 1, tripwire_service_key(p));
        return r ? r : &CODES[C_TRIP_OTHER];
    }
    case ATTACK_ARP:       return &CODES[C_ARP_SPOOF];
    case ATTACK_WIFI:      return &CODES[C_WIFI_DEAUTH];
    case ATTACK_DISCOVERY: return &CODES[C_DISCOVERY];
    case ATTACK_NEW_DEVICE: return &CODES[C_NEW_DEVICE];
    case ATTACK_ROUTER: {
        // "[55-NN] <detail>": the watcher names the code.
        payload_str(e, p, sizeof(p));
        char code[DESCRIBE_CODE_LEN] = "";
        if (p[0] == '[' && strlen(p) > 6 && p[6] == ']') { memcpy(code, p + 1, 5); code[5] = 0; }
        for (int i = C_ROUTER_FIRST; i <= C_ROUTER_LAST; i++) if (!strcmp(CODES[i].code, code)) return &CODES[i];
        return &CODES[C_ROUTER_FIRST];
    }
    default:               return &UNKNOWN;
    }
}
_Static_assert(ATTACK_ROUTER + 1 == ATTACK_TYPE_COUNT, "describe.c: give the new attack type a code in CODES[] and code_row()");

const char *describe_code(const attack_log_t *e)
{
    return code_row(e)->code;
}

static const code_row_t *row_by_code(const char *code)
{
    if (!code) return NULL;
    for (int i = 0; i < CODE_N; i++)
        if (!strcmp(CODES[i].code, code)) return &CODES[i];
    return NULL;
}

const char *describe_code_name(const char *code)
{
    const code_row_t *r = row_by_code(code);
    return r ? r->name : NULL;
}

int describe_code_tier(const char *code)
{
    const code_row_t *r = row_by_code(code);
    return r ? r->tier : 0;
}

int describe_code_count(void)
{
    return CODE_N;
}

const char *describe_code_at(int i, const char **name, int *tier)
{
    if (i < 0 || i >= CODE_N) return NULL;
    if (name) *name = CODES[i].name;
    if (tier) *tier = CODES[i].tier;
    return CODES[i].code;
}

// ── Tiers ─────────────────────────────────────────────────────────────────────

describe_tier_t describe_tier(const attack_log_t *e)
{
    return (describe_tier_t)code_row(e)->tier;
}

const char *describe_tier_key(describe_tier_t t)
{
    return t == TIER_SEV1 ? "alert" : t == TIER_SEV3 ? "info" : "probe";
}

// ── Bounded text ──────────────────────────────────────────────────────────────

typedef struct { char *b; size_t cap, n; } sb_t;

static void sb_fmt(sb_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_fmt(sb_t *s, const char *fmt, ...)
{
    if (s->n + 1 >= s->cap) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(s->b + s->n, s->cap - s->n, fmt, ap);
    va_end(ap);
    if (w < 0) { s->b[s->n] = '\0'; return; }
    s->n += (size_t)w;
    if (s->n >= s->cap) s->n = s->cap - 1;
}

// Attacker text: printable ASCII only; backticks and double quotes become
// single quotes, '#' a space (the panel's recolor marker). At most max - 1
// characters; a longer one is cut with "...".
static void clean(char *out, size_t max, const char *src, size_t n)
{
    size_t o = 0, i = 0;
    for (; i < n && src[i] && o + 1 < max; i++) {
        char c = src[i];
        if (c < 0x20 || c > 0x7e) continue;
        if (c == '`' || c == '"') c = '\'';
        if (c == '#') c = ' ';
        out[o++] = c;
    }
    if (i < n && src[i] && max > 4 && o + 1 >= max) {     // cut: end on "..."
        o = max - 4;
        memcpy(out + o, "...", 3);
        o += 3;
    }
    out[o] = '\0';
}

// Length of the token at s: up to a space, tab, shell separator or max.
static size_t tok_len(const char *s, size_t max)
{
    size_t n = 0;
    while (s[n] && n < max && s[n] != ' ' && s[n] != '\t' && s[n] != ';' && s[n] != '|' &&
           s[n] != '&' && s[n] != ',' && s[n] != ')') n++;
    return n;
}

static void tok(char *out, size_t max, const char *s)
{
    clean(out, max, s, tok_len(s, 64));
}

static void ip_str(uint32_t ip, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

// Who it was, best first: the MAC vendor, the IP, the MAC.
static void who(const attack_log_t *e, char *out, size_t len)
{
    const char *v = wifi_manager_mac_vendor(e->src_mac);
    if (v[0] && strncmp(v, "randomized", 10) != 0) { strlcpy(out, v, len); return; }
    if (e->src_ip) { ip_str(e->src_ip, out, len); return; }
    if (v[0]) { strlcpy(out, "a device with a private MAC", len); return; }
    wifi_manager_format_mac(e->src_mac, out, len);
}

// The vendor, if the MAC has a real one; else "".
static void vendor(const attack_log_t *e, char *out, size_t len)
{
    const char *v = wifi_manager_mac_vendor(e->src_mac);
    if (v[0] && strncmp(v, "randomized", 10) != 0) strlcpy(out, v, len);
    else out[0] = 0;
}

// The headline's source: the IP, else the MAC, else "nearby" (radio).
static void source(const attack_log_t *e, char *out, size_t len)
{
    static const uint8_t zero[6] = { 0 };
    if (e->src_ip)                         ip_str(e->src_ip, out, len);
    else if (memcmp(e->src_mac, zero, 6))  wifi_manager_format_mac(e->src_mac, out, len);
    else                                   strlcpy(out, "nearby", len);
}

static const char *after(const char *p, const char *needle)
{
    const char *f = strstr(p, needle);
    return f ? f + strlen(needle) : NULL;
}

// ── Per type ──────────────────────────────────────────────────────────────────

// The detail after "Code CC-NN <name> | <source>: ". The code's name already
// says what it is, so these say only how much, as whom, or what.

static void http_detail(sb_t *s, const attack_log_t *e, const char *p)
{
    const char *key = http_engine_category_key(p);
    if (!key) {
        // Upstream's trap ("POST /path user:pass | UA=..") or the rate notice.
        unsigned long n;
        if (sscanf(p, "%lu HTTP requests", &n) == 1) {
            sb_fmt(s, "%lu more requests not listed", n);
            return;
        }
        char m[12], path[PATH_MAX_Q];
        tok(m, sizeof(m), p);
        const char *q = strchr(p, ' ');
        tok(path, sizeof(path), q ? q + 1 : "");
        if (!strcmp(m, "POST")) {
            char u[TOK_MAX];
            clean(u, sizeof(u), e->username, sizeof(e->username));
            sb_fmt(s, "attempt as %s on %s", u[0] ? u : "?", path[0] ? path : "/");
        } else {
            sb_fmt(s, "%s %s", m[0] ? m : "request", path[0] ? path : "/");
        }
        return;
    }
    // "<label> on <port>: <method> <path> ... UA=<ua>"
    const char *on = after(p, " on ");
    unsigned port = on ? (unsigned)strtoul(on, NULL, 10) : 0;
    const char *body = after(p, ": ");
    char m[12] = "", path[PATH_MAX_Q] = "", ua[20] = "";
    if (body) {
        tok(m, sizeof(m), body);
        const char *q = strchr(body, ' ');
        if (q) tok(path, sizeof(path), q + 1);
    }
    const char *u = after(p, "UA=");
    if (u) {
        size_t n = 0;
        while (u[n] && n < sizeof(ua) - 1 && u[n] != '/' && u[n] != ' ' && u[n] != ';' && u[n] != '(') n++;
        clean(ua, sizeof(ua), u, n);
    }
    const char *pth = path[0] ? path : "/";
    if (!strcmp(key, "login_post")) {
        char un[TOK_MAX];
        clean(un, sizeof(un), e->username, sizeof(e->username));
        sb_fmt(s, "attempt as %s on port %u", un[0] ? un : "?", port);
    } else if (!strcmp(key, "dotfile_path") || !strcmp(key, "dotdot_path")) {
        sb_fmt(s, "%s on port %u", pth, port);
    } else if (!strcmp(key, "scanner_ua") || !strcmp(key, "library_ua")) {
        sb_fmt(s, "%s requested %s on port %u", ua[0] ? ua : "?", pth, port);
    } else if (!strcmp(key, "oversize") || !strcmp(key, "non_http")) {
        sb_fmt(s, "on port %u", port);
    } else {        // odd_method, unclassified
        sb_fmt(s, "%s %s on port %u", m[0] ? m : "request", pth, port);
    }
}

static void adb_detail(sb_t *s, const char *p)
{
    char t[PATH_MAX_Q];
    unsigned long b;
    const char *q;
    if ((q = after(p, "ADB push ")) && strncmp(p, "ADB push incomplete", 19)) {
        const char *c = strstr(q, ", ");
        if (c && sscanf(c + 2, "%lu B", &b) == 1) {
            if (b >= 10240) sb_fmt(s, "push of %lu KB", b / 1024);
            else            sb_fmt(s, "push of %lu B", b);
            return;
        }
    }
    if (!strncmp(p, "ADB push incomplete", 19)) { sb_fmt(s, "push cut short"); return; }
    if ((q = after(p, "ADB $ ")))  { tok(t, TOK_MAX, q); sb_fmt(s, "shell ran '%s'", t); return; }
    if ((q = after(p, "ADB pull "))) { tok(t, sizeof(t), q); sb_fmt(s, "pull of %s", t); return; }
    if (!strncmp(p, "ADB connect", 11)) { sb_fmt(s, "connect"); return; }
    if ((q = after(p, "ADB OPEN "))) {
        size_t n = 0;
        while (q[n] && q[n] != ':' && n < 12) n++;
        clean(t, sizeof(t), q, n);
        sb_fmt(s, "opened %s", t[0] ? t : "a stream");
        return;
    }
    sb_fmt(s, "activity");
}

static void discovery_detail(sb_t *s, const char *p)
{
    // "New device <label>, ...", "<label> now ...", "Label <label> (from ..."
    char lab[40];
    const char *q = p;
    size_t n;
    if (!strncmp(p, "New device ", 11)) {
        q = p + 11;
        const char *c = strstr(q, ", ");
        n = c ? (size_t)(c - q) : strlen(q);
    } else if (!strncmp(p, "Label ", 6)) {
        q = p + 6;
        const char *c = strstr(q, " (");
        n = c ? (size_t)(c - q) : strlen(q);
    } else {
        const char *c = strstr(p, " now ");
        n = c ? (size_t)(c - p) : 0;
    }
    clean(lab, sizeof(lab), q, n);
    sb_fmt(s, "%s is searching the network", lab[0] ? lab : "a device");
}

static void new_device_detail(sb_t *s, const char *p)
{
    // "New device <name> on <where>" (admin/mikrotik.c); the router's text,
    // so cleaned like attacker text.
    char d[64];
    const char *q = !strncmp(p, "New device ", 11) ? p + 11 : p;
    clean(d, sizeof(d), q, strlen(q));
    sb_fmt(s, "%s", d[0] ? d : "a device joined");
}

size_t describe_event(const attack_log_t *e, char *out, size_t len)
{
    if (!out || !len) return 0;
    out[0] = '\0';
    if (!e) return 0;
    sb_t s = { .b = out, .cap = len < DESCRIBE_MAX ? len : DESCRIBE_MAX, .n = 0 };

    char p[sizeof(e->payload) + 1];
    payload_str(e, p, sizeof(p));
    char src[20], by[48], u[TOK_MAX], t[TOK_MAX];
    source(e, src, sizeof(src));
    clean(u, sizeof(u), e->username, sizeof(e->username));
    unsigned long a, b;
    const char *q;

    const code_row_t *c = code_row(e);
    sb_fmt(&s, "Code %s %s | %s: ", c->code, c->name, src);

    switch (e->type) {
    case ATTACK_SCAN:
        if (sscanf(p, "Port scan: %lu ports in %lu s", &a, &b) == 2) sb_fmt(&s, "%lu ports in %lu s", a, b);
        else if (sscanf(p, "Scan ended: %lu ports", &a) == 1)       sb_fmt(&s, "port scan, %lu ports in all", a);
        else                                                         sb_fmt(&s, "many ports");
        break;
    case ATTACK_PROBE:
        if (sscanf(p, "Probe: TCP SYN to port %lu", &a) == 1) {
            q = strchr(p, '(');
            tok(t, sizeof(t), q ? q + 1 : "");
            if (t[0]) sb_fmt(&s, "port %lu (%s)", a, t);
            else      sb_fmt(&s, "port %lu", a);
        } else {
            sb_fmt(&s, "a trap port");
        }
        break;
    case ATTACK_ARP_SWEEP:
        vendor(e, by, sizeof(by));
        if (sscanf(p, "ARP sweep: %lu hosts in %lu s", &a, &b) == 2)
            sb_fmt(&s, "%lu hosts in %lu s%s%s%s", a, b, by[0] ? " (" : "", by, by[0] ? ")" : "");
        else if (sscanf(p, "ARP sweep ended: %lu hosts", &a) == 1)
            sb_fmt(&s, "ARP sweep, %lu hosts in all", a);
        else
            sb_fmt(&s, "many hosts%s%s%s", by[0] ? " (" : "", by, by[0] ? ")" : "");
        break;
    case ATTACK_TELNET:
    case ATTACK_SSH:
    case ATTACK_FTP:
    case ATTACK_RTSP:
        sb_fmt(&s, "attempt as %s", u[0] ? u : "?");
        break;
    case ATTACK_SHELL:
        if ((q = after(p, "$ "))) {
            while (*q == ' ' || *q == '\t') q++;
            tok(t, sizeof(t), q);
            sb_fmt(&s, "ran '%s'", t[0] ? t : "?");
        } else if (!strncmp(p, "shell session opened", 20)) {
            sb_fmt(&s, "opened as %s", u[0] ? u : "?");
        } else {
            sb_fmt(&s, "activity");
        }
        break;
    case ATTACK_HTTP:
        http_detail(&s, e, p);
        break;
    case ATTACK_TRIPWIRE:
        if ((q = after(p, " on ")) && q - p - 4 > 0 && q - p - 4 < 16) {
            char svc[16];
            clean(svc, sizeof(svc), p, (size_t)(q - p - 4));
            sb_fmt(&s, "%s connection on %lu", svc, strtoul(q, NULL, 10));
        } else {
            sb_fmt(&s, "connection");
        }
        break;
    case ATTACK_ADB:
        adb_detail(&s, p);
        break;
    case ATTACK_ARP:
        who(e, by, sizeof(by));
        if (!strncmp(p, "Gateway ", 8)) sb_fmt(&s, "the gateway's MAC changed to %s", by);
        else if (strstr(p, " claims "))  sb_fmt(&s, "%s claims two addresses", by);
        else                             sb_fmt(&s, "by %s", by);
        break;
    case ATTACK_WIFI:
        if (sscanf(p, "Deauth attack: %lu forced disconnect", &a) == 1) {
            sb_fmt(&s, "%lu forced disconnect%s", a, a == 1 ? "" : "s");
        } else if (sscanf(p, "Broadcast deauth flood: %lu frames", &a) == 1) {
            sb_fmt(&s, "flood of %lu frames", a);
        } else {
            sb_fmt(&s, "attack nearby");
        }
        break;
    case ATTACK_DISCOVERY:
        discovery_detail(&s, p);
        break;
    case ATTACK_NEW_DEVICE:
        new_device_detail(&s, p);
        break;
    case ATTACK_ROUTER: {
        char d[80];
        const char *q = (p[0] == '[' && strlen(p) > 8) ? p + 8 : p;
        clean(d, sizeof(d), q, strlen(q));
        sb_fmt(&s, "%s", d[0] ? d : "configuration changed");
        break;
    }
    default:
        sb_fmt(&s, "type %d", (int)e->type);
        break;
    }
    return s.n;
}
