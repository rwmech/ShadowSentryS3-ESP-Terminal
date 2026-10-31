#include "describe.h"
#include "http_engine.h"
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

// ── Tiers ─────────────────────────────────────────────────────────────────────

// Per type; ATTACK_HTTP is decided per event in describe_tier().
static const uint8_t TIER[ATTACK_TYPE_COUNT] = {
    [ATTACK_RTSP]      = TIER_SEV1,
    [ATTACK_HTTP]      = TIER_SEV2,
    [ATTACK_TELNET]    = TIER_SEV1,
    [ATTACK_SSH]       = TIER_SEV1,
    [ATTACK_FTP]       = TIER_SEV1,
    [ATTACK_ARP]       = TIER_SEV1,
    [ATTACK_WIFI]      = TIER_SEV1,
    [ATTACK_SHELL]     = TIER_SEV1,
    [ATTACK_SCAN]      = TIER_SEV1,
    [ATTACK_PROBE]     = TIER_SEV2,
    [ATTACK_ARP_SWEEP] = TIER_SEV1,
    [ATTACK_ADB]       = TIER_SEV1,
    [ATTACK_TRIPWIRE]  = TIER_SEV1,
    [ATTACK_DISCOVERY] = TIER_SEV3,
};
_Static_assert(ATTACK_DISCOVERY + 1 == ATTACK_TYPE_COUNT, "describe.c: add the new attack type to TIER[] and describe_event()");

describe_tier_t describe_tier(const attack_log_t *e)
{
    if (!e || (unsigned)e->type >= ATTACK_TYPE_COUNT) return TIER_SEV2;
    if (e->type == ATTACK_HTTP) {
        const char *k = http_engine_category_key(e->payload);
        if (k) return strcmp(k, "login_post") == 0 ? TIER_SEV1 : TIER_SEV2;
        // Upstream's single-port trap: a POST carries credentials.
        return strncmp(e->payload, "POST ", 5) == 0 ? TIER_SEV1 : TIER_SEV2;
    }
    return (describe_tier_t)TIER[e->type];
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

static const char *after(const char *p, const char *needle)
{
    const char *f = strstr(p, needle);
    return f ? f + strlen(needle) : NULL;
}

// ── Per type ──────────────────────────────────────────────────────────────────

static void http_headline(sb_t *s, const attack_log_t *e, const char *p, const char *ip)
{
    const char *key = http_engine_category_key(p);
    if (!key) {
        // Upstream's trap ("POST /path user:pass | UA=..") or the rate notice.
        unsigned long n;
        if (sscanf(p, "%lu HTTP requests", &n) == 1) {
            sb_fmt(s, "HTTP flood: %lu more requests from %s not listed", n, ip);
            return;
        }
        char m[12], path[PATH_MAX_Q];
        tok(m, sizeof(m), p);
        const char *q = strchr(p, ' ');
        tok(path, sizeof(path), q ? q + 1 : "");
        if (!strcmp(m, "POST")) {
            char u[TOK_MAX];
            clean(u, sizeof(u), e->username, sizeof(e->username));
            sb_fmt(s, "HTTP login attempt as %s from %s", u[0] ? u : "?", ip);
        } else {
            sb_fmt(s, "HTTP %s %s from %s", m[0] ? m : "request", path[0] ? path : "/", ip);
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
        sb_fmt(s, "HTTP login attempt as %s on port %u from %s", un[0] ? un : "?", port, ip);
    } else if (!strcmp(key, "dotfile_path")) {
        sb_fmt(s, "HTTP config-file probe for %s on port %u", pth, port);
    } else if (!strcmp(key, "dotdot_path")) {
        sb_fmt(s, "HTTP path-traversal probe for %s on port %u", pth, port);
    } else if (!strcmp(key, "scanner_ua")) {
        sb_fmt(s, "HTTP scanner %s requested %s on port %u", ua[0] ? ua : "?", pth, port);
    } else if (!strcmp(key, "library_ua")) {
        sb_fmt(s, "HTTP script (%s) requested %s on port %u", ua[0] ? ua : "?", pth, port);
    } else if (!strcmp(key, "odd_method")) {
        sb_fmt(s, "HTTP %s request for %s on port %u", m[0] ? m : "odd", pth, port);
    } else if (!strcmp(key, "oversize")) {
        sb_fmt(s, "Oversize HTTP request on port %u from %s", port, ip);
    } else if (!strcmp(key, "non_http")) {
        sb_fmt(s, "Non-HTTP data on web port %u from %s", port, ip);
    } else {
        sb_fmt(s, "HTTP %s %s on port %u from %s", m[0] ? m : "request", pth, port, ip);
    }
}

static void adb_headline(sb_t *s, const char *p, const char *ip)
{
    char t[PATH_MAX_Q];
    unsigned long b;
    const char *q;
    if ((q = after(p, "ADB push ")) && strncmp(p, "ADB push incomplete", 19)) {
        const char *c = strstr(q, ", ");
        if (c && sscanf(c + 2, "%lu B", &b) == 1) {
            if (b >= 10240) sb_fmt(s, "ADB device push of %lu KB from %s", b / 1024, ip);
            else            sb_fmt(s, "ADB device push of %lu B from %s", b, ip);
            return;
        }
    }
    if (!strncmp(p, "ADB push incomplete", 19)) { sb_fmt(s, "ADB push cut short from %s", ip); return; }
    if ((q = after(p, "ADB $ ")))  { tok(t, TOK_MAX, q); sb_fmt(s, "ADB shell ran '%s' from %s", t, ip); return; }
    if ((q = after(p, "ADB pull "))) { tok(t, sizeof(t), q); sb_fmt(s, "ADB pull of %s from %s", t, ip); return; }
    if (!strncmp(p, "ADB connect", 11)) { sb_fmt(s, "ADB connect from %s", ip); return; }
    if ((q = after(p, "ADB OPEN "))) {
        size_t n = 0;
        while (q[n] && q[n] != ':' && n < 12) n++;
        clean(t, sizeof(t), q, n);
        sb_fmt(s, "ADB opened %s from %s", t[0] ? t : "a stream", ip);
        return;
    }
    sb_fmt(s, "ADB activity from %s", ip);
}

static void discovery_headline(sb_t *s, const char *p)
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
    sb_fmt(s, "%s is searching the network", lab[0] ? lab : "A device");
}

size_t describe_event(const attack_log_t *e, char *out, size_t len)
{
    if (!out || !len) return 0;
    out[0] = '\0';
    if (!e) return 0;
    sb_t s = { .b = out, .cap = len < DESCRIBE_MAX ? len : DESCRIBE_MAX, .n = 0 };

    char p[sizeof(e->payload) + 1];
    size_t pl = strnlen(e->payload, sizeof(e->payload));
    memcpy(p, e->payload, pl);
    p[pl] = '\0';
    char ip[16], by[48], u[TOK_MAX], t[TOK_MAX];
    if (e->src_ip) ip_str(e->src_ip, ip, sizeof(ip));
    else           who(e, ip, sizeof(ip));
    clean(u, sizeof(u), e->username, sizeof(e->username));
    unsigned long a, b;
    const char *q;

    switch (e->type) {
    case ATTACK_SCAN:
        if (sscanf(p, "Port scan: %lu ports in %lu s", &a, &b) == 2)
            sb_fmt(&s, "Port scan from %s: %lu ports in %lu s", ip, a, b);
        else if (sscanf(p, "Scan ended: %lu ports", &a) == 1)
            sb_fmt(&s, "Port scan from %s ended: %lu ports in all", ip, a);
        else
            sb_fmt(&s, "Port scan from %s", ip);
        break;
    case ATTACK_PROBE:
        if (sscanf(p, "Probe: TCP SYN to port %lu", &a) == 1) {
            q = strchr(p, '(');
            tok(t, sizeof(t), q ? q + 1 : "");
            if (t[0]) sb_fmt(&s, "Probe of port %lu (%s) from %s", a, t, ip);
            else      sb_fmt(&s, "Probe of port %lu from %s", a, ip);
        } else {
            sb_fmt(&s, "Port probe from %s", ip);
        }
        break;
    case ATTACK_ARP_SWEEP:
        who(e, by, sizeof(by));
        if (sscanf(p, "ARP sweep: %lu hosts in %lu s", &a, &b) == 2)
            sb_fmt(&s, "ARP sweep: %lu hosts in %lu s from %s", a, b, by);
        else if (sscanf(p, "ARP sweep ended: %lu hosts", &a) == 1)
            sb_fmt(&s, "ARP sweep from %s ended: %lu hosts in all", by, a);
        else
            sb_fmt(&s, "ARP sweep from %s", by);
        break;
    case ATTACK_TELNET: sb_fmt(&s, "Telnet login attempt as %s from %s", u[0] ? u : "?", ip); break;
    case ATTACK_SSH:    sb_fmt(&s, "SSH login attempt as %s from %s", u[0] ? u : "?", ip); break;
    case ATTACK_FTP:    sb_fmt(&s, "FTP login attempt as %s from %s", u[0] ? u : "?", ip); break;
    case ATTACK_RTSP:   sb_fmt(&s, "Camera (RTSP) login attempt as %s from %s", u[0] ? u : "?", ip); break;
    case ATTACK_SHELL:
        if ((q = after(p, "$ "))) {
            while (*q == ' ' || *q == '\t') q++;
            tok(t, sizeof(t), q);
            sb_fmt(&s, "Shell session ran '%s' from %s", t[0] ? t : "?", ip);
        } else if (!strncmp(p, "shell session opened", 20)) {
            sb_fmt(&s, "Shell session opened as %s from %s", u[0] ? u : "?", ip);
        } else {
            sb_fmt(&s, "Shell activity from %s", ip);
        }
        break;
    case ATTACK_HTTP:
        http_headline(&s, e, p, ip);
        break;
    case ATTACK_TRIPWIRE:
        if ((q = after(p, " on ")) && q - p - 4 > 0 && q - p - 4 < 16) {
            char svc[16];
            clean(svc, sizeof(svc), p, (size_t)(q - p - 4));
            sb_fmt(&s, "%s connection attempt on %lu from %s", svc, strtoul(q, NULL, 10), ip);
        } else {
            sb_fmt(&s, "Tripwire connection from %s", ip);
        }
        break;
    case ATTACK_ADB:
        adb_headline(&s, p, ip);
        break;
    case ATTACK_ARP:
        who(e, by, sizeof(by));
        if (!strncmp(p, "Gateway ", 8)) sb_fmt(&s, "ARP spoof: the gateway's MAC changed to %s", by);
        else if (strstr(p, " claims "))  sb_fmt(&s, "ARP spoof: %s claims two addresses", by);
        else                             sb_fmt(&s, "ARP spoof by %s", by);
        break;
    case ATTACK_WIFI:
        if (sscanf(p, "Deauth attack: %lu forced disconnect", &a) == 1) {
            sb_fmt(&s, "Wi-Fi deauth: %lu forced disconnect%s", a, a == 1 ? "" : "s");
        } else if (sscanf(p, "Broadcast deauth flood: %lu frames", &a) == 1) {
            who(e, by, sizeof(by));
            sb_fmt(&s, "Wi-Fi deauth flood: %lu frames from %s", a, by);
        } else {
            sb_fmt(&s, "Wi-Fi attack nearby");
        }
        break;
    case ATTACK_DISCOVERY:
        discovery_headline(&s, p);
        break;
    default:
        sb_fmt(&s, "Event from %s", ip);
        break;
    }
    return s.n;
}
