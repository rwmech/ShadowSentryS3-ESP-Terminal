// GET /api/crashes and the debug crash route. See api_crash.h.
// Fork addition, Robert Mech.

#include "api_crash.h"
#include "crash.h"
#include "json_esc.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "API-CRASH";

#define DEBUG_BODY_MAX  64

static bool send_all(int sock, const void *p, size_t n)
{
    const char *c = p;
    while (n) {
        int r = send(sock, c, n, 0);
        if (r <= 0) return false;
        c += r;
        n -= (size_t)r;
    }
    return true;
}

static void reply(int sock, const char *status, const char *body, size_t len)
{
    char hdr[192];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n", status, (unsigned)len);
    if (n > 0 && n < (int)sizeof(hdr) && send_all(sock, hdr, (size_t)n)) send_all(sock, body, len);
}

#define REPLY_LIT(sock, status, lit) reply((sock), (status), (lit), sizeof(lit) - 1)

// "METHOD /path" followed by a space or '?'.
static bool is_route(const char *req, const char *method_path)
{
    size_t n = strlen(method_path);
    return strncmp(req, method_path, n) == 0 && (req[n] == ' ' || req[n] == '?');
}

// ── GET /api/crashes ──────────────────────────────────────────────────────────

static void get_crashes(int sock)
{
    size_t log_len, rep_len;
    const char *log = crash_log_text(&log_len);
    const char *rep = crash_report_text(&rep_len);
    crash_summary_t last;
    bool this_boot = crash_last(&last) && last.this_boot;

    // The summaries are crash.c's own lines, checked when loaded; the report
    // is escaped (a newline becomes two bytes, anything else at most six).
    size_t cap = log_len + 6 * rep_len + 128;
    char *out = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM);
    if (!out) { REPLY_LIT(sock, "503 Service Unavailable", "{\"error\":\"out of memory\"}"); return; }

    int count = 0;
    size_t o = (size_t)snprintf(out, cap, "{\"crashes\":[");
    for (size_t i = 0; i < log_len; ) {
        const char *nl = memchr(log + i, '\n', log_len - i);
        size_t ll = nl ? (size_t)(nl - (log + i)) : log_len - i;
        if (ll && o + ll + 2 < cap) {
            if (count) out[o++] = ',';
            memcpy(out + o, log + i, ll);
            o += ll;
            count++;
        }
        i += ll + 1;
    }
    o += (size_t)snprintf(out + o, cap - o, "],\"count\":%d,\"latest_this_boot\":%s,\"latest\":\"",
                          count, this_boot ? "true" : "false");
    o += json_esc(rep, rep_len, out + o, cap - o - 3);
    out[o++] = '"';
    out[o++] = '}';
    reply(sock, "200 OK", out, o);
    free(out);
}

// ── POST /api/debug/crash {"type":"abort"|"fault"|"wdt"} ─────────────────────

static void post_debug_crash(int sock, const char *req, int req_len)
{
    const char *hend = strstr(req, "\r\n\r\n");
    long cl = -1;
    for (const char *p = req; hend && (p = strchr(p, '\n')) != NULL && p < hend; ) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) { cl = strtol(p + 15, NULL, 10); break; }
    }
    if (!hend || cl <= 0 || cl > DEBUG_BODY_MAX) {
        REPLY_LIT(sock, "400 Bad Request", "{\"error\":\"need a small JSON body\"}");
        return;
    }
    char body[DEBUG_BODY_MAX + 1];
    size_t start = (size_t)(hend + 4 - req);
    size_t have = (req_len > 0 && (size_t)req_len > start) ? (size_t)req_len - start : 0;
    if (have > (size_t)cl) have = (size_t)cl;
    memcpy(body, req + start, have);
    while (have < (size_t)cl) {                 // recv timeout set by admin_panel.c
        int n = recv(sock, body + have, (size_t)cl - have, 0);
        if (n <= 0) { REPLY_LIT(sock, "408 Request Timeout", "{\"error\":\"body incomplete\"}"); return; }
        have += (size_t)n;
    }
    body[have] = '\0';

    cJSON *root = cJSON_ParseWithLength(body, have);
    const cJSON *t = root ? cJSON_GetObjectItemCaseSensitive(root, "type") : NULL;
    int kind = -1;
    if (cJSON_IsString(t)) {
        if (!strcmp(t->valuestring, "abort"))      kind = 0;
        else if (!strcmp(t->valuestring, "fault")) kind = 1;
        else if (!strcmp(t->valuestring, "wdt"))   kind = 2;
    }
    cJSON_Delete(root);
    if (kind < 0) {
        REPLY_LIT(sock, "400 Bad Request", "{\"error\":\"type must be abort, fault or wdt\"}");
        return;
    }
    static const char *const NAMES[] = {"abort", "fault", "wdt"};
    char ok[48];
    int n = snprintf(ok, sizeof(ok), "{\"crash\":\"%s\"}", NAMES[kind]);
    reply(sock, "202 Accepted", ok, (size_t)n);
    shutdown(sock, SHUT_WR);
    vTaskDelay(pdMS_TO_TICKS(300));             // let the reply leave
    ESP_LOGE(TAG, "Deliberate crash (%s) from the debug route", NAMES[kind]);

    if (kind == 0) crash_debug_abort();
    if (kind == 1) {
        volatile uintptr_t addr = 0x10;         // unmapped: StoreProhibited
        *(volatile uint32_t *)addr = 1;
    }
    // kind 2, and anything left: spin with interrupts masked, so this core's
    // tick stops feeding the interrupt watchdog (its level-4 interrupt still runs).
    portDISABLE_INTERRUPTS();
    for (;;) { }
}

bool api_crash_handle(int sock, const char *req, int req_len)
{
    if (is_route(req, "GET /api/crashes"))       { get_crashes(sock); return true; }
    if (is_route(req, "POST /api/debug/crash"))  { post_debug_crash(sock, req, req_len); return true; }
    return false;
}
