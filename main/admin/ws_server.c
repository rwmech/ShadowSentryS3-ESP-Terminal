#include "ws_server.h"
#include "json_esc.h"
#include "alarm.h"
#include "log_store.h"
#include "geoip.h"
#include "wifi_manager.h"
#include "ignore.h"
#include "describe.h"
#include "correlate.h"
#include "config.h"
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "WS";

static httpd_handle_t s_server;
// Connected client socket fds (-1 = empty). Only ever touched from the httpd
// task (ws_handler on connect, broadcast_work on send), so no lock is needed.
static int s_clients[ADMIN_WS_MAX_CLIENTS];

// ── JSON helpers ────────────────────────────────────────────────────────────────

// JSON string escaper for attacker-supplied text: json_esc() (fork), which
// also turns bytes that are not UTF-8 into U+FFFD.
static void jesc(const char *in, char *out, size_t outlen)
{
    json_esc(in, (size_t)-1, out, outlen);
}

// Serialize one attack into the same per-entry JSON shape as the REST API, so
// the dashboard's existing render code consumes it unchanged. Geo fields are
// usually empty at push time (enrichment is async) and fill in on the next poll.
static void format_entry_json(const attack_log_t *e, char *buf, size_t len)
{
    char user_j[96], pass_j[192], pay_j[400], hl[DESCRIBE_MAX], hl_j[2 * DESCRIBE_MAX];
    jesc(e->username, user_j, sizeof(user_j));
    jesc(e->password, pass_j, sizeof(pass_j));
    jesc(e->payload,  pay_j,  sizeof(pay_j));
    describe_event(e, hl, sizeof(hl));
    jesc(hl, hl_j, sizeof(hl_j));

    char mac_j[WIFI_MAC_STR_LEN];
    wifi_manager_format_mac(e->src_mac, mac_j, sizeof(mac_j));
    const char *vendor = wifi_manager_mac_vendor(e->src_mac);

    geoip_info_t gi;
    char ctry_j[40] = "", org_j[100] = "";
    if (geoip_lookup(e->src_ip, &gi)) {
        jesc(gi.country, ctry_j, sizeof(ctry_j));
        jesc(gi.org,     org_j,  sizeof(org_j));
    } else {
        gi.cc[0] = gi.asn[0] = gi.tag[0] = '\0';
    }

    snprintf(buf, len,
        "{\"ts\":%lu,\"ip\":%lu,\"type\":%d,\"ign\":%s,"
        "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\","
        "\"mac\":\"%s\",\"vendor\":\"%s\","
        "\"cc\":\"%s\",\"country\":\"%s\",\"org\":\"%s\","
        "\"asn\":\"%s\",\"geotag\":\"%s\",\"headline\":\"%s\",\"tier\":\"%s\",\"code\":\"%s\"}",
        (unsigned long)e->timestamp, (unsigned long)e->src_ip, (int)e->type,
        ignore_match(e->src_ip, e->src_mac, describe_code(e)) ? "true" : "false",
        user_j, pass_j, pay_j, mac_j, vendor,
        gi.cc, ctry_j, org_j, gi.asn, gi.tag, hl_j, describe_tier_key(describe_tier(e)),
        describe_code(e));
}

// ── Client tracking (httpd task context only) ───────────────────────────────────

static void add_client(int fd)
{
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++)
        if (s_clients[i] == fd) return;              // already tracked
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++)
        if (s_clients[i] < 0) { s_clients[i] = fd; return; }
    ESP_LOGW(TAG, "client table full — dropping fd=%d", fd);
}

// ── Broadcast (runs on the httpd task via httpd_queue_work) ──────────────────────

// Carries a raw copy of the entry — NOT a pre-formatted string. The ~1 KB of
// stack that format_entry_json() needs must be spent on the httpd task, never on
// the appending task: honeypot traps like FTP run on a 3 KB stack and would
// overflow if the formatting happened in their context.
typedef struct { attack_log_t e; } ws_msg_t;

static void broadcast_text(const char *json);

#define WS_JSON_MAX 1536        // one entry, with its headline and code

static void broadcast_work(void *arg)
{
    ws_msg_t *m = (ws_msg_t *)arg;
    // 1 KB in PSRAM, made once: httpd is one task, so no reentry.
    static char *json;
    if (!json) json = heap_caps_malloc(WS_JSON_MAX, MALLOC_CAP_SPIRAM);
    if (!json) { free(m); return; }
    format_entry_json(&m->e, json, WS_JSON_MAX);       // heavy work on httpd stack
    free(m);
    broadcast_text(json);
}

// log_store listener — runs in the appending (honeypot/monitor) task, so it must
// stay tiny: just copy the raw entry and hand off to the httpd task. All string
// formatting and socket I/O happen there, off the caller's (small) stack.
static void on_attack(const attack_log_t *e)
{
    if (!s_server) return;
    ws_msg_t *m = (ws_msg_t *)malloc(sizeof(*m));
    if (!m) return;
    m->e = *e;
    if (httpd_queue_work(s_server, broadcast_work, m) != ESP_OK) free(m);
}

// ── Alarm push ──────────────────────────────────────────────────────────────────

void ws_format_alarm_json(const alarm_info_t *a, char *buf, size_t len)
{
    char mac[WIFI_MAC_STR_LEN], code_j[2 * DESCRIBE_CODE_LEN], hl_j[2 * DESCRIBE_MAX], vend_j[128];
    char intel[CORRELATE_SUMMARY_LEN], intel_j[2 * CORRELATE_SUMMARY_LEN];
    correlate_summary(a->src_ip, a->src_mac, intel, sizeof(intel));     // RAM only, "" when nothing is known
    jesc(intel, intel_j, sizeof(intel_j));
    wifi_manager_format_mac(a->src_mac, mac, sizeof(mac));
    jesc(a->code, code_j, sizeof(code_j));
    jesc(a->headline, hl_j, sizeof(hl_j));
    jesc(wifi_manager_mac_vendor(a->src_mac), vend_j, sizeof(vend_j));   // the OUI database's text
    snprintf(buf, len,
        "{\"state\":%d,\"cond\":\"%s\",\"code\":\"%s\",\"headline\":\"%s\","
        "\"id\":%lu,\"ip\":%lu,\"type\":%u,\"count\":%lu,"
        "\"first\":%lu,\"last\":%lu,\"mac\":\"%s\",\"vendor\":\"%s\","
        "\"acked_by\":\"%s\",\"resolved_by\":\"%s\",\"intel\":\"%s\"}",
        (int)a->state, alarm_cond_key(a->cond), code_j, hl_j,
        (unsigned long)a->id, (unsigned long)a->src_ip,
        (unsigned)a->type, (unsigned long)a->count,
        (unsigned long)a->first_ts, (unsigned long)a->last_ts,
        mac, vend_j,
        alarm_by_key(a->acked_by), alarm_by_key(a->resolved_by), intel_j);
}

static void broadcast_text(const char *json)
{
    httpd_ws_frame_t f = {
        .final   = true,
        .type    = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)json,
        .len     = strlen(json),
    };
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++) {
        if (s_clients[i] < 0) continue;
        if (httpd_ws_send_frame_async(s_server, s_clients[i], &f) != ESP_OK) {
            ESP_LOGI(TAG, "client fd=%d closed", s_clients[i]);
            s_clients[i] = -1;
        }
    }
}

static void alarm_work(void *arg)
{
    alarm_info_t *a = (alarm_info_t *)arg;
    char inner[WS_ALARM_JSON_MAX], json[WS_ALARM_JSON_MAX + 16];
    ws_format_alarm_json(a, inner, sizeof(inner));
    free(a);
    snprintf(json, sizeof(json), "{\"alarm\":%s}", inner);
    broadcast_text(json);
}

// alarm listener — runs on the alarm task; copy and hand off to the httpd task.
static void on_alarm(const alarm_info_t *info)
{
    if (!s_server) return;
    alarm_info_t *a = (alarm_info_t *)malloc(sizeof(*a));
    if (!a) return;
    *a = *info;
    if (httpd_queue_work(s_server, alarm_work, a) != ESP_OK) free(a);
}

// ── WebSocket endpoint ──────────────────────────────────────────────────────────

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {                   // handshake already completed
        int fd = httpd_req_to_sockfd(req);
        add_client(fd);
        ESP_LOGI(TAG, "client connected (fd=%d)", fd);
        return ESP_OK;
    }
    // We never expect data from the dashboard; drain any frame and move on.
    httpd_ws_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t r = httpd_ws_recv_frame(req, &f, 0);   // length only
    if (r == ESP_OK && f.len) {
        uint8_t tmp[64];
        if (f.len < sizeof(tmp)) { f.payload = tmp; httpd_ws_recv_frame(req, &f, sizeof(tmp)); }
    }
    return ESP_OK;
}

void ws_server_start(void)
{
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++) s_clients[i] = -1;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = ADMIN_WS_PORT;
    // The control socket is UDP on localhost. ADMIN_WS_PORT + 1 (9999) took
    // UDP 9999 from the Kasa discovery listener; this is the only httpd, so the
    // IDF default port is free.
    cfg.ctrl_port        = ESP_HTTPD_DEF_CTRL_PORT;
    cfg.max_open_sockets = ADMIN_WS_MAX_CLIENTS + 1;
    cfg.lru_purge_enable = true;
    cfg.stack_size       = 8192;                     // broadcast_work formats JSON here
    // The push only formats JSON and sends on sockets (no flash or NVS), so the
    // server task's stack goes to PSRAM.
    cfg.task_caps        = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;

    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed — live push disabled");
        s_server = NULL;
        return;
    }

    httpd_uri_t ws_uri = {
        .uri          = "/ws",
        .method       = HTTP_GET,
        .handler      = ws_handler,
        .is_websocket = true,
    };
    httpd_register_uri_handler(s_server, &ws_uri);

    log_store_add_listener(on_attack);
    alarm_add_listener(on_alarm);
    ESP_LOGI(TAG, "WebSocket push server on ws://<device-ip>:%d/ws", ADMIN_WS_PORT);
}
