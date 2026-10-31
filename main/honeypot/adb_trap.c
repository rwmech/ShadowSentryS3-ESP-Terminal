// ADB trap. Protocol handling ported from Glutton (https://github.com/mushorg/glutton),
// protocols/tcp/adb.go and protocols/tcp/adb/adb.go, MIT, Copyright (c) 2016 MushMush.
// See THIRD_PARTY_NOTICES at the repository root.

#include "adb_trap.h"
#include "trap_listen.h"
#include "log_store.h"
#include "sd_log.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/sha256.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "ADB";

// ── Wire format (protocol.txt, SYNC.TXT) ──────────────────────────────────────

#define A_CNXN          0x4e584e43u
#define A_AUTH          0x48545541u
#define A_OPEN          0x4e45504fu
#define A_OKAY          0x59414b4fu
#define A_CLSE          0x45534c43u
#define A_WRTE          0x45545257u

#define ADB_HDR_LEN     24
#define ADB_VERSION     0x01000000u   // v1; the data checksum is always sent
#define HOST_REQ_MAX    255           // AOSP clips a host request to 255 bytes
#define SYNC_DATA_MAX   (64 * 1024)   // largest DATA chunk
#define SYNC_PATH_MAX   1024          // longest SEND/STAT/LIST/RECV path accepted
#define SYNC_PATH_KEEP  96            // bytes of a path kept for the log
#define SYNC_MTIME      1546300800u   // fixed mtime in STAT replies (2019-01-01)
#define SYNC_DIR_MODE   040771
#define ADB_LINE_MAX    256           // interactive shell line, longer runs as is

typedef enum { ST_FREE = 0, ST_SHELL, ST_SYNC } st_kind_t;
typedef enum { SY_HDR = 0, SY_PATH, SY_DATA } sy_state_t;

typedef struct {
    st_kind_t  kind;
    uint32_t   local, remote;           // our id and the client's id
    // interactive shell
    uint16_t   line_len;
    char       line[ADB_LINE_MAX];
    // sync request parser: requests may be split across or batched in WRTEs
    sy_state_t sy;
    uint8_t    hdr[8];
    uint8_t    hdr_have;
    char       id[5];
    uint32_t   need;                    // body bytes still to come
    uint16_t   path_len;
    char       path[SYNC_PATH_KEEP];
    // push in progress (SEND ... DONE): counted, hashed, and kept in PSRAM up to
    // ADB_MAX_BYTES (the session's byte limit) for the card
    bool       pushing;
    char       push_path[SYNC_PATH_KEEP];
    uint32_t   push_size;
    mbedtls_sha256_context sha;
    uint8_t   *buf;                     // PSRAM, NULL when nothing kept
    uint32_t   buf_len, buf_cap;
    bool       buf_lost;                // out of PSRAM: hashed but not kept
} adb_stream_t;

#define PUSH_BUF_START  (16 * 1024)

static void push_buf_free(adb_stream_t *st)
{
    free(st->buf);
    st->buf = NULL;
    st->buf_len = st->buf_cap = 0;
}

// Keep a DATA chunk. Doubling growth in PSRAM, never past ADB_MAX_BYTES.
static void push_keep(adb_stream_t *st, const uint8_t *d, uint32_t n)
{
    if (st->buf_lost || !n) return;
    if (st->buf_len + n > ADB_MAX_BYTES) { st->buf_lost = true; push_buf_free(st); return; }
    if (st->buf_len + n > st->buf_cap) {
        uint32_t cap = st->buf_cap ? st->buf_cap : PUSH_BUF_START;
        while (cap < st->buf_len + n) cap *= 2;
        if (cap > ADB_MAX_BYTES) cap = ADB_MAX_BYTES;
        uint8_t *nb = heap_caps_realloc(st->buf, cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!nb) { st->buf_lost = true; push_buf_free(st); return; }
        st->buf = nb;
        st->buf_cap = cap;
    }
    memcpy(st->buf + st->buf_len, d, n);
    st->buf_len += n;
}

typedef struct {
    int         sock;
    struct sockaddr_in addr;
    uint8_t     mac[6];
    char        ip[16];
    int64_t     deadline_us;
    uint32_t    rx_bytes;
    uint32_t    next_id;
    uint16_t    events, unlogged;
    bool        connected, authed_logged;
    const char *why;                    // why the session ended
    adb_stream_t st[ADB_MAX_STREAMS];
    uint8_t     body[ADB_MAX_DATA];
    uint8_t     tx[ADB_HDR_LEN + ADB_MAX_DATA];
    char        cmd[ADB_LINE_MAX];
    char        out[512];
} adb_sess_t;

static adb_sess_t *S;   // PSRAM; one session at a time

// Canned output for common recon commands (Glutton's table). Everything else,
// download-and-run chains included, succeeds silently.
static const struct { const char *cmd, *out; } SHELL_OUT[] = {
    { "id",       "uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),1007(log),"
                  "1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),"
                  "3003(inet),3006(net_bw_stats) context=u:r:shell:s0\n" },
    { "whoami",   "shell\n" },
    { "uname -m", "armv7l\n" },
    { "getprop ro.product.model",         "MBOX\n" },
    { "getprop ro.product.name",          "p281\n" },
    { "getprop ro.product.device",        "p281\n" },
    { "getprop ro.product.cpu.abi",       "armeabi-v7a\n" },
    { "getprop ro.build.version.release", "6.0.1\n" },
};

// Directories a STAT finds (everything else does not exist).
static const char *const SYNC_DIRS[] = {
    "/", "/data", "/data/local", "/data/local/tmp", "/sdcard", "/sdcard/Download",
    "/system", "/system/bin", "/dev",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

// Copy up to n attacker bytes as a printable C string: stops at NUL, anything
// outside 0x20..0x7e becomes '.'. dlen must be at least 1.
static void printable(char *dst, size_t dlen, const uint8_t *src, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < dlen; i++) {
        uint8_t c = src[i];
        if (c == 0) break;
        dst[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    dst[o] = '\0';
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
    return s;
}

static void adb_event(adb_sess_t *s, bool alert, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void adb_event(adb_sess_t *s, bool alert, const char *fmt, ...)
{
    attack_log_t e = {
        .type      = ATTACK_ADB,
        .src_ip    = s->addr.sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };
    memcpy(e.src_mac, s->mac, 6);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e.payload, sizeof(e.payload), fmt, ap);
    va_end(ap);

    if (s->events >= ADB_MAX_EVENTS) {          // bound flash and SD writes
        s->unlogged++;
        ESP_LOGD(TAG, "[%s] (not logged) %s", s->ip, e.payload);
        return;
    }
    s->events++;
    ESP_LOGW(TAG, "[%s] %s", s->ip, e.payload);
    log_store_append(&e);
    if (alert) telegram_notify(&e);
}

// ── Transport I/O (bounded by the session's time and byte budget) ─────────────

static bool rx_full(adb_sess_t *s, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        int64_t left_us = s->deadline_us - esp_timer_get_time();
        if (left_us <= 0)              { s->why = "time limit"; return false; }
        if (s->rx_bytes >= ADB_MAX_BYTES) { s->why = "byte limit"; return false; }

        // Idle timeout, but never past the session deadline.
        int64_t to_us = (int64_t)ADB_RECV_TIMEOUT_S * 1000000;
        if (to_us > left_us) to_us = left_us;
        struct timeval tv = { .tv_sec = to_us / 1000000, .tv_usec = to_us % 1000000 };
        if (tv.tv_sec == 0 && tv.tv_usec < 1000) tv.tv_usec = 1000;
        setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        size_t want = n, room = ADB_MAX_BYTES - s->rx_bytes;
        if (want > room) want = room;
        int r = recv(s->sock, p, want, 0);
        if (r <= 0) { s->why = r == 0 ? "closed by client" : "idle timeout or error"; return false; }
        p += r;
        n -= (size_t)r;
        s->rx_bytes += (uint32_t)r;
    }
    return true;
}

static bool tx_all(adb_sess_t *s, const uint8_t *buf, size_t n)
{
    while (n) {
        int r = send(s->sock, buf, n, 0);
        if (r <= 0) { s->why = "send failed"; return false; }
        buf += r;
        n -= (size_t)r;
    }
    return true;
}

// Build and send one transport message. data must not point into s->tx.
static bool adb_send(adb_sess_t *s, uint32_t cmd, uint32_t arg0, uint32_t arg1,
                     const void *data, size_t len)
{
    if (len > ADB_MAX_DATA) len = ADB_MAX_DATA;
    const uint8_t *d = data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) sum += d[i];

    uint8_t *t = s->tx;
    put_le32(t + 0,  cmd);
    put_le32(t + 4,  arg0);
    put_le32(t + 8,  arg1);
    put_le32(t + 12, (uint32_t)len);
    put_le32(t + 16, sum);
    put_le32(t + 20, cmd ^ 0xffffffffu);
    if (len) memcpy(t + ADB_HDR_LEN, d, len);
    return tx_all(s, t, ADB_HDR_LEN + len);
}

// ── Streams ───────────────────────────────────────────────────────────────────

static adb_stream_t *stream_find(adb_sess_t *s, uint32_t local)
{
    if (!local) return NULL;
    for (int i = 0; i < ADB_MAX_STREAMS; i++)
        if (s->st[i].kind != ST_FREE && s->st[i].local == local) return &s->st[i];
    return NULL;
}

static adb_stream_t *stream_alloc(adb_sess_t *s)
{
    for (int i = 0; i < ADB_MAX_STREAMS; i++)
        if (s->st[i].kind == ST_FREE) return &s->st[i];
    return NULL;
}

// A push that never reached DONE (client closed, or a session limit) is still
// a drop attempt: log what arrived.
static void push_abandon(adb_sess_t *s, adb_stream_t *st)
{
    if (!st->pushing) return;
    adb_event(s, true, "ADB push incomplete: %.40s, %lu B received",
              st->push_path, (unsigned long)st->push_size);
    mbedtls_sha256_free(&st->sha);
    push_buf_free(st);
    st->pushing = false;
}

static void stream_release(adb_sess_t *s, adb_stream_t *st)
{
    push_abandon(s, st);
    memset(st, 0, sizeof(*st));
}

static bool stream_close(adb_sess_t *s, adb_stream_t *st)
{
    uint32_t local = st->local, remote = st->remote;
    stream_release(s, st);
    return adb_send(s, A_CLSE, local, remote, NULL, 0);
}

// ── Shell ─────────────────────────────────────────────────────────────────────

// Canned output for cmd (trimmed) into s->out. Returns its length, 0 for none.
static size_t shell_output(adb_sess_t *s, const char *cmd)
{
    s->out[0] = '\0';
    for (size_t i = 0; i < sizeof(SHELL_OUT) / sizeof(SHELL_OUT[0]); i++) {
        if (strcmp(cmd, SHELL_OUT[i].cmd) == 0) {
            strlcpy(s->out, SHELL_OUT[i].out, sizeof(s->out));
            return strlen(s->out);
        }
    }
    // "echo X" prints X when X has no shell metacharacters.
    if (strncmp(cmd, "echo ", 5) == 0 && !strpbrk(cmd + 5, ";|&$`<>()\\")) {
        const char *a = cmd + 5;
        size_t n = strlen(a);
        while (n && (*a == '"' || *a == '\'')) { a++; n--; }
        while (n && (a[n - 1] == '"' || a[n - 1] == '\'')) n--;
        snprintf(s->out, sizeof(s->out), "%.*s\n", (int)n, a);
        return strlen(s->out);
    }
    return 0;
}

// One interactive line in st->line. Returns -1 on a send failure, 1 if the
// stream was closed, 0 to go on.
static int shell_line(adb_sess_t *s, adb_stream_t *st)
{
    strlcpy(s->cmd, st->line, sizeof(s->cmd));
    char *cmd = trim(s->cmd);
    if (!cmd[0]) return 0;

    adb_event(s, false, "ADB $ %.118s", cmd);
    if (strcmp(cmd, "exit") == 0) return stream_close(s, st) ? 1 : -1;

    shell_output(s, cmd);
    strlcat(s->out, ADB_SHELL_PROMPT, sizeof(s->out));
    return adb_send(s, A_WRTE, st->local, st->remote, s->out, strlen(s->out)) ? 0 : -1;
}

static bool shell_feed(adb_sess_t *s, adb_stream_t *st, const uint8_t *d, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = d[i];
        bool eol = (c == '\r' || c == '\n');
        if (!eol) {
            st->line[st->line_len++] = (c >= 0x20 && c < 0x7f) ? (char)c : (c == '\t' ? ' ' : '.');
            if (st->line_len < sizeof(st->line) - 1) continue;   // room left
        }
        st->line[st->line_len] = '\0';                          // EOL, or full: run it
        st->line_len = 0;
        int r = shell_line(s, st);
        if (r < 0) return false;
        if (r > 0) return true;                                 // stream gone
    }
    return true;
}

// ── Sync (adb push / pull) ────────────────────────────────────────────────────

static bool sync_reply(adb_sess_t *s, adb_stream_t *st, const void *buf, size_t n)
{
    return adb_send(s, A_WRTE, st->local, st->remote, buf, n);
}

// FAIL reply, then close the stream (the request stream is out of step).
// Returns -1 on a send failure, else 1 (stream closed).
static int sync_fail(adb_sess_t *s, adb_stream_t *st, const char *msg)
{
    uint8_t b[64];
    size_t ml = strlen(msg);
    if (ml > sizeof(b) - 8) ml = sizeof(b) - 8;
    memcpy(b, "FAIL", 4);
    put_le32(b + 4, (uint32_t)ml);
    memcpy(b + 8, msg, ml);
    if (!sync_reply(s, st, b, 8 + ml)) return -1;
    return stream_close(s, st) ? 1 : -1;
}

static bool sync_known_dir(char *path)
{
    size_t n = strlen(path);
    while (n > 1 && path[n - 1] == '/') path[--n] = '\0';    // path.Clean, the cheap part
    for (size_t i = 0; i < sizeof(SYNC_DIRS) / sizeof(SYNC_DIRS[0]); i++)
        if (strcmp(path, SYNC_DIRS[i]) == 0) return true;
    return false;
}

// A SEND/STAT/LIST/RECV path is complete in st->path. Returns -1/0/1 as above.
static int sync_path_done(adb_sess_t *s, adb_stream_t *st)
{
    for (uint16_t i = 0; i < st->path_len; i++) {
        char c = st->path[i];
        if (c < 0x20 || c >= 0x7f) st->path[i] = '.';
    }
    st->path[st->path_len] = '\0';

    if (strcmp(st->id, "SEND") == 0) {                       // "remote/path,mode"
        char *comma = strrchr(st->path, ',');
        if (comma) *comma = '\0';
        push_abandon(s, st);                                 // a SEND without DONE before it
        strlcpy(st->push_path, st->path, sizeof(st->push_path));
        st->push_size = 0;
        push_buf_free(st);
        st->buf_lost = false;
        mbedtls_sha256_init(&st->sha);
        mbedtls_sha256_starts(&st->sha, 0);
        st->pushing = true;
        ESP_LOGI(TAG, "[%s] push started: %s", s->ip, st->push_path);
        return 0;                                            // DATA follows, no reply
    }
    if (strcmp(st->id, "STAT") == 0) {
        uint8_t b[16] = { 'S', 'T', 'A', 'T' };              // all zero: does not exist
        ESP_LOGI(TAG, "[%s] stat %s", s->ip, st->path);
        if (sync_known_dir(st->path)) {
            put_le32(b + 4, SYNC_DIR_MODE);
            put_le32(b + 8, 4096);
            put_le32(b + 12, SYNC_MTIME);
        }
        return sync_reply(s, st, b, sizeof(b)) ? 0 : -1;
    }
    if (strcmp(st->id, "LIST") == 0) {
        uint8_t b[20] = { 'D', 'O', 'N', 'E' };              // an empty directory
        ESP_LOGI(TAG, "[%s] list %s", s->ip, st->path);
        return sync_reply(s, st, b, sizeof(b)) ? 0 : -1;
    }
    // RECV: a pull. Nothing to give.
    adb_event(s, false, "ADB pull %.100s", st->path);
    uint8_t b[8 + 25];
    memcpy(b, "FAIL", 4);
    put_le32(b + 4, 25);
    memcpy(b + 8, "No such file or directory", 25);
    return sync_reply(s, st, b, sizeof(b)) ? 0 : -1;
}

static int sync_push_done(adb_sess_t *s, adb_stream_t *st)
{
    if (!st->pushing) return sync_fail(s, st, "protocol failure");

    unsigned char dig[32];
    char hex[65];
    mbedtls_sha256_finish(&st->sha, dig);
    mbedtls_sha256_free(&st->sha);
    st->pushing = false;
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", dig[i]);

    // Keep the file on the card: /sd/adb/YYYY-MM-DD_HH-MM-SS_<sha8>.bin. The
    // buffer goes to the SD writer task, which frees it (also on failure).
    char file[64] = "";
    if (st->buf && st->buf_len == st->push_size) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char stamp[24];
        strftime(stamp, sizeof(stamp), "%Y-%m-%d_%H-%M-%S", &tm);
        snprintf(file, sizeof(file), SD_MOUNT_POINT "/adb/%s_%.8s.bin", stamp, hex);
        if (!sd_log_write_file(file, st->buf, st->buf_len)) file[0] = '\0';
        st->buf = NULL;                     // owned (and freed) by sd_log now
    }
    push_buf_free(st);
    ESP_LOGW(TAG, "[%s] push done: %s, %lu B, sha256 %s%s%s",
             s->ip, st->push_path, (unsigned long)st->push_size, hex,
             file[0] ? ", saved " : ", not saved", file);
    adb_event(s, true, "ADB push %.32s, %lu B, sha256 %s%s%s",
              st->push_path, (unsigned long)st->push_size, hex,
              file[0] ? ", saved " : "", file);

    uint8_t ok[8] = { 'O', 'K', 'A', 'Y' };
    return sync_reply(s, st, ok, sizeof(ok)) ? 0 : -1;
}

// A request header (id + length) is complete in st->hdr. Returns -1/0/1.
static int sync_header(adb_sess_t *s, adb_stream_t *st)
{
    memcpy(st->id, st->hdr, 4);
    st->id[4] = '\0';
    uint32_t len = le32(st->hdr + 4);

    if (strcmp(st->id, "DONE") == 0) return sync_push_done(s, st);   // len = mtime
    if (strcmp(st->id, "QUIT") == 0) return stream_close(s, st) ? 1 : -1;
    if (strcmp(st->id, "DATA") == 0) {
        if (len > SYNC_DATA_MAX) return sync_fail(s, st, "invalid DATA length");
        st->need = len;
        st->sy = len ? SY_DATA : SY_HDR;
        return 0;
    }
    if (strcmp(st->id, "SEND") == 0 || strcmp(st->id, "STAT") == 0 ||
        strcmp(st->id, "LIST") == 0 || strcmp(st->id, "RECV") == 0) {
        if (len > SYNC_PATH_MAX) return sync_fail(s, st, "path too long");
        st->need = len;
        st->path_len = 0;
        if (len) { st->sy = SY_PATH; return 0; }
        return sync_path_done(s, st);
    }
    char id[5];
    printable(id, sizeof(id), st->hdr, 4);
    ESP_LOGI(TAG, "[%s] sync: unknown request '%s'", s->ip, id);
    return sync_fail(s, st, "unknown sync request");
}

static bool sync_feed(adb_sess_t *s, adb_stream_t *st, const uint8_t *d, uint32_t n)
{
    while (n) {
        if (st->sy == SY_HDR) {
            uint32_t take = 8u - st->hdr_have;
            if (take > n) take = n;
            memcpy(st->hdr + st->hdr_have, d, take);
            st->hdr_have += (uint8_t)take;
            d += take;
            n -= take;
            if (st->hdr_have < 8) break;
            st->hdr_have = 0;
            int r = sync_header(s, st);
            if (r) return r > 0;                    // closed (st is free now) or failed
            continue;
        }

        uint32_t take = st->need < n ? st->need : n;
        if (st->sy == SY_PATH) {
            uint32_t room = (uint32_t)sizeof(st->path) - 1u - st->path_len;
            uint32_t c = take < room ? take : room;  // keep the head, skip the rest
            memcpy(st->path + st->path_len, d, c);
            st->path_len += (uint16_t)c;
        } else if (st->pushing) {                    // SY_DATA; DATA without SEND is skipped
            mbedtls_sha256_update(&st->sha, d, take);
            st->push_size += take;
            push_keep(st, d, take);
        }
        d += take;
        n -= take;
        st->need -= take;
        if (st->need == 0) {
            bool path = (st->sy == SY_PATH);
            st->sy = SY_HDR;
            if (path) {
                int r = sync_path_done(s, st);
                if (r) return r > 0;
            }
        }
    }
    return true;
}

// ── Transport messages ────────────────────────────────────────────────────────

static bool on_cnxn(adb_sess_t *s, uint32_t len)
{
    printable(s->cmd, sizeof(s->cmd), s->body, len);
    if (!s->connected)
        adb_event(s, true, "ADB connect, client %.104s", s->cmd);
    s->connected = true;
    // sizeof includes the NUL, which is part of the banner on the wire.
    return adb_send(s, A_CNXN, ADB_VERSION, ADB_MAX_DATA, ADB_BANNER, sizeof(ADB_BANNER));
}

static bool on_open(adb_sess_t *s, uint32_t remote, uint32_t len)
{
    if (!s->connected || remote == 0) return true;   // an offline device ignores OPEN

    // "name[,opts]:arg", e.g. "shell:id", "shell,v2,raw:ls", "sync:", "tcp:8080"
    printable(s->cmd, sizeof(s->cmd), s->body, len);
    char *name = s->cmd;
    char *colon = strchr(s->cmd, ':');
    char *arg = colon ? colon + 1 : s->cmd + strlen(s->cmd);
    if (colon) *colon = '\0';
    char *comma = strchr(name, ',');
    if (comma) *comma = '\0';

    bool known = !strcmp(name, "shell") || !strcmp(name, "exec") || !strcmp(name, "sync");
    adb_stream_t *st = known ? stream_alloc(s) : NULL;
    if (!st) {
        // Never forward tcp:, localabstract:, reverse:, ...: refuse like a failed service.
        adb_event(s, true, "ADB OPEN refused%s: %.40s:%.60s",
                  known ? " (streams full)" : "", name, arg);
        return adb_send(s, A_CLSE, 0, remote, NULL, 0);
    }
    adb_event(s, true, "ADB OPEN %.12s:%.100s", name, arg);

    st->kind   = !strcmp(name, "sync") ? ST_SYNC : ST_SHELL;
    st->local  = s->next_id++;
    st->remote = remote;
    if (!adb_send(s, A_OKAY, st->local, remote, NULL, 0)) return false;
    if (st->kind == ST_SYNC) return true;

    char *cmd = trim(arg);
    if (!strcmp(name, "shell") && !cmd[0])           // interactive
        return adb_send(s, A_WRTE, st->local, remote, ADB_SHELL_PROMPT, strlen(ADB_SHELL_PROMPT));

    size_t n = shell_output(s, cmd);                 // one-shot: output, then close
    if (n && !adb_send(s, A_WRTE, st->local, remote, s->out, n)) return false;
    return stream_close(s, st);
}

static bool on_wrte(adb_sess_t *s, uint32_t remote, uint32_t local, uint32_t len)
{
    adb_stream_t *st = stream_find(s, local);
    if (!st || st->remote != remote) return true;    // unknown stream: ignore
    if (!adb_send(s, A_OKAY, local, remote, NULL, 0)) return false;
    if (st->kind == ST_SYNC) return sync_feed(s, st, s->body, len);
    return shell_feed(s, st, s->body, len);
}

static bool dispatch(adb_sess_t *s, uint32_t cmd, uint32_t arg0, uint32_t arg1, uint32_t len)
{
    switch (cmd) {
    case A_CNXN: return on_cnxn(s, len);
    case A_OPEN: return on_open(s, arg0, len);
    case A_WRTE: return on_wrte(s, arg0, arg1, len);
    case A_CLSE: {
        adb_stream_t *st = stream_find(s, arg1);
        if (st && st->remote == arg0) stream_release(s, st);
        return true;
    }
    case A_AUTH:                                     // never asked for: note it once
        if (!s->authed_logged) {
            s->authed_logged = true;
            ESP_LOGI(TAG, "[%s] AUTH type %lu (not requested)", s->ip, (unsigned long)arg0);
        }
        return true;
    default:                                         // OKAY (flow control), STLS, SYNC, unknown
        return true;
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

static bool is_hex4(const uint8_t *b)
{
    for (int i = 0; i < 4; i++) {
        uint8_t c = b[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

// "000chost:version": the adb client to adb server framing (tcp/5037). Log it.
static void host_request(adb_sess_t *s, const uint8_t *hex)
{
    char h[5];
    memcpy(h, hex, 4);
    h[4] = '\0';
    unsigned long len = strtoul(h, NULL, 16);
    if (len > HOST_REQ_MAX) len = HOST_REQ_MAX;
    if (len && !rx_full(s, s->body, len)) return;
    printable(s->cmd, sizeof(s->cmd), s->body, len);
    adb_event(s, false, "ADB host request: %.100s", s->cmd);
    s->why = "host request";
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    adb_sess_t *s = S;
    memset(s, 0, sizeof(*s));
    s->sock        = sock;
    s->addr        = *addr;
    s->next_id     = 1;
    s->deadline_us = esp_timer_get_time() + (int64_t)ADB_SESSION_S * 1000000;
    s->why         = "?";
    strlcpy(s->ip, inet_ntoa(addr->sin_addr), sizeof(s->ip));
    wifi_manager_lookup_mac(addr->sin_addr.s_addr, s->mac);

    uint8_t hdr[ADB_HDR_LEN];
    uint32_t msgs = 0;

    if (!rx_full(s, hdr, 4)) goto done;
    if (is_hex4(hdr)) { host_request(s, hdr); goto done; }
    if (!rx_full(s, hdr + 4, ADB_HDR_LEN - 4)) goto done;

    for (;;) {
        uint32_t cmd = le32(hdr), arg0 = le32(hdr + 4), arg1 = le32(hdr + 8);
        uint32_t len = le32(hdr + 12), magic = le32(hdr + 20);

        if (magic != (cmd ^ 0xffffffffu)) {
            if (msgs == 0) {
                char first[17];
                printable(first, sizeof(first), hdr, 16);
                adb_event(s, false, "ADB port: not ADB, first bytes '%s'", first);
            }
            s->why = "bad magic";
            break;
        }
        if (len > ADB_MAX_DATA) {
            adb_event(s, false, "ADB message of %lu B refused (max %d)", (unsigned long)len, ADB_MAX_DATA);
            s->why = "message too large";
            break;
        }
        if (len && !rx_full(s, s->body, len)) break;
        if (!dispatch(s, cmd, arg0, arg1, len)) break;
        if (++msgs >= ADB_MAX_MSGS) { s->why = "message limit"; break; }
        if (!rx_full(s, hdr, ADB_HDR_LEN)) break;
    }

done:
    for (int i = 0; i < ADB_MAX_STREAMS; i++)
        if (s->st[i].kind != ST_FREE) stream_release(s, &s->st[i]);
    ESP_LOGI(TAG, "[%s] session ended (%s): %lu msgs, %lu B in, %u events logged, %u not (task stack free: %u B)",
             s->ip, s->why, (unsigned long)msgs, (unsigned long)s->rx_bytes,
             (unsigned)s->events, (unsigned)s->unlogged,
             (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
}

void adb_trap_task(void *arg)
{
    S = heap_caps_calloc(1, sizeof(*S), MALLOC_CAP_SPIRAM);
    if (!S) {
        ESP_LOGE(TAG, "No PSRAM for the session (%u B), ADB honeypot disabled", (unsigned)sizeof(*S));
        vTaskDelete(NULL);
    }
    int srv = trap_listen(ADB_PORT, ADB_BACKLOG);
    if (srv < 0) {
        ESP_LOGE(TAG, "No listen socket on port %d, ADB honeypot disabled", ADB_PORT);
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, session=%ds, idle=%ds, max %d B)",
             ADB_PORT, ADB_BACKLOG, ADB_SESSION_S, ADB_RECV_TIMEOUT_S, ADB_MAX_BYTES);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) { vTaskDelay(pdMS_TO_TICKS(200)); continue; }   // out of sockets: don't spin

        // A client that never reads must not pin the task in send().
        struct timeval tv = { .tv_sec = ADB_RECV_TIMEOUT_S, .tv_usec = 0 };
        setsockopt(csock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        ESP_LOGI(TAG, "Connect from %s", inet_ntoa(client.sin_addr));
        handle_client(csock, &client);
        close(csock);
    }
}
