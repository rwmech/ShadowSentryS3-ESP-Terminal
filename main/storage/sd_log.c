#include "sd_log.h"
#include "board.h"
#include "config.h"
#include "log_store.h"
#include "alarm.h"
#include "wifi_manager.h"
#include "ignore.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "lwip/ip4_addr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static const char *TAG = "SDLOG";

#define SD_QUEUE_DEPTH   32
#define SD_TASK_STACK    6144
#define SD_TASK_PRIO     2
#define SD_BUS_WAIT_MS   15000     // give up waiting for the display after this
#define BUS_READY_BIT    BIT0

typedef enum { SDM_ATTACK, SDM_ALARM, SDM_BOOT, SDM_FLUSH, SDM_FILE, SDM_SNAP } sdm_kind_t;

typedef struct {                    // SDM_FILE: the writer owns data and frees it
    char   path[64];
    void  *data;
    size_t len;
} sdm_file_t;

typedef struct {                    // SDM_SNAP: one "snap" line in the day log
    uint32_t ts;
    uint32_t size;
    char     action[16];
    char     file[64];
} sdm_snap_t;

typedef struct {
    sdm_kind_t kind;
    bool       ignored;        // SDM_ATTACK: source on the ignore list when it was logged
    union {
        attack_log_t e;
        alarm_info_t a;
        sdm_file_t   f;
        sdm_snap_t   s;
    };
} sdm_t;

static QueueHandle_t      s_q;
static EventGroupHandle_t s_eg;
static SemaphoreHandle_t  s_mutex;
static sd_status_t        s_status;
static sdmmc_card_t      *s_card;
static sd_stats_t        *s_stats;        // PSRAM, guarded by s_mutex
static bool               s_stats_dirty;

#define STATS_PATH     SD_MOUNT_POINT "/stats.bin"
#define STATS_MAGIC    0x53535354u      // "TSSS"
#define STATS_VERSION  2              // 2: by_type[STATS_TYPE_SLOTS], was [8]

static const char *TYPE_NAME[] = {
    "RTSP", "HTTP", "Telnet", "SSH", "FTP", "ARP spoof", "WiFi deauth", "Shell",
    "Port scan", "Probe", "ARP sweep",
};
_Static_assert(sizeof(TYPE_NAME) / sizeof(TYPE_NAME[0]) == ATTACK_TYPE_COUNT, "TYPE_NAME: one per attack_type_t");
_Static_assert(ATTACK_TYPE_COUNT <= STATS_TYPE_SLOTS, "stats.bin by_type[] too small: bump STATS_VERSION");

// stats.bin version 1: the same fields with by_type[8]. Read once and migrated.
typedef struct {
    uint32_t magic, version;
    uint32_t total;
    uint32_t by_type[8];
    uint32_t first_ts, last_ts;
    uint32_t hour_key[24];
    uint32_t hour_count[24];
    uint32_t day_key[STATS_DAYS];
    uint32_t day_count[STATS_DAYS];
    stat_src_t  src[STATS_SRC_MAX];
    stat_cred_t cred[STATS_CRED_MAX];
} sd_stats_v1_t;

// ── Listeners (other tasks: copy and queue only) ──────────────────────────────

static void on_attack(const attack_log_t *e)
{
    sdm_t m = { .kind = SDM_ATTACK, .ignored = ignore_match(e->src_ip, e->src_mac) };
    m.e = *e;
    if (xQueueSend(s_q, &m, 0) != pdTRUE) s_status.dropped++;
}

static void on_alarm(const alarm_info_t *a)
{
    // Only transitions are worth a line; count-only updates arrive every second.
    static alarm_state_t last_state = (alarm_state_t)-1;
    static uint32_t      last_id    = 0;
    if (a->state == last_state && a->id == last_id) return;
    last_state = a->state;
    last_id    = a->id;
    sdm_t m = { .kind = SDM_ALARM };
    m.a = *a;
    if (xQueueSend(s_q, &m, 0) != pdTRUE) s_status.dropped++;
}

void sd_log_bus_ready(void)
{
    if (s_eg) xEventGroupSetBits(s_eg, BUS_READY_BIT);
}

void sd_log_flush(void)
{
    sdm_t m = { .kind = SDM_FLUSH };
    // Front of the queue, so it isn't stuck behind a backlog of line writes.
    if (s_q) xQueueSendToFront(s_q, &m, pdMS_TO_TICKS(100));
}

bool sd_log_write_file(const char *path, void *data, size_t len)
{
    sdm_t m = { .kind = SDM_FILE };
    bool ok = s_q && s_status.mounted && data && len &&
              strncmp(path, SD_MOUNT_POINT "/", sizeof(SD_MOUNT_POINT)) == 0 &&
              strlcpy(m.f.path, path, sizeof(m.f.path)) < sizeof(m.f.path);
    if (ok) {
        m.f.data = data;
        m.f.len  = len;
        ok = xQueueSend(s_q, &m, 0) == pdTRUE;
        if (!ok) s_status.dropped++;
    }
    if (!ok) free(data);
    return ok;
}

bool sd_log_snap(uint32_t ts, const char *action, const char *file, size_t size)
{
    if (!s_q || !s_status.mounted) return false;
    sdm_t m = { .kind = SDM_SNAP };
    m.s.ts   = ts;
    m.s.size = (uint32_t)size;
    strlcpy(m.s.action, action ? action : "", sizeof(m.s.action));
    strlcpy(m.s.file, file ? file : "", sizeof(m.s.file));
    if (xQueueSend(s_q, &m, 0) != pdTRUE) { s_status.dropped++; return false; }
    return true;
}

void sd_log_status(sd_status_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_status;
    xSemaphoreGive(s_mutex);
}

// ── Formatting ────────────────────────────────────────────────────────────────

static void jesc(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    for (; in && *in && o + 7 < outlen; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c < 0x20)  { o += snprintf(out + o, outlen - o, "\\u%04x", c); }
        else out[o++] = (char)c;
    }
    out[o] = '\0';
}

static void fmt_ip(uint32_t ip_net, char *buf, size_t len)
{
    ip4_addr_t a = { .addr = ip_net };
    ip4addr_ntoa_r(&a, buf, (int)len);
}

static bool clock_valid(uint32_t ts) { return ts >= 1600000000; }

// /sd/log/YYYY-MM-DD.jsonl for the event's local date, or nosync.jsonl.
static void day_path(uint32_t ts, char *buf, size_t len)
{
    if (!clock_valid(ts)) ts = (uint32_t)time(NULL);
    if (!clock_valid(ts)) { snprintf(buf, len, SD_LOG_DIR "/nosync.jsonl"); return; }
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(buf, len, SD_LOG_DIR "/%04d-%02d-%02d.jsonl",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static int format_line(const sdm_t *m, char *buf, size_t len, uint32_t *ts_out)
{
    char ip[16], mac[WIFI_MAC_STR_LEN];
    switch (m->kind) {
    case SDM_ATTACK: {
        const attack_log_t *e = &m->e;
        char user_j[96], pass_j[192], pay_j[400];
        jesc(e->username, user_j, sizeof(user_j));
        jesc(e->password, pass_j, sizeof(pass_j));
        jesc(e->payload,  pay_j,  sizeof(pay_j));
        fmt_ip(e->src_ip, ip, sizeof(ip));
        wifi_manager_format_mac(e->src_mac, mac, sizeof(mac));
        uint8_t t = (uint8_t)e->type;
        *ts_out = clock_valid(e->timestamp) ? e->timestamp : (uint32_t)time(NULL);
        return snprintf(buf, len,
            "{\"kind\":\"attack\",\"ts\":%lu,\"ip\":\"%s\",\"type\":%u,\"tname\":\"%s\","
            "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\"%s}\n",
            (unsigned long)*ts_out, ip, t, t < ATTACK_TYPE_COUNT ? TYPE_NAME[t] : "?",
            user_j, pass_j, pay_j, mac, wifi_manager_mac_vendor(e->src_mac),
            m->ignored ? ",\"ignored\":true" : "");
    }
    case SDM_ALARM: {
        const alarm_info_t *a = &m->a;
        static const char *STATE[] = { "closed", "opened", "acknowledged" };
        fmt_ip(a->src_ip, ip, sizeof(ip));
        *ts_out = (uint32_t)time(NULL);
        return snprintf(buf, len,
            "{\"kind\":\"alarm\",\"ts\":%lu,\"event\":\"%s\",\"id\":%lu,\"ip\":\"%s\","
            "\"type\":%u,\"count\":%lu}\n",
            (unsigned long)*ts_out, a->state <= 2 ? STATE[a->state] : "?",
            (unsigned long)a->id, ip, (unsigned)a->type, (unsigned long)a->count);
    }
    case SDM_SNAP: {
        const sdm_snap_t *s = &m->s;
        char act_j[40], file_j[136];
        jesc(s->action, act_j, sizeof(act_j));
        jesc(s->file, file_j, sizeof(file_j));
        *ts_out = clock_valid(s->ts) ? s->ts : (uint32_t)time(NULL);
        return snprintf(buf, len,
            "{\"kind\":\"snap\",\"ts\":%lu,\"action\":\"%s\",\"file\":\"%s\",\"size\":%lu}\n",
            (unsigned long)*ts_out, act_j, file_j, (unsigned long)s->size);
    }
    case SDM_BOOT:
    default:
        *ts_out = (uint32_t)time(NULL);
        return snprintf(buf, len,
            "{\"kind\":\"boot\",\"ts\":%lu,\"fw\":\"%s\",\"reset\":%d}\n",
            (unsigned long)*ts_out, SHADOWSENTRY_VERSION, (int)esp_reset_reason());
    }
}

// ── Summary metrics ───────────────────────────────────────────────────────────

void sd_log_stats(sd_stats_t *out)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = *s_stats;
    xSemaphoreGive(s_mutex);
}

static void stats_reset(void)
{
    memset(s_stats, 0, sizeof(*s_stats));
    s_stats->magic   = STATS_MAGIC;
    s_stats->version = STATS_VERSION;
}

static uint32_t local_day(uint32_t ts)
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    return (uint32_t)((tm.tm_year + 1900) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday);
}

// Space-saving top-N: a miss evicts the smallest entry and inherits its count.
static void stats_add_source(const attack_log_t *e, uint32_t ts)
{
    stat_src_t *slot = NULL, *min = &s_stats->src[0];
    for (int i = 0; i < STATS_SRC_MAX; i++) {
        stat_src_t *s = &s_stats->src[i];
        if (s->count && s->ip == e->src_ip) { slot = s; break; }
        if (s->count < min->count) min = s;
    }
    if (!slot) {
        uint32_t base = min->count;
        memset(min, 0, sizeof(*min));
        min->ip = e->src_ip;
        min->count = base;
        min->first_ts = ts;
        slot = min;
    }
    slot->count++;
    slot->last_ts   = ts;
    slot->last_type = (uint8_t)e->type;
    memcpy(slot->mac, e->src_mac, sizeof(slot->mac));
}

static void stats_add_cred(const attack_log_t *e)
{
    if (e->type > ATTACK_FTP || (!e->username[0] && !e->password[0])) return;
    stat_cred_t *slot = NULL, *min = &s_stats->cred[0];
    for (int i = 0; i < STATS_CRED_MAX; i++) {
        stat_cred_t *c = &s_stats->cred[i];
        if (c->count && !strncmp(c->user, e->username, sizeof(c->user) - 1) &&
            !strncmp(c->pass, e->password, sizeof(c->pass) - 1)) { slot = c; break; }
        if (c->count < min->count) min = c;
    }
    if (!slot) {
        uint32_t base = min->count;
        memset(min, 0, sizeof(*min));
        strlcpy(min->user, e->username, sizeof(min->user));
        strlcpy(min->pass, e->password, sizeof(min->pass));
        min->count = base;
        slot = min;
    }
    slot->count++;
}

static void stats_add(const attack_log_t *e, uint32_t ts)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_stats->total++;
    if ((unsigned)e->type < ATTACK_TYPE_COUNT) s_stats->by_type[e->type]++;
    if (clock_valid(ts)) {
        if (!s_stats->first_ts) s_stats->first_ts = ts;
        s_stats->last_ts = ts;

        uint32_t hour = ts / 3600, h = hour % 24;
        if (s_stats->hour_key[h] != hour) { s_stats->hour_key[h] = hour; s_stats->hour_count[h] = 0; }
        s_stats->hour_count[h]++;

        uint32_t day = local_day(ts);
        int slot = -1, oldest = 0;
        for (int i = 0; i < STATS_DAYS; i++) {
            if (s_stats->day_key[i] == day) { slot = i; break; }
            if (s_stats->day_key[i] < s_stats->day_key[oldest]) oldest = i;
        }
        if (slot < 0) { slot = oldest; s_stats->day_key[slot] = day; s_stats->day_count[slot] = 0; }
        s_stats->day_count[slot]++;
    }
    stats_add_source(e, ts);
    stats_add_cred(e);
    s_stats_dirty = true;
    xSemaphoreGive(s_mutex);
}

static void stats_load(void)
{
    // A power cut between remove() and rename() in stats_save leaves only .tmp.
    FILE *f = fopen(STATS_PATH, "rb");
    if (!f) f = fopen(STATS_PATH ".tmp", "rb");
    if (!f) return;
    sd_stats_t *tmp = heap_caps_calloc(1, sizeof(*tmp), MALLOC_CAP_SPIRAM);
    uint32_t hdr[2] = { 0, 0 };
    bool ok = false;
    if (tmp && fread(hdr, sizeof(hdr), 1, f) == 1 && hdr[0] == STATS_MAGIC && fseek(f, 0, SEEK_SET) == 0) {
        if (hdr[1] == STATS_VERSION) {
            ok = fread(tmp, sizeof(*tmp), 1, f) == 1;
        } else if (hdr[1] == 1) {           // older firmware: by_type[8], migrate
            sd_stats_v1_t *v1 = heap_caps_malloc(sizeof(*v1), MALLOC_CAP_SPIRAM);
            if (v1 && fread(v1, sizeof(*v1), 1, f) == 1) {
                tmp->magic    = STATS_MAGIC;
                tmp->version  = STATS_VERSION;
                tmp->total    = v1->total;
                memcpy(tmp->by_type, v1->by_type, sizeof(v1->by_type));
                tmp->first_ts = v1->first_ts;
                tmp->last_ts  = v1->last_ts;
                memcpy(tmp->hour_key, v1->hour_key, sizeof(tmp->hour_key));
                memcpy(tmp->hour_count, v1->hour_count, sizeof(tmp->hour_count));
                memcpy(tmp->day_key, v1->day_key, sizeof(tmp->day_key));
                memcpy(tmp->day_count, v1->day_count, sizeof(tmp->day_count));
                memcpy(tmp->src, v1->src, sizeof(tmp->src));
                memcpy(tmp->cred, v1->cred, sizeof(tmp->cred));
                ok = true;
                ESP_LOGI(TAG, "Summary metrics: stats.bin v1 migrated to v%d", STATS_VERSION);
            }
            heap_caps_free(v1);
        }
    }
    if (ok) {
        // The card is not trusted to hold what we wrote: terminate the strings.
        for (int i = 0; i < STATS_CRED_MAX; i++) {
            tmp->cred[i].user[sizeof(tmp->cred[i].user) - 1] = '\0';
            tmp->cred[i].pass[sizeof(tmp->cred[i].pass) - 1] = '\0';
        }
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        // Events counted before the card mounted are added on top.
        uint32_t early = s_stats->total;
        *s_stats = *tmp;
        s_stats->total += early;
        xSemaphoreGive(s_mutex);
        ESP_LOGI(TAG, "Summary metrics restored (%lu events)", (unsigned long)s_stats->total);
    }
    heap_caps_free(tmp);
    fclose(f);
}

static void stats_save(void)
{
    sd_stats_t *tmp = heap_caps_malloc(sizeof(*tmp), MALLOC_CAP_SPIRAM);
    if (!tmp) return;
    sd_log_stats(tmp);
    s_stats_dirty = false;
    // Write-then-rename: a power cut mid-write can't corrupt the saved copy.
    FILE *f = fopen(STATS_PATH ".tmp", "wb");
    if (f) {
        bool ok = fwrite(tmp, sizeof(*tmp), 1, f) == 1;
        ok = (fclose(f) == 0) && ok;
        if (ok) { remove(STATS_PATH); rename(STATS_PATH ".tmp", STATS_PATH); }
    }
    heap_caps_free(tmp);
}

// ── Card ──────────────────────────────────────────────────────────────────────

static void refresh_space(void)
{
    uint64_t total = 0, free_b = 0;
    if (esp_vfs_fat_info(SD_MOUNT_POINT, &total, &free_b) == ESP_OK) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_status.total_bytes = total;
        s_status.free_bytes  = free_b;
        xSemaphoreGive(s_mutex);
    }
}

static bool mount(bool display_has_bus)
{
    // If the display never came up, the bus is ours to initialise.
    spi_bus_config_t bus = {
        .mosi_io_num = BOARD_LCD_MOSI, .miso_io_num = BOARD_LCD_MISO,
        .sclk_io_num = BOARD_LCD_SCLK, .quadwp_io_num = -1, .quadhd_io_num = -1,
        .max_transfer_sz = 4096,
    };
    esp_err_t r = display_has_bus ? ESP_OK
                : spi_bus_initialize(SPI3_HOST, &bus, SPI_DMA_CH_AUTO);
    if (r != ESP_OK) {
        ESP_LOGE(TAG, "SPI bus init failed: %s", esp_err_to_name(r));
        return false;
    }

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI3_HOST;
    host.max_freq_khz = SDMMC_FREQ_DEFAULT;        // 20 MHz
    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = BOARD_SD_CS;
    slot.host_id = SPI3_HOST;
    esp_vfs_fat_sdmmc_mount_config_t mc = {
        .format_if_mount_failed = false,           // never wipe a card on our own
        .max_files              = 4,
        .allocation_unit_size   = 16 * 1024,
    };
    r = esp_vfs_fat_sdspi_mount(SD_MOUNT_POINT, &host, &slot, &mc, &s_card);
    if (r != ESP_OK) {
        ESP_LOGE(TAG, "microSD mount failed: %s (card inserted? FAT32/exFAT?)",
                 esp_err_to_name(r));
        return false;
    }
    mkdir(SD_LOG_DIR, 0775);

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_status.mounted = true;
    strlcpy(s_status.card_name, s_card->cid.name, sizeof(s_status.card_name));
    xSemaphoreGive(s_mutex);
    refresh_space();
    ESP_LOGI(TAG, "microSD \"%s\" mounted: %llu MB, %llu MB free",
             s_status.card_name, s_status.total_bytes >> 20, s_status.free_bytes >> 20);
    return true;
}

// ── Writer task ───────────────────────────────────────────────────────────────

// SDM_FILE: write a whole file (parent directory created if missing), then free
// the caller's buffer. Write-then-rename, so a power cut never leaves a torn file
// under the final name.
static void write_file(sdm_file_t *f)
{
    char dir[sizeof(f->path)], tmp[sizeof(f->path) + 4];
    f->path[sizeof(f->path) - 1] = '\0';
    strlcpy(dir, f->path, sizeof(dir));
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir(dir, 0775); }
    snprintf(tmp, sizeof(tmp), "%s.tmp", f->path);

    FILE *fp = fopen(tmp, "wb");
    bool ok = fp && fwrite(f->data, 1, f->len, fp) == f->len;
    if (fp) ok = (fclose(fp) == 0) && ok;
    if (ok) { remove(f->path); ok = rename(tmp, f->path) == 0; }
    else remove(tmp);
    free(f->data);
    f->data = NULL;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (!ok) s_status.write_errors++;
    xSemaphoreGive(s_mutex);
    if (!ok) ESP_LOGW(TAG, "write to %s failed", f->path);
}

static void sd_task(void *arg)
{
    (void)arg;
    EventBits_t bits = xEventGroupWaitBits(s_eg, BUS_READY_BIT, pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(SD_BUS_WAIT_MS));
    if (!mount((bits & BUS_READY_BIT) != 0)) {
        // No card: keep draining so the listeners never back up.
        sdm_t m;
        for (;;) {
            xQueueReceive(s_q, &m, portMAX_DELAY);
            if (m.kind == SDM_FILE) free(m.f.data);
            if (m.kind == SDM_ATTACK)
                stats_add(&m.e, clock_valid(m.e.timestamp) ? m.e.timestamp : (uint32_t)time(NULL));
        }
    }
    stats_load();

    // Give SNTP a moment so the boot line (and early events) land in today's
    // file rather than nosync.jsonl; events keep queueing meanwhile.
    // Stop waiting early if the queue is filling, so a burst isn't dropped.
    for (int i = 0; i < 30 && !clock_valid((uint32_t)time(NULL)) &&
                    uxQueueMessagesWaiting(s_q) < SD_QUEUE_DEPTH / 2; i++)
        vTaskDelay(pdMS_TO_TICKS(1000));

    static char line[1024];
    char path[48];
    int64_t last_space_us = 0;
    for (;;) {
        sdm_t m;
        if (xQueueReceive(s_q, &m, pdMS_TO_TICKS(60000)) != pdTRUE) {
            if (s_stats_dirty) stats_save();
            continue;
        }
        if (m.kind == SDM_FLUSH) {          // reboot or OTA coming
            if (s_stats_dirty) stats_save();
            continue;
        }
        if (m.kind == SDM_FILE) {
            write_file(&m.f);
            continue;
        }

        uint32_t ts = 0;
        int n = format_line(&m, line, sizeof(line), &ts);
        if (m.kind == SDM_ATTACK) stats_add(&m.e, ts);
        if (n <= 0) continue;
        if (n >= (int)sizeof(line)) { n = sizeof(line) - 1; line[n - 1] = '\n'; }
        day_path(ts, path, sizeof(path));

        FILE *f = fopen(path, "a");
        bool ok = f && fwrite(line, 1, (size_t)n, f) == (size_t)n;
        if (f) ok = (fclose(f) == 0) && ok;   // close per line: power loss costs one line

        xSemaphoreTake(s_mutex, portMAX_DELAY);
        if (ok) s_status.lines_written++; else s_status.write_errors++;
        xSemaphoreGive(s_mutex);
        if (!ok) ESP_LOGW(TAG, "write to %s failed", path);

        if (esp_timer_get_time() - last_space_us > 60LL * 1000000) {
            last_space_us = esp_timer_get_time();
            refresh_space();
            if (s_stats_dirty) stats_save();
        }
    }
}

void sd_log_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_eg    = xEventGroupCreate();
    s_q     = xQueueCreate(SD_QUEUE_DEPTH, sizeof(sdm_t));
    s_stats = heap_caps_malloc(sizeof(*s_stats), MALLOC_CAP_SPIRAM);
    configASSERT(s_stats);
    stats_reset();
    log_store_add_listener(on_attack);
    alarm_add_listener(on_alarm);

    sdm_t boot = { .kind = SDM_BOOT };
    xQueueSend(s_q, &boot, 0);

    xTaskCreatePinnedToCore(sd_task, "sdlog", SD_TASK_STACK, NULL, SD_TASK_PRIO, NULL, 1);
}
