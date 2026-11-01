// OV2640 panel-press snapshots. See cam.h.
//
// Settings copied from Elecrow's A-Camera example for this board (XCLK 20 MHz,
// JPEG quality 10, one frame buffer, vflip 0, hmirror 1, brightness 0,
// saturation 1). Their example streams RGB565 QVGA to the panel; here the
// sensor's own JPEG encoder is used, at VGA, so a face is recognisable.

#include "cam.h"
#include "board.h"
#include "display.h"
#include "sd_log.h"
#include "esp_camera.h"
#include "driver/i2c_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "CAM";

#define CAM_TASK_STACK    4096          // esp_camera_init() runs on it; PSRAM
#define CAM_TASK_PRIO     3             // below the traps and admin (5)
#define CAM_QUEUE_DEPTH   2
#define CAM_BUS_WAIT_MS   15000         // display_init() creates the bus well before
#define CAM_MIN_GAP_US    1000000       // one snapshot a second: distinct file names
#define CAM_FRAME_SIZE    FRAMESIZE_VGA // 640x480
#define CAM_JPEG_QUALITY  10            // Elecrow's value (0-63, lower is better)
#define CAM_JPEG_BUF      (96 * 1024)   // PSRAM; VGA at q10 is typically 20-50 KB
#define CAM_INIT_TRIES    4             // the last one at QVGA (Elecrow's size)
#define CAM_RETRY_MS      300

#define CAM_SETTLE_MAX_MS 2000

typedef struct {
    uint32_t ts;
    char     action[CAM_ACTION_MAX];
    uint16_t settle_ms;                 // let auto exposure settle first (cam_snap_lit)
    cam_done_cb_t done;                 // called after the capture, NULL for none
} cam_req_t;

static QueueHandle_t     s_q;
static SemaphoreHandle_t s_lock;        // guards s_jpeg and s_meta
static volatile bool     s_ready;
static volatile int      s_pending;     // queued or being captured
static uint8_t          *s_jpeg;        // PSRAM, s_meta.size bytes
static cam_meta_t        s_meta;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;
static int64_t           s_last_req_us = -CAM_MIN_GAP_US;

static void pending_add(int d)
{
    taskENTER_CRITICAL(&s_mux);
    s_pending += d;
    taskEXIT_CRITICAL(&s_mux);
}

// ── API ───────────────────────────────────────────────────────────────────────

bool cam_ready(void) { return s_ready; }

bool cam_snap(const char *action) { return cam_snap_lit(action, 0, NULL); }

bool cam_snap_lit(const char *action, int settle_ms, cam_done_cb_t done)
{
    if (!s_ready) return false;

    int64_t now = esp_timer_get_time();
    bool go;
    taskENTER_CRITICAL(&s_mux);
    go = now - s_last_req_us >= CAM_MIN_GAP_US;
    if (go) { s_last_req_us = now; s_pending++; }
    taskEXIT_CRITICAL(&s_mux);
    if (!go) return false;

    cam_req_t r = {
        .ts        = (uint32_t)time(NULL),
        .settle_ms = (uint16_t)(settle_ms <= 0 ? 0 : settle_ms > CAM_SETTLE_MAX_MS ? CAM_SETTLE_MAX_MS : settle_ms),
        .done      = done,
    };
    size_t n = 0;
    for (; action && action[n] && n < CAM_ACTION_MAX - 1; n++) {
        char c = action[n];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) { n = 0; break; }
        r.action[n] = c;
    }
    if (n == 0 || (action && action[n])) strlcpy(r.action, "press", sizeof(r.action));
    else r.action[n] = '\0';

    if (xQueueSend(s_q, &r, 0) != pdTRUE) {
        pending_add(-1);
        return false;
    }
    return true;
}

bool cam_last_meta(cam_meta_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_lock) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_meta;
    xSemaphoreGive(s_lock);
    return out->seq != 0;
}

uint8_t *cam_last_dup(size_t *len, cam_meta_t *meta)
{
    uint8_t *copy = NULL;
    *len = 0;
    if (meta) memset(meta, 0, sizeof(*meta));
    if (!s_lock) return NULL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_jpeg && s_meta.size) {
        copy = heap_caps_malloc(s_meta.size, MALLOC_CAP_SPIRAM);
        if (copy) {
            memcpy(copy, s_jpeg, s_meta.size);
            *len = s_meta.size;
            if (meta) *meta = s_meta;
        }
    }
    xSemaphoreGive(s_lock);
    return copy;
}

bool cam_wait_idle(int timeout_ms)
{
    for (int t = 0; s_pending > 0; t += 20) {
        if (t >= timeout_ms) return false;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return true;
}

// ── Capture ───────────────────────────────────────────────────────────────────

// With one buffer in CAMERA_GRAB_WHEN_EMPTY mode the frame waiting in it was
// captured whenever it was last returned, possibly minutes ago: return it and
// take the next one, which starts on the VSYNC after the press.
static camera_fb_t *grab_fresh(void)
{
    camera_fb_t *fb = esp_camera_fb_get();
    if (fb) esp_camera_fb_return(fb);
    fb = esp_camera_fb_get();
    if (fb && (fb->format != PIXFORMAT_JPEG || fb->len < 4 ||
               fb->buf[0] != 0xFF || fb->buf[1] != 0xD8)) {
        ESP_LOGW(TAG, "frame is not a JPEG (format %d, %u B), dropped",
                 (int)fb->format, (unsigned)fb->len);
        esp_camera_fb_return(fb);
        fb = NULL;
    }
    return fb;
}

static void snap_path(const cam_req_t *r, char *buf, size_t len)
{
    time_t t = (time_t)r->ts;
    if (r->ts >= 1600000000) {
        struct tm tm;
        localtime_r(&t, &tm);
        snprintf(buf, len, SD_MOUNT_POINT "/snap/%04d-%02d-%02d_%02d-%02d-%02d_%s.jpg",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, r->action);
    } else {
        snprintf(buf, len, SD_MOUNT_POINT "/snap/nosync_%lu_%s.jpg",
                 (unsigned long)r->ts, r->action);
    }
}

// cam_snap_lit(): the panel has just turned white. The sensor's auto exposure
// adjusts over a few frames, so take and drop frames for settle_ms; the frame
// kept starts after that.
static int settle(int ms)
{
    int dropped = 0;
    int64_t end = esp_timer_get_time() + (int64_t)ms * 1000;
    while (esp_timer_get_time() < end) {
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) break;
        esp_camera_fb_return(fb);
        dropped++;
    }
    return dropped;
}

static void capture(const cam_req_t *r)
{
    int64_t t0 = esp_timer_get_time();
    int dropped = r->settle_ms ? settle(r->settle_ms) : 0;
    int64_t t1 = esp_timer_get_time();
    camera_fb_t *fb = grab_fresh();
    if (!fb) {
        if (r->done) r->done(false);
        ESP_LOGW(TAG, "snapshot \"%s\" failed: no frame", r->action);
        return;
    }
    size_t   n = fb->len;
    uint16_t w = (uint16_t)fb->width, h = (uint16_t)fb->height;
    uint8_t *keep = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
    uint8_t *disk = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
    if (keep) memcpy(keep, fb->buf, n);
    if (disk) memcpy(disk, fb->buf, n);
    esp_camera_fb_return(fb);
    if (r->done) r->done(true);             // the frame is taken: the light can go
    int ms = (int)((esp_timer_get_time() - t1) / 1000);
    if (r->settle_ms)
        ESP_LOGI(TAG, "lit snapshot: %d frames dropped in %d ms of settling, request to frame %d ms",
                 dropped, (int)((t1 - t0) / 1000), (int)((esp_timer_get_time() - t0) / 1000));

    char path[CAM_FILE_MAX];
    snap_path(r, path, sizeof(path));
    // sd_log owns disk from here, written or not.
    bool saved = disk && sd_log_write_file(path, disk, n);
    if (saved) sd_log_snap(r->ts, r->action, path, n);

    uint32_t seq = 0;
    if (keep) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        uint8_t *old = s_jpeg;
        s_jpeg = keep;
        seq = s_meta.seq + 1;
        s_meta.seq    = seq;
        s_meta.ts     = r->ts;
        s_meta.size   = (uint32_t)n;
        s_meta.width  = w;
        s_meta.height = h;
        strlcpy(s_meta.action, r->action, sizeof(s_meta.action));
        strlcpy(s_meta.file, saved ? path : "", sizeof(s_meta.file));
        xSemaphoreGive(s_lock);
        free(old);
    }
    ESP_LOGI(TAG, "snapshot #%lu \"%s\": %ux%u, %u B in %d ms, %s, stack high-water %u B",
             (unsigned long)seq, r->action, w, h, (unsigned)n, ms,
             saved ? path : "not saved (no card, or SD queue full)",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

// ── Task ──────────────────────────────────────────────────────────────────────

static bool sensor_start(void)
{
    // Touch creates the bus in display_init() on the UI task; wait for it.
    i2c_master_bus_handle_t bus = NULL;
    for (int t = 0; !(bus = display_i2c_bus()) && t < CAM_BUS_WAIT_MS; t += 100)
        vTaskDelay(pdMS_TO_TICKS(100));
    if (!bus) {
        ESP_LOGW(TAG, "no I2C bus from the display after %d s, camera disabled",
                 CAM_BUS_WAIT_MS / 1000);
        return false;
    }
    // esp32-camera finds the bus by port number; make sure it is the same one.
    i2c_master_bus_handle_t by_port = NULL;
    if (i2c_master_get_bus_handle((i2c_port_num_t)BOARD_I2C_PORT, &by_port) != ESP_OK ||
        by_port != bus) {
        ESP_LOGE(TAG, "I2C port %d is not the touch bus, camera disabled", BOARD_I2C_PORT);
        return false;
    }

    size_t int0 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps0  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    // Elecrow's example has the camera alone on the bus. Hold touch polling
    // through the SCCB init (a few hundred register writes) so no FT6236
    // traffic lands between them; touch reads as released meanwhile.
    display_touch_hold(true);
    vTaskDelay(pdMS_TO_TICKS(50));              // a touch read under way finishes

    // No RESET or PWDN pin: the only reset is the SRST that esp_camera_init()
    // writes first, so a retry starts the sensor from scratch. The last try
    // uses Elecrow's QVGA, which takes the sensor's CIF path, not SVGA.
    // Worst case (no sensor fitted) holds touch for about 1.5 s at boot.
    esp_err_t err = ESP_FAIL;
    sensor_t *s = NULL;
    for (int attempt = 1; attempt <= CAM_INIT_TRIES; attempt++) {
        framesize_t fs = attempt < CAM_INIT_TRIES ? CAM_FRAME_SIZE : FRAMESIZE_QVGA;
        camera_config_t c = {
            .pin_pwdn      = BOARD_CAM_PWDN,
            .pin_reset     = BOARD_CAM_RESET,
            .pin_xclk      = BOARD_CAM_XCLK,
            .pin_sccb_sda  = -1,                    // -1: use the bus already on sccb_i2c_port
            .pin_sccb_scl  = -1,
            .pin_d7 = BOARD_CAM_D7, .pin_d6 = BOARD_CAM_D6,
            .pin_d5 = BOARD_CAM_D5, .pin_d4 = BOARD_CAM_D4,
            .pin_d3 = BOARD_CAM_D3, .pin_d2 = BOARD_CAM_D2,
            .pin_d1 = BOARD_CAM_D1, .pin_d0 = BOARD_CAM_D0,
            .pin_vsync     = BOARD_CAM_VSYNC,
            .pin_href      = BOARD_CAM_HREF,
            .pin_pclk      = BOARD_CAM_PCLK,
            .xclk_freq_hz  = BOARD_CAM_XCLK_HZ,
            // Unused on the S3 (LCD_CAM makes XCLK), set clear of the backlight
            // (timer/channel 0) and buzzer (1) anyway.
            .ledc_timer    = LEDC_TIMER_2,
            .ledc_channel  = LEDC_CHANNEL_2,
            .pixel_format  = PIXFORMAT_JPEG,
            .frame_size    = fs,
            .jpeg_quality  = CAM_JPEG_QUALITY,
            .fb_count      = 1,
            .fb_location   = CAMERA_FB_IN_PSRAM,
            .grab_mode     = CAMERA_GRAB_WHEN_EMPTY,
            .sccb_i2c_port = BOARD_I2C_PORT,
            .jpeg_buffer_size = CAM_JPEG_BUF,
        };
        err = esp_camera_init(&c);
        if (err == ESP_OK) {
            s = esp_camera_sensor_get();
            if (s && s->id.PID == OV2640_PID) {     // as Elecrow's A-Camera example
                s->set_vflip(s, 0);
                s->set_hmirror(s, 1);
                s->set_brightness(s, 0);
                s->set_saturation(s, 1);
            }
            if (attempt > 1)
                ESP_LOGW(TAG, "camera init took %d tries", attempt);
            break;
        }
        ESP_LOGW(TAG, "camera init try %d of %d failed (%s)", attempt, CAM_INIT_TRIES,
                 esp_err_to_name(err));
        // Not detected is retried too: on the board the probe has missed the
        // sensor on one boot and found it on the next. The wait lets XCLK
        // (left running by the failed init) settle the sensor, and the bus
        // reset (9 SCL pulses and a STOP; safe, touch is held) frees a
        // sensor left mid-byte by a warm reset.
        if (attempt < CAM_INIT_TRIES) {
            vTaskDelay(pdMS_TO_TICKS(CAM_RETRY_MS));
            esp_err_t r = i2c_master_bus_reset(bus);
            if (r != ESP_OK) ESP_LOGW(TAG, "I2C bus reset: %s", esp_err_to_name(r));
            // For the log only: does the sensor ACK now, with XCLK running?
            r = i2c_master_probe(bus, OV2640_SCCB_ADDR, 50);
            ESP_LOGI(TAG, "SCCB 0x%02x before try %d: %s", OV2640_SCCB_ADDR, attempt + 1,
                     r == ESP_OK ? "ACK" : esp_err_to_name(r));
        }
    }
    display_touch_hold(false);

    size_t int1 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps1  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "no camera (%s), snapshots disabled; internal heap free %u -> %u B",
                 esp_err_to_name(err), (unsigned)int0, (unsigned)int1);
        return false;
    }

    // Test frame: proves the DVP path, not just SCCB, before calling it ready.
    int64_t t0 = esp_timer_get_time();
    camera_fb_t *fb = grab_fresh();
    if (!fb) {
        ESP_LOGW(TAG, "sensor PID 0x%02x answers but gives no JPEG frame, camera disabled",
                 s ? s->id.PID : 0);
        esp_camera_deinit();
        return false;
    }
    ESP_LOGI(TAG, "camera ready: PID 0x%02x, %ux%u JPEG q%d, test frame %u B in %d ms",
             s ? s->id.PID : 0, (unsigned)fb->width, (unsigned)fb->height,
             CAM_JPEG_QUALITY, (unsigned)fb->len,
             (int)((esp_timer_get_time() - t0) / 1000));
    esp_camera_fb_return(fb);
    ESP_LOGI(TAG, "internal heap free %u -> %u B (camera costs %d B), PSRAM free %u -> %u B",
             (unsigned)int0, (unsigned)int1, (int)int0 - (int)int1,
             (unsigned)ps0, (unsigned)ps1);
    return true;
}

static void cam_task(void *arg)
{
    (void)arg;
    if (!sensor_start()) {
        vTaskDeleteWithCaps(NULL);              // gives its stack back; cam_snap stays a no-op
        return;
    }
    s_ready = true;
    for (;;) {
        cam_req_t r;
        xQueueReceive(s_q, &r, portMAX_DELAY);
        capture(&r);
        pending_add(-1);
    }
}

void cam_snap_init(void)
{
    if (!CAM_ENABLE) {
        ESP_LOGW(TAG, "camera off (CAM_ENABLE 0), snapshots disabled");
        return;
    }
    s_lock = xSemaphoreCreateMutex();
    s_q    = xQueueCreate(CAM_QUEUE_DEPTH, sizeof(cam_req_t));
    if (!s_lock || !s_q ||
        // Stack in PSRAM (CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY): this task
        // never touches flash, and internal RAM is the scarce pool.
        xTaskCreatePinnedToCoreWithCaps(cam_task, "cam", CAM_TASK_STACK, NULL,
                                        CAM_TASK_PRIO, NULL, 1,
                                        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        ESP_LOGE(TAG, "no memory for the camera task, camera disabled");
    }
}
