// Waveshare ESP32-S3-Touch-LCD-4.3B front panel: 800 x 480 RGB LCD
// (esp_lcd_panel_rgb), GT911 touch and the CH422G expander (backlight, resets,
// SD chip select), as Waveshare's demo drives them (board_waveshare43.h has
// the sources). The CrowPanel's driver is display.cpp.
//
// Frame buffers: two in PSRAM, LVGL in direct mode drawing straight into the
// one not on the glass (LVGL copies each finished area to the other buffer);
// flush hands the buffer to the panel and waits for the frame that shows it,
// the demo's "double buffer, direct mode" (lvgl_port.c, avoid-tear mode 3).
// The panel scans out through two 800 x 10 px bounce buffers in internal
// DMA RAM, filled from PSRAM by the driver's interrupt, so PSRAM traffic from
// Wi-Fi cannot starve the LCD (the drift fix), and the build's XIP from PSRAM
// keeps them filling while flash is written.
//
// Touch, expander and RTC are on the new i2c_master driver: the demo's legacy
// driver would abort IDF 5.4 next to the new one.

#include "board.h"
#if BOARD_IS_WAVESHARE43

#include "display.h"
#include "lvgl.h"
#include "buzzer.h"
#include "settings.h"
#include "sd_log.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_rgb.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "DISPLAY";

#define I2C_TIMEOUT_MS      50
#define FLUSH_WAIT_MS       100     // a frame is 26 ms at 39 Hz; never hang the UI

// ── I2C bus and CH422G expander ───────────────────────────────────────────────

static i2c_master_bus_handle_t s_i2c_bus;
static i2c_master_dev_handle_t s_exp_mode, s_exp_io, s_exp_oc;
static SemaphoreHandle_t       s_exp_lock;  // the IO byte: UI task and a settings save
static uint8_t                 s_exp_io_val;

static esp_err_t exp_write(i2c_master_dev_handle_t d, uint8_t v)
{
    return i2c_master_transmit(d, &v, 1, I2C_TIMEOUT_MS);
}

// Set and clear EXIO bits; the bank stays all output.
static esp_err_t exp_io(uint8_t set, uint8_t clr)
{
    if (!s_exp_io) return ESP_ERR_INVALID_STATE;
    if (s_exp_lock) xSemaphoreTake(s_exp_lock, portMAX_DELAY);
    s_exp_io_val = (uint8_t)((s_exp_io_val | set) & ~clr);
    esp_err_t r = exp_write(s_exp_io, s_exp_io_val);
    if (s_exp_lock) xSemaphoreGive(s_exp_lock);
    return r;
}

static esp_err_t add_dev(uint8_t addr, i2c_master_dev_handle_t *out)
{
    i2c_device_config_t dc = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = addr,
        .scl_speed_hz    = BOARD_I2C_HZ,
    };
    return i2c_master_bus_add_device(s_i2c_bus, &dc, out);
}

static bool i2c_init(void)
{
    i2c_master_bus_config_t bc = {
        .i2c_port          = BOARD_I2C_PORT,
        .sda_io_num        = BOARD_I2C_SDA,
        .scl_io_num        = BOARD_I2C_SCL,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,   // the board also has 4.7 k pull-ups
    };
    if (i2c_new_master_bus(&bc, &s_i2c_bus) != ESP_OK) {
        s_i2c_bus = NULL;
        ESP_LOGE(TAG, "I2C init failed: no touch, backlight or microSD select");
        return false;
    }
    return true;
}

// The demo's order (ESP32_Display_Panel, BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_4_3_B.h):
// all EXIO outputs; LCD reset low 10 ms, then 100 ms; touch INT low, 10 ms,
// touch reset low 100 ms, then 200 ms, INT released. The card stays selected
// from the first write (the SD demo); DO0 and DO1 off.
static bool expander_init(void)
{
    s_exp_lock = xSemaphoreCreateMutex();
    if (!s_exp_lock || add_dev(BOARD_EXP_ADDR_MODE, &s_exp_mode) != ESP_OK ||
        add_dev(BOARD_EXP_ADDR_IO, &s_exp_io) != ESP_OK ||
        add_dev(BOARD_EXP_ADDR_OC, &s_exp_oc) != ESP_OK) {
        ESP_LOGE(TAG, "CH422G: no memory for its I2C devices");
        s_exp_io = NULL;
        return false;
    }
    if (exp_write(s_exp_mode, 0x01) != ESP_OK) {             // IO0..7 outputs, OC push-pull
        ESP_LOGE(TAG, "CH422G not answering at 0x%02x", BOARD_EXP_ADDR_MODE);
        s_exp_io = NULL;
        return false;
    }
    exp_write(s_exp_oc, 0x0F);                                // OC high: DO0, DO1 off
    exp_io(0, 0xFF);                                          // resets held, backlight off, card selected
    vTaskDelay(pdMS_TO_TICKS(10));
    exp_io(BOARD_EXP_LCD_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(100));

    gpio_reset_pin(BOARD_TOUCH_INT);
    gpio_set_direction(BOARD_TOUCH_INT, GPIO_MODE_OUTPUT);
    gpio_set_level(BOARD_TOUCH_INT, 0);                       // GT911 address 0x5D
    vTaskDelay(pdMS_TO_TICKS(10));
    exp_io(0, BOARD_EXP_TP_RST);
    vTaskDelay(pdMS_TO_TICKS(100));
    exp_io(BOARD_EXP_TP_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(200));
    gpio_reset_pin(BOARD_TOUCH_INT);                          // input again; polled, not used
    ESP_LOGI(TAG, "CH422G ready: LCD and touch out of reset, microSD selected");
    return true;
}

#if BOARD_BUZZER_GPIO == 6
// A buzzer wired to GPIO6 shares the PCF85063's open-drain INT line: clear
// Control_2 (alarm, minute and half-minute interrupts off) so a battery-backed
// RTC left with an interrupt enabled never pulls the line against the tone.
static void rtc_int_off(void)
{
    i2c_master_dev_handle_t rtc;
    if (add_dev(BOARD_RTC_ADDR, &rtc) != ESP_OK) return;
    uint8_t w[2] = { 0x01, 0x00 };
    esp_err_t r = i2c_master_transmit(rtc, w, sizeof(w), I2C_TIMEOUT_MS);
    i2c_master_bus_rm_device(rtc);
    ESP_LOGI(TAG, "PCF85063 interrupts %s (GPIO6 buzzer)", r == ESP_OK ? "off" : "not answering");
}
#endif

// ── GT911 touch (polled; INT is only the address strap at reset) ──────────────

static i2c_master_dev_handle_t s_touch_dev;
static bool                    s_touch_ok;
static volatile bool           s_touch_hold;
static lv_coord_t              s_tx, s_ty;
static bool                    s_tpressed;

static esp_err_t gt_read(uint16_t reg, uint8_t *out, size_t len)
{
    uint8_t r[2] = { (uint8_t)(reg >> 8), (uint8_t)reg };
    return i2c_master_transmit_receive(s_touch_dev, r, 2, out, len, I2C_TIMEOUT_MS);
}

static esp_err_t gt_write(uint16_t reg, uint8_t v)
{
    uint8_t w[3] = { (uint8_t)(reg >> 8), (uint8_t)reg, v };
    return i2c_master_transmit(s_touch_dev, w, sizeof(w), I2C_TIMEOUT_MS);
}

static void touch_init(void)
{
    const uint8_t addrs[2] = { BOARD_TOUCH_ADDR, BOARD_TOUCH_ADDR_ALT };
    for (int i = 0; i < 2; i++) {
        if (add_dev(addrs[i], &s_touch_dev) != ESP_OK) break;
        uint8_t id[4] = { 0 };
        if (gt_read(0x8140, id, sizeof(id)) == ESP_OK) {      // product ID, "911"
            char s[5] = { 0 };
            for (int k = 0; k < 4; k++) s[k] = (id[k] >= 0x20 && id[k] < 0x7F) ? (char)id[k] : 0;
            ESP_LOGI(TAG, "GT911 touch ready at 0x%02x (product id \"%s\")", addrs[i], s);
            s_touch_ok = true;
            return;
        }
        i2c_master_bus_rm_device(s_touch_dev);
        s_touch_dev = NULL;
    }
    ESP_LOGE(TAG, "GT911 not answering at 0x%02x or 0x%02x, touch disabled",
             BOARD_TOUCH_ADDR, BOARD_TOUCH_ADDR_ALT);
}

// Status 0x814E: bit 7 a new report, low nibble the points (1..5); the first
// point from 0x814F: id, x low, x high, y low, y high, size (esp_lcd_touch_gt911).
// No new report: the last state stands (the GT911 reports about every 10 ms,
// LVGL reads every 30).
static void touch_read_cb(lv_indev_drv_t *drv, lv_indev_data_t *data)
{
    (void)drv;
    data->state = LV_INDEV_STATE_REL;
    if (!s_touch_ok || s_touch_hold) return;

    uint8_t st = 0;
    if (gt_read(0x814E, &st, 1) == ESP_OK && (st & 0x80)) {
        uint8_t n = st & 0x0F;
        uint8_t p[5];
        if (n >= 1 && n <= 5 && gt_read(0x814F, p, sizeof(p)) == ESP_OK) {
            int x = p[1] | (p[2] << 8);
            int y = p[3] | (p[4] << 8);
            if (x >= BOARD_LCD_HRES) x = BOARD_LCD_HRES - 1;
            if (y >= BOARD_LCD_VRES) y = BOARD_LCD_VRES - 1;
            s_tx = (lv_coord_t)x;
            s_ty = (lv_coord_t)y;
            s_tpressed = true;
        } else {
            s_tpressed = false;
        }
        gt_write(0x814E, 0);
    }
    data->point.x = s_tx;
    data->point.y = s_ty;
    data->state   = s_tpressed ? LV_INDEV_STATE_PR : LV_INDEV_STATE_REL;
}

i2c_master_bus_handle_t display_i2c_bus(void) { return s_i2c_bus; }

void display_touch_hold(bool hold) { s_touch_hold = hold; }

// Click on every new press anywhere on the glass (UI task).
static void touch_feedback_cb(lv_indev_drv_t *drv, uint8_t event)
{
    (void)drv;
    if (event == LV_EVENT_PRESSED) buzzer_click();
}

// ── Backlight: CH422G EXIO2, on or off ────────────────────────────────────────
//
// The boost's enable sits on the expander, so there is no PWM: any brightness
// setting (5..100) is full on; the override (red alert, face light) is too.

static bool s_bl_ok, s_bl_override;

static void backlight_apply(void)
{
    if (!s_bl_ok) return;
    bool on = s_bl_override || settings_get()->brightness > 0;
    exp_io(on ? BOARD_EXP_DISP : 0, on ? 0 : BOARD_EXP_DISP);
}

void display_set_backlight_override(bool full)
{
    if (!s_bl_ok) return;
    s_bl_override = full;
    backlight_apply();
}

// ── RGB panel and LVGL ────────────────────────────────────────────────────────

static esp_lcd_panel_handle_t s_panel;
static TaskHandle_t           s_ui_task;

// The bounce buffers finished a frame: the buffer handed over in flush is on
// the glass (the demo's on_bounce_frame_finish).
static IRAM_ATTR bool on_frame_done(esp_lcd_panel_handle_t panel,
                                    const esp_lcd_rgb_panel_event_data_t *ed, void *ctx)
{
    (void)panel; (void)ed; (void)ctx;
    BaseType_t woke = pdFALSE;
    if (s_ui_task) vTaskNotifyGiveFromISR(s_ui_task, &woke);
    return woke == pdTRUE;
}

static void flush_cb(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *px)
{
    // Direct mode: px is a whole frame buffer; only the last area of a refresh
    // swaps it in.
    if (lv_disp_flush_is_last(drv)) {
        ulTaskNotifyTake(pdTRUE, 0);
        esp_lcd_panel_draw_bitmap(s_panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1, px);
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(FLUSH_WAIT_MS));
    }
    lv_disp_flush_ready(drv);
}

static bool panel_init(void)
{
    esp_lcd_rgb_panel_config_t pc = {
        .clk_src = LCD_CLK_SRC_DEFAULT,
        .timings = {
            .pclk_hz           = BOARD_LCD_PCLK_HZ,
            .h_res             = BOARD_LCD_HRES,
            .v_res             = BOARD_LCD_VRES,
            .hsync_pulse_width = BOARD_LCD_HSYNC_PW,
            .hsync_back_porch  = BOARD_LCD_HSYNC_BP,
            .hsync_front_porch = BOARD_LCD_HSYNC_FP,
            .vsync_pulse_width = BOARD_LCD_VSYNC_PW,
            .vsync_back_porch  = BOARD_LCD_VSYNC_BP,
            .vsync_front_porch = BOARD_LCD_VSYNC_FP,
            .flags.pclk_active_neg = BOARD_LCD_PCLK_NEG,
        },
        .data_width            = 16,
        .bits_per_pixel        = 16,
        .num_fbs               = 2,
        .bounce_buffer_size_px = BOARD_LCD_HRES * BOARD_LCD_BOUNCE_LINES,
        .sram_trans_align      = 4,
        .psram_trans_align     = 64,
        .hsync_gpio_num        = BOARD_LCD_HSYNC,
        .vsync_gpio_num        = BOARD_LCD_VSYNC,
        .de_gpio_num           = BOARD_LCD_DE,
        .pclk_gpio_num         = BOARD_LCD_PCLK,
        .disp_gpio_num         = -1,
        .data_gpio_nums        = BOARD_LCD_DATA,
        .flags.fb_in_psram     = 1,
    };
    _Static_assert((BOARD_LCD_HRES * BOARD_LCD_VRES) % (BOARD_LCD_HRES * BOARD_LCD_BOUNCE_LINES * 2) == 0,
                   "a frame must be an even number of bounce buffers");
    size_t int0 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps0  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    esp_err_t r = esp_lcd_new_rgb_panel(&pc, &s_panel);
    if (r == ESP_OK) r = esp_lcd_panel_init(s_panel);        // no reset: the demo's order
    if (r != ESP_OK) {
        ESP_LOGE(TAG, "RGB panel init failed: %s (internal free %u B)", esp_err_to_name(r),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        return false;
    }
    esp_lcd_rgb_panel_event_callbacks_t cbs = { .on_bounce_frame_finish = on_frame_done };
    esp_lcd_rgb_panel_register_event_callbacks(s_panel, &cbs, NULL);
    ESP_LOGI(TAG, "RGB panel %dx%d at %d Hz pixel clock: frame buffers 2 x %u B in PSRAM, "
             "bounce buffers 2 x %u B internal; internal heap %u -> %u B, PSRAM %u -> %u B",
             BOARD_LCD_HRES, BOARD_LCD_VRES, BOARD_LCD_PCLK_HZ,
             (unsigned)(BOARD_LCD_HRES * BOARD_LCD_VRES * 2),
             (unsigned)(BOARD_LCD_HRES * BOARD_LCD_BOUNCE_LINES * 2),
             (unsigned)int0, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)ps0, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    return true;
}

bool display_init(void)
{
    s_ui_task = xTaskGetCurrentTaskHandle();

    bool exp_ok = i2c_init() && expander_init();
    sd_log_bus_ready();                         // the card is selected (or never will be)
#if BOARD_BUZZER_GPIO == 6
    if (exp_ok) rtc_int_off();
#endif

    if (!panel_init()) return false;

    s_bl_ok = exp_ok;
    backlight_apply();
    settings_on_change(backlight_apply);

    if (exp_ok) touch_init();

    lv_init();

    static lv_disp_draw_buf_t draw_buf;
    void *fb0 = NULL, *fb1 = NULL;
    if (esp_lcd_rgb_panel_get_frame_buffer(s_panel, 2, &fb0, &fb1) != ESP_OK) {
        ESP_LOGE(TAG, "RGB panel frame buffers missing");
        return false;
    }
    lv_disp_draw_buf_init(&draw_buf, fb0, fb1, BOARD_LCD_HRES * BOARD_LCD_VRES);

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res     = BOARD_LCD_HRES;
    disp_drv.ver_res     = BOARD_LCD_VRES;
    disp_drv.flush_cb    = flush_cb;
    disp_drv.draw_buf    = &draw_buf;
    disp_drv.direct_mode = 1;
    lv_disp_drv_register(&disp_drv);

    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type        = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb     = touch_read_cb;
    indev_drv.feedback_cb = touch_feedback_cb;
    lv_indev_drv_register(&indev_drv);

    ESP_LOGI(TAG, "Panel %dx%d up", BOARD_LCD_HRES, BOARD_LCD_VRES);
    return true;
}

#endif // BOARD_IS_WAVESHARE43
