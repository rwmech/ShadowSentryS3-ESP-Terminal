#define LGFX_USE_V1
#include <LovyanGFX.hpp>

#include "display.h"
#include "board.h"
#include "lvgl.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "DISPLAY";

// ── Panel: Elecrow CrowPanel 3.5" LVGL_SPI_ example config, verbatim ──────────
class LGFX_CrowPanel35 : public lgfx::LGFX_Device
{
    lgfx::Panel_ILI9488 _panel;
    lgfx::Bus_SPI       _bus;

public:
    LGFX_CrowPanel35(void)
    {
        {
            auto cfg = _bus.config();
            cfg.spi_host    = SPI3_HOST;
            cfg.spi_mode    = 0;
            cfg.freq_write  = BOARD_LCD_SPI_HZ;
            cfg.freq_read   = 16000000;
            cfg.spi_3wire   = false;
            cfg.use_lock    = true;
            cfg.dma_channel = SPI_DMA_CH_AUTO;
            cfg.pin_sclk    = BOARD_LCD_SCLK;
            cfg.pin_mosi    = BOARD_LCD_MOSI;
            cfg.pin_miso    = BOARD_LCD_MISO;
            cfg.pin_dc      = BOARD_LCD_DC;
            _bus.config(cfg);
            _panel.setBus(&_bus);
        }
        {
            auto cfg = _panel.config();
            cfg.pin_cs           = BOARD_LCD_CS;
            cfg.pin_rst          = BOARD_LCD_RST;
            cfg.pin_busy         = -1;
            cfg.memory_width     = 320;
            cfg.memory_height    = 480;
            cfg.panel_width      = 320;
            cfg.panel_height     = 480;
            cfg.offset_x         = 0;
            cfg.offset_y         = 0;
            cfg.offset_rotation  = 0;
            cfg.dummy_read_pixel = 8;
            cfg.dummy_read_bits  = 1;
            cfg.readable         = true;
            cfg.invert           = false;
            cfg.rgb_order        = false;
            cfg.dlen_16bit       = false;
            cfg.bus_shared       = true;     // microSD shares this SPI bus
            _panel.config(cfg);
        }
        setPanel(&_panel);
    }
};

static LGFX_CrowPanel35 s_tft;

// ── FT6236 touch (legacy I2C driver; see board.h for why INT is unused) ───────

#define TOUCH_I2C_PORT  I2C_NUM_0
static bool s_touch_ok = false;

static void touch_init(void)
{
    i2c_config_t c = {};
    c.mode             = I2C_MODE_MASTER;
    c.sda_io_num       = BOARD_TOUCH_SDA;
    c.scl_io_num       = BOARD_TOUCH_SCL;
    c.sda_pullup_en    = GPIO_PULLUP_ENABLE;   // board also has 4.7k pull-ups
    c.scl_pullup_en    = GPIO_PULLUP_ENABLE;
    c.master.clk_speed = 400000;
    if (i2c_param_config(TOUCH_I2C_PORT, &c) != ESP_OK ||
        i2c_driver_install(TOUCH_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0) != ESP_OK) {
        ESP_LOGE(TAG, "I2C init failed — touch disabled");
        return;
    }
    uint8_t reg = 0xA8, id = 0;              // FOCALTECH_ID
    if (i2c_master_write_read_device(TOUCH_I2C_PORT, BOARD_TOUCH_ADDR, &reg, 1,
                                     &id, 1, pdMS_TO_TICKS(50)) != ESP_OK) {
        ESP_LOGE(TAG, "FT6236 not answering at 0x%02x — touch disabled",
                 BOARD_TOUCH_ADDR);
        return;
    }
    ESP_LOGI(TAG, "FT6236 touch ready (vendor id 0x%02x)", id);
    s_touch_ok = true;
}

static void touch_read_cb(lv_indev_drv_t *drv, lv_indev_data_t *data)
{
    (void)drv;
    data->state = LV_INDEV_STATE_REL;
    if (!s_touch_ok) return;

    // TD_STATUS, P1_XH, P1_XL, P1_YH, P1_YL
    uint8_t reg = 0x02, b[5];
    if (i2c_master_write_read_device(TOUCH_I2C_PORT, BOARD_TOUCH_ADDR, &reg, 1,
                                     b, sizeof(b), pdMS_TO_TICKS(20)) != ESP_OK)
        return;

    uint8_t points = b[0] & 0x0F;
    uint8_t event  = b[1] >> 6;              // 1 = lift-up
    if (points == 0 || points > 2 || event == 1) return;

    int raw_x = ((b[1] & 0x0F) << 8) | b[2];   // 0..319 (portrait)
    int raw_y = ((b[3] & 0x0F) << 8) | b[4];   // 0..479
    // Rotation 3 mapping, as Elecrow's LVGL example: x = W - raw_y, y = raw_x
    int x = BOARD_LCD_HRES - raw_y;
    int y = raw_x;
    if (x < 0) x = 0;
    if (x >= BOARD_LCD_HRES) x = BOARD_LCD_HRES - 1;
    if (y < 0) y = 0;
    if (y >= BOARD_LCD_VRES) y = BOARD_LCD_VRES - 1;

    data->point.x = (lv_coord_t)x;
    data->point.y = (lv_coord_t)y;
    data->state   = LV_INDEV_STATE_PR;
}

// ── LVGL display driver ───────────────────────────────────────────────────────

#define DRAW_BUF_LINES  40

static void flush_cb(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *px)
{
    uint32_t w = (uint32_t)(area->x2 - area->x1 + 1);
    uint32_t h = (uint32_t)(area->y2 - area->y1 + 1);
    s_tft.startWrite();
    s_tft.setAddrWindow(area->x1, area->y1, w, h);
    s_tft.writePixels((lgfx::rgb565_t *)&px->full, w * h);   // → RGB666 on the wire
    s_tft.endWrite();
    lv_disp_flush_ready(drv);
}

extern "C" bool display_init(void)
{
    if (!s_tft.init()) {
        ESP_LOGE(TAG, "ILI9488 init failed");
        return false;
    }
    s_tft.setRotation(3);                    // landscape, as Elecrow's example
    s_tft.fillScreen(TFT_BLACK);

    gpio_reset_pin((gpio_num_t)BOARD_LCD_BL);
    gpio_set_direction((gpio_num_t)BOARD_LCD_BL, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)BOARD_LCD_BL, 1);

    touch_init();

    lv_init();

    static lv_disp_draw_buf_t draw_buf;
    size_t px = BOARD_LCD_HRES * DRAW_BUF_LINES;
    lv_color_t *buf = (lv_color_t *)heap_caps_malloc(px * sizeof(lv_color_t),
                                                     MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (!buf) {
        ESP_LOGE(TAG, "draw buffer allocation failed");
        return false;
    }
    lv_disp_draw_buf_init(&draw_buf, buf, NULL, px);

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res  = BOARD_LCD_HRES;
    disp_drv.ver_res  = BOARD_LCD_VRES;
    disp_drv.flush_cb = flush_cb;
    disp_drv.draw_buf = &draw_buf;
    lv_disp_drv_register(&disp_drv);

    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type    = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = touch_read_cb;
    lv_indev_drv_register(&indev_drv);

    ESP_LOGI(TAG, "Panel %dx%d up", BOARD_LCD_HRES, BOARD_LCD_VRES);
    return true;
}
