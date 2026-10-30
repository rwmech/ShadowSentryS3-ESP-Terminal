#define LGFX_USE_V1
#include <LovyanGFX.hpp>

#include "display.h"
#include "board.h"
#include "lvgl.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
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
            cfg.freq_read   = 8000000;
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

// ── FT6236 touch (see board.h for why INT is unused) ──────────────────────────
//
// New i2c_master driver: LovyanGFX links it, and IDF aborts at boot ("CONFLICT!
// driver_ng is not allowed to be used with this old driver") if the legacy
// driver is linked alongside. The camera (whose SCCB needs the legacy driver
// below IDF 5.4) is unused, so nothing here needs the old one.

static i2c_master_dev_handle_t s_touch_dev;
static bool s_touch_ok = false;

static esp_err_t touch_read(uint8_t reg, uint8_t *out, size_t len, int timeout_ms)
{
    return i2c_master_transmit_receive(s_touch_dev, &reg, 1, out, len, timeout_ms);
}

static void touch_init(void)
{
    i2c_master_bus_config_t bc = {};
    bc.i2c_port          = I2C_NUM_0;
    bc.sda_io_num        = (gpio_num_t)BOARD_TOUCH_SDA;
    bc.scl_io_num        = (gpio_num_t)BOARD_TOUCH_SCL;
    bc.clk_source        = I2C_CLK_SRC_DEFAULT;
    bc.glitch_ignore_cnt = 7;
    bc.flags.enable_internal_pullup = true;  // board also has 4.7k pull-ups
    i2c_master_bus_handle_t bus;
    if (i2c_new_master_bus(&bc, &bus) != ESP_OK) {
        ESP_LOGE(TAG, "I2C init failed — touch disabled");
        return;
    }
    i2c_device_config_t dc = {};
    dc.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    dc.device_address  = BOARD_TOUCH_ADDR;
    dc.scl_speed_hz    = 400000;
    if (i2c_master_bus_add_device(bus, &dc, &s_touch_dev) != ESP_OK) {
        ESP_LOGE(TAG, "I2C device add failed — touch disabled");
        return;
    }
    uint8_t id = 0;
    if (touch_read(0xA8, &id, 1, 50) != ESP_OK) {          // FOCALTECH_ID
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
    uint8_t b[5];
    if (touch_read(0x02, b, sizeof(b), 20) != ESP_OK) return;

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

#define DRAW_BUF_LINES  20      // 19 KB of internal DMA RAM

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
    // The microSD shares this SPI bus: hold its CS high so the card can never
    // answer or drive MISO while the panel is being talked to.
    gpio_reset_pin((gpio_num_t)BOARD_SD_CS);
    gpio_set_direction((gpio_num_t)BOARD_SD_CS, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)BOARD_SD_CS, 1);

    if (!s_tft.init()) {
        ESP_LOGE(TAG, "ILI9488 init failed");
        return false;
    }
    s_tft.setRotation(3);                    // landscape, as Elecrow's example

    // Panel self-check over MISO: ILI9488 answers 0xD3 with 0x009488. A wrong
    // ID or a pixel that doesn't read back means the panel isn't listening.
    s_tft.startWrite();
    uint32_t id = s_tft.getPanel()->readCommand(0xD3, 0, 4);
    s_tft.endWrite();
    s_tft.fillScreen(TFT_RED);
    uint16_t rb = s_tft.readPixel(10, 10);
    ESP_LOGI(TAG, "ILI9488 ID 0x%06lx, pixel after red fill 0x%04x (want ~0xf800)",
             (unsigned long)(id & 0xFFFFFF), rb);
    s_tft.fillScreen(TFT_BLACK);

    gpio_reset_pin((gpio_num_t)BOARD_LCD_BL);
    gpio_set_direction((gpio_num_t)BOARD_LCD_BL, GPIO_MODE_INPUT_OUTPUT);
    gpio_set_level((gpio_num_t)BOARD_LCD_BL, 1);
    ESP_LOGI(TAG, "Backlight GPIO%d driven high, reads %d",
             BOARD_LCD_BL, gpio_get_level((gpio_num_t)BOARD_LCD_BL));

    touch_init();

    lv_init();

    static lv_disp_draw_buf_t draw_buf;
    size_t px = BOARD_LCD_HRES * DRAW_BUF_LINES;
    lv_color_t *buf = (lv_color_t *)heap_caps_malloc(px * sizeof(lv_color_t),
                                                     MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (!buf) {
        ESP_LOGE(TAG, "draw buffer allocation failed (internal free %u B)",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
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
