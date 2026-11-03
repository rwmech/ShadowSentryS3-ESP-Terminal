// Panel logo: the built-in PNG, decoded once into PSRAM. See ui_logo.h.
//
// lodepng is called directly rather than through lv_img_decoder_open(), so its
// zlib output can be capped at what the IHDR allows: a deflate bomb then stops
// with an error instead of filling PSRAM. Its allocations are LVGL's
// (lv_mem_alloc, which is PSRAM here: lv_mem_psram.c).

#include "ui_logo.h"
#include "extra/libs/png/lodepng.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "LOGO";

#if LV_COLOR_DEPTH != 16
#error "ui_logo.c converts to 16-bit true colour with alpha"
#endif

extern const uint8_t logo_png_start[] asm("_binary_shadowsentry_logo_200_png_start");
extern const uint8_t logo_png_end[]   asm("_binary_shadowsentry_logo_200_png_end");

EXT_RAM_BSS_ATTR static lv_img_dsc_t s_dsc;
EXT_RAM_BSS_ATTR static bool         s_tried, s_ok;

// ── PNG header ────────────────────────────────────────────────────────────────

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

bool ui_logo_png_ok(const uint8_t *p, size_t len, uint16_t *w, uint16_t *h)
{
    static const uint8_t SIG[8] = { 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };
    // signature 8, then the IHDR chunk: length 4, type 4, data 13, CRC 4
    if (!p || len < 33 || len > UI_LOGO_MAX_BYTES) return false;
    if (memcmp(p, SIG, sizeof(SIG)) != 0) return false;
    if (be32(p + 8) != 13 || memcmp(p + 12, "IHDR", 4) != 0) return false;
    uint32_t pw = be32(p + 16), ph = be32(p + 20);
    if (pw < 1 || ph < 1 || pw > UI_LOGO_MAX_PX || ph > UI_LOGO_MAX_PX) return false;
    uint8_t depth = p[24], ct = p[25];
    bool ok;
    switch (ct) {
    case 0:  ok = depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16; break;  // grey
    case 3:  ok = depth == 1 || depth == 2 || depth == 4 || depth == 8; break;                 // palette
    case 2: case 4: case 6: ok = depth == 8 || depth == 16; break;                             // RGB, grey + alpha, RGBA
    default: ok = false; break;
    }
    if (!ok || p[26] != 0 || p[27] != 0 || p[28] > 1) return false;   // compression, filter, interlace
    if (w) *w = (uint16_t)pw;
    if (h) *h = (uint16_t)ph;
    return true;
}

const uint8_t *ui_logo_builtin(size_t *len)
{
    if (len) *len = (size_t)(logo_png_end - logo_png_start);
    return logo_png_start;
}

// ── Decode ────────────────────────────────────────────────────────────────────

// png into s_dsc. what names the source in the log.
static bool decode(const uint8_t *png, size_t len, const char *what)
{
    uint16_t w, h;
    if (!ui_logo_png_ok(png, len, &w, &h)) {
        ESP_LOGW(TAG, "%s: not a PNG of at most %d x %d px and %d B", what,
                 UI_LOGO_MAX_PX, UI_LOGO_MAX_PX, UI_LOGO_MAX_BYTES);
        return false;
    }
    int64_t t0 = esp_timer_get_time();
    LodePNGState st;
    lodepng_state_init(&st);
    st.info_raw.colortype = LCT_RGBA;
    st.info_raw.bitdepth = 8;
    st.decoder.read_text_chunks = 0;
    st.decoder.remember_unknown_chunks = 0;
    st.decoder.max_icc_size = 64 * 1024;
    // The most the image data can inflate to: 16-bit RGBA (8 B a pixel) plus a
    // filter byte a row, with room for Adam7's extra rows.
    st.decoder.zlibsettings.max_output_size = (size_t)w * h * 8 + (size_t)h * 2 + 64;
    unsigned char *rgba = NULL;
    unsigned ow = 0, oh = 0;
    unsigned err = lodepng_decode(&rgba, &ow, &oh, &st, png, len);
    lodepng_state_cleanup(&st);
    if (err || !rgba || ow != w || oh != h) {
        if (rgba) lv_mem_free(rgba);
        ESP_LOGW(TAG, "%s: PNG decode failed (%u: %s)", what, err, err ? lodepng_error_text(err) : "size");
        return false;
    }
    size_t px = (size_t)w * h;
    uint8_t *buf = heap_caps_malloc(px * LV_IMG_PX_SIZE_ALPHA_BYTE, MALLOC_CAP_SPIRAM);
    if (!buf) {
        lv_mem_free(rgba);
        ESP_LOGW(TAG, "%s: no PSRAM for %u B", what, (unsigned)(px * LV_IMG_PX_SIZE_ALPHA_BYTE));
        return false;
    }
    // LV_IMG_CF_TRUE_COLOR_ALPHA at 16 bits: colour low byte, high byte, alpha
    // (as LVGL's own PNG decoder writes it).
    for (size_t i = 0; i < px; i++) {
        const uint8_t *s = rgba + i * 4;
        lv_color_t c = lv_color_make(s[0], s[1], s[2]);
        buf[i * 3 + 0] = (uint8_t)(c.full & 0xff);
        buf[i * 3 + 1] = (uint8_t)(c.full >> 8);
        buf[i * 3 + 2] = s[3];
    }
    lv_mem_free(rgba);
    memset(&s_dsc, 0, sizeof(s_dsc));
    s_dsc.header.cf = LV_IMG_CF_TRUE_COLOR_ALPHA;
    s_dsc.header.w = w;
    s_dsc.header.h = h;
    s_dsc.data_size = (uint32_t)(px * LV_IMG_PX_SIZE_ALPHA_BYTE);
    s_dsc.data = buf;
    ESP_LOGI(TAG, "Logo from %s: %u x %u px, %u B PNG, %u B in PSRAM, decoded in %u ms; "
             "UI stack high-water %u B, internal heap %u B free",
             what, w, h, (unsigned)len, (unsigned)s_dsc.data_size,
             (unsigned)((esp_timer_get_time() - t0) / 1000),
             (unsigned)uxTaskGetStackHighWaterMark(NULL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    return true;
}

const lv_img_dsc_t *ui_logo_get(void)
{
    if (!s_tried) {
        s_tried = true;
        size_t len;
        const uint8_t *png = ui_logo_builtin(&len);
        s_ok = decode(png, len, "built-in");
    }
    return s_ok ? &s_dsc : NULL;
}
