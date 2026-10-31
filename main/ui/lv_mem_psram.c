#include "lv_mem_psram.h"
#include "esp_heap_caps.h"

// PSRAM first, internal RAM if PSRAM is out. Only the UI task calls LVGL, and
// it never runs with the cache disabled, so PSRAM objects are safe here.
void *lv_psram_malloc(size_t size)
{
    void *p = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return p ? p : heap_caps_malloc(size, MALLOC_CAP_8BIT);
}

void lv_psram_free(void *p)
{
    heap_caps_free(p);
}

void *lv_psram_realloc(void *p, size_t size)
{
    void *n = heap_caps_realloc(p, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return n ? n : heap_caps_realloc(p, size, MALLOC_CAP_8BIT);
}
