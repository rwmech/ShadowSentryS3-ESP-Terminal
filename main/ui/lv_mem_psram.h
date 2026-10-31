#pragma once
/*
 * LVGL's object and style allocations, PSRAM first (fork, network fix-forward).
 *
 * With LV_MEM_CUSTOM=y LVGL calls malloc(), and with
 * CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL at its 16 KB default every LVGL object
 * landed in internal RAM: the armed dashboard cost about 15 KB of it. The
 * project CMakeLists.txt points LV_MEM_CUSTOM_ALLOC / _FREE / _REALLOC and
 * LV_MEM_CUSTOM_INCLUDE at these for the lvgl target. The draw buffer is not
 * allocated through here: display.cpp keeps it internal and DMA-capable.
 */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *lv_psram_malloc(size_t size);
void  lv_psram_free(void *p);
void *lv_psram_realloc(void *p, size_t size);

#ifdef __cplusplus
}
#endif
