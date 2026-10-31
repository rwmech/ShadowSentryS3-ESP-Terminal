// Ignore list, see ignore.h.

#include "ignore.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>
#include <time.h>

static const char *TAG = "IGNORE";

#define NVS_NS   "ignore"
#define NVS_KEY  "list"

static ignore_entry_t   *s_list;        // PSRAM, IGNORE_MAX entries, guarded by s_mutex
static volatile int      s_n;           // entries in use; read without the lock as a fast path
static SemaphoreHandle_t s_mutex;       // the table
static SemaphoreHandle_t s_save_mutex;  // NVS writes, so a slow flash write never holds s_mutex

static bool mac_given(const uint8_t *m)
{
    if (!m) return false;
    for (int i = 0; i < 6; i++) if (m[i]) return true;
    return false;
}

// Write the table to NVS from a snapshot taken under the lock.
static esp_err_t save(void)
{
    ignore_entry_t *snap = heap_caps_malloc(IGNORE_MAX * sizeof(*snap), MALLOC_CAP_SPIRAM);
    if (!snap) return ESP_ERR_NO_MEM;
    xSemaphoreTake(s_save_mutex, portMAX_DELAY);
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = s_n;
    memcpy(snap, s_list, (size_t)n * sizeof(*snap));
    xSemaphoreGive(s_mutex);

    nvs_handle_t h;
    esp_err_t r = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (r == ESP_OK) {
        r = n ? nvs_set_blob(h, NVS_KEY, snap, (size_t)n * sizeof(*snap))
              : nvs_erase_key(h, NVS_KEY);
        if (r == ESP_ERR_NVS_NOT_FOUND) r = ESP_OK;
        if (r == ESP_OK) r = nvs_commit(h);
        nvs_close(h);
    }
    xSemaphoreGive(s_save_mutex);
    heap_caps_free(snap);
    if (r != ESP_OK) ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(r));
    return r;
}

void ignore_init(void)
{
    if (s_mutex) return;
    s_list = heap_caps_calloc(IGNORE_MAX, sizeof(*s_list), MALLOC_CAP_SPIRAM);
    configASSERT(s_list);
    s_save_mutex = xSemaphoreCreateMutex();
    s_mutex      = xSemaphoreCreateMutex();
    configASSERT(s_mutex && s_save_mutex);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = IGNORE_MAX * sizeof(*s_list);
        if (nvs_get_blob(h, NVS_KEY, s_list, &len) == ESP_OK && len % sizeof(*s_list) == 0) {
            int n = (int)(len / sizeof(*s_list));
            for (int i = 0; i < n; i++) s_list[i].note[IGNORE_NOTE_MAX - 1] = '\0';
            s_n = n;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "%d ignored source%s", s_n, s_n == 1 ? "" : "s");
}

esp_err_t ignore_add(uint32_t ip, const uint8_t *mac, const char *note)
{
    if (!s_mutex) return ESP_ERR_INVALID_STATE;
    bool has_mac = mac_given(mac);
    if (!ip && !has_mac) return ESP_ERR_INVALID_ARG;

    ignore_entry_t e = { .ip = ip };
    if (has_mac) memcpy(e.mac, mac, 6);
    time_t now = time(NULL);
    e.added_ts = now >= 1600000000 ? (uint32_t)now : 0;
    size_t k = 0;
    for (; note && note[k] && k < IGNORE_NOTE_MAX - 1; k++) {
        unsigned char c = (unsigned char)note[k];
        e.note[k] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    e.note[k] = '\0';

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_n; i++) {
        if (s_list[i].ip == e.ip && !memcmp(s_list[i].mac, e.mac, 6)) {
            xSemaphoreGive(s_mutex);
            return ESP_OK;                      // already there
        }
    }
    if (s_n >= IGNORE_MAX) { xSemaphoreGive(s_mutex); return ESP_ERR_NO_MEM; }
    s_list[s_n] = e;
    s_n = s_n + 1;
    xSemaphoreGive(s_mutex);
    ESP_LOGW(TAG, "Source added to the ignore list (%d in use)", s_n);
    return save();
}

esp_err_t ignore_remove(int index)
{
    if (!s_mutex) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (index < 0 || index >= s_n) { xSemaphoreGive(s_mutex); return ESP_ERR_INVALID_ARG; }
    memmove(&s_list[index], &s_list[index + 1], (size_t)(s_n - index - 1) * sizeof(*s_list));
    s_n = s_n - 1;
    memset(&s_list[s_n], 0, sizeof(*s_list));
    xSemaphoreGive(s_mutex);
    ESP_LOGW(TAG, "Ignore entry %d removed (%d in use)", index, s_n);
    return save();
}

int ignore_list(ignore_entry_t *out, int max)
{
    if (!s_mutex || !out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = s_n < max ? s_n : max;
    memcpy(out, s_list, (size_t)n * sizeof(*out));
    xSemaphoreGive(s_mutex);
    return n;
}

bool ignore_match(uint32_t ip, const uint8_t mac[6])
{
    if (!s_mutex || s_n == 0) return false;
    bool has_mac = mac_given(mac);
    bool hit = false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_n && !hit; i++) {
        const ignore_entry_t *e = &s_list[i];
        if (ip && e->ip == ip) hit = true;
        else if (has_mac && mac_given(e->mac) && !memcmp(e->mac, mac, 6)) hit = true;
    }
    xSemaphoreGive(s_mutex);
    return hit;
}
