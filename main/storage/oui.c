// MAC vendor database on the microSD card. See oui.h.
//
// The file comes from the PC, so it is checked like anything else that
// arrives over the network: the header against the file size, every record
// index and name offset against the counts, every name cut to printable ASCII.

#include "oui.h"
#include "wifi_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char *TAG = "OUI";

#define MISSQ_DEPTH     16
#define RECHECK_US      (15 * 1000000LL)  // stat the file at most this often

enum { C_EMPTY, C_FOUND, C_NONE, C_PENDING };
typedef struct {
    uint8_t     key[5];                 // 36 bits: mac[0..3] and mac[4] & 0xf0
    uint8_t     state;
    uint32_t    used;
    const char *name;                   // interned, C_FOUND only (NULL if the pool was full)
} cent_t;

typedef struct {
    bool     checked, present;
    uint32_t count, build_ts, size, str_off, str_len;
    time_t   mtime;
    int64_t  checked_us;
} hdr_t;

static cent_t           *s_cache;
static char             *s_pool;
static size_t            s_pool_used;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;   // cache and pool
static SemaphoreHandle_t s_fmux;                                 // the file and s_hdr
static QueueHandle_t     s_missq;
static uint32_t          s_tick, s_lookups, s_hits, s_queued;
static volatile bool     s_dirty = true;
static hdr_t             s_hdr;

static inline uint16_t le16(const uint8_t *b) { return (uint16_t)(b[0] | (b[1] << 8)); }
static inline uint32_t le32(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static bool hdr_parse(const uint8_t *h, size_t total, hdr_t *o)
{
    if (total < OUI_HDR_SIZE || total > OUI_MAX_BYTES || memcmp(h, "SSOU", 4)) return false;
    if (le16(h + 4) != OUI_VERSION || le16(h + 6) != OUI_REC_SIZE) return false;
    uint32_t count = le32(h + 8), str_off = le32(h + 16), str_len = le32(h + 20);
    if (!count || count > OUI_MAX_COUNT) return false;
    if (str_off != OUI_HDR_SIZE + count * OUI_REC_SIZE || !str_len) return false;
    if ((uint64_t)str_off + str_len != total) return false;
    o->count = count;
    o->build_ts = le32(h + 12);
    o->str_off = str_off;
    o->str_len = str_len;
    o->size = (uint32_t)total;
    return true;
}

bool oui_header_ok(const uint8_t *buf, size_t len, uint32_t *count, uint32_t *build_ts)
{
    hdr_t h;
    if (!buf || !hdr_parse(buf, len, &h)) return false;
    if (count) *count = h.count;
    if (build_ts) *build_ts = h.build_ts;
    return true;
}

static void cache_clear(void)
{
    portENTER_CRITICAL(&s_mux);
    if (s_cache) memset(s_cache, 0, OUI_CACHE_N * sizeof(*s_cache));
    portEXIT_CRITICAL(&s_mux);
}

// s_fmux held. True when the file is there and valid; a change empties the cache.
static bool hdr_refresh(void)
{
    int64_t now = esp_timer_get_time();
    if (!s_dirty && s_hdr.checked && now - s_hdr.checked_us < RECHECK_US) return s_hdr.present;
    struct stat st;
    bool was = s_hdr.present;
    if (stat(OUI_PATH, &st) != 0 || st.st_size <= 0) {
        s_hdr.present = false;
    } else if (s_dirty || !s_hdr.checked || (uint32_t)st.st_size != s_hdr.size || st.st_mtime != s_hdr.mtime) {
        uint8_t h[OUI_HDR_SIZE];
        FILE *f = fopen(OUI_PATH, "rb");
        hdr_t n = { 0 };
        bool ok = f && fread(h, 1, sizeof(h), f) == sizeof(h) && hdr_parse(h, (size_t)st.st_size, &n);
        if (f) fclose(f);
        if (ok) {
            n.mtime = st.st_mtime;
            n.present = true;
            s_hdr = n;
            ESP_LOGI(TAG, "Vendor database: %lu prefixes, %lu B, built %lu",
                     (unsigned long)n.count, (unsigned long)n.size, (unsigned long)n.build_ts);
        } else {
            s_hdr.present = false;
            s_hdr.size = (uint32_t)st.st_size;
            s_hdr.mtime = st.st_mtime;
            ESP_LOGW(TAG, "%s is not a valid vendor database, ignored", OUI_PATH);
        }
        cache_clear();
    }
    if (was && !s_hdr.present) cache_clear();
    s_hdr.checked = true;
    s_hdr.checked_us = now;
    s_dirty = false;
    return s_hdr.present;
}

// Exact (prefix, bits) record by binary search. s_fmux held, header valid.
static bool file_find(FILE *f, const uint8_t key[6], uint8_t bits, uint32_t *name_off)
{
    uint32_t lo = 0, hi = s_hdr.count;
    for (int guard = 0; lo < hi && guard < 32; guard++) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint8_t r[OUI_REC_SIZE];
        if (fseek(f, (long)(OUI_HDR_SIZE + mid * OUI_REC_SIZE), SEEK_SET) != 0 ||
            fread(r, 1, sizeof(r), f) != sizeof(r)) return false;
        int c = memcmp(r, key, 6);
        if (!c) c = (int)r[6] - (int)bits;
        if (!c) { *name_off = le32(r + 8); return true; }
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

static bool file_name(FILE *f, uint32_t off, char *out, size_t cap)
{
    if (off >= s_hdr.str_len || cap < 2) return false;
    uint8_t b[OUI_NAME_MAX];
    size_t want = s_hdr.str_len - off;
    if (want > sizeof(b)) want = sizeof(b);
    if (fseek(f, (long)(s_hdr.str_off + off), SEEK_SET) != 0) return false;
    size_t n = fread(b, 1, want, f), o = 0;
    for (size_t i = 0; i < n && b[i] && o + 1 < cap; i++)
        out[o++] = (b[i] >= 0x20 && b[i] < 0x7f) ? (char)b[i] : '?';
    out[o] = '\0';
    return o > 0;
}

// s_mux held. Pointer to name in the pool (existing or appended), or NULL.
static const char *intern(const char *name)
{
    size_t n = strlen(name) + 1;
    for (size_t i = 0; i < s_pool_used; i += strlen(s_pool + i) + 1)
        if (!strcmp(s_pool + i, name)) return s_pool + i;
    if (!s_pool || s_pool_used + n > OUI_POOL_BYTES) return NULL;
    char *p = s_pool + s_pool_used;
    memcpy(p, name, n);
    s_pool_used += n;
    return p;
}

static void key_of(const uint8_t mac[6], uint8_t k[5])
{
    memcpy(k, mac, 4);
    k[4] = mac[4] & 0xf0;
}

// s_mux held.
static cent_t *cache_slot(const uint8_t k[5], bool make)
{
    cent_t *lru = NULL;
    for (int i = 0; i < OUI_CACHE_N; i++) {
        cent_t *e = &s_cache[i];
        if (e->state != C_EMPTY && !memcmp(e->key, k, 5)) { e->used = ++s_tick; return e; }
        if (!lru || e->state == C_EMPTY || (lru->state != C_EMPTY && e->used < lru->used)) lru = e;
    }
    if (!make || !lru) return NULL;
    memset(lru, 0, sizeof(*lru));
    memcpy(lru->key, k, 5);
    lru->used = ++s_tick;
    return lru;
}

static bool private_or_zero(const uint8_t mac[6])
{
    static const uint8_t zero[6] = { 0 };
    return (mac[0] & 0x02) || !memcmp(mac, zero, 6);
}

const char *oui_cached(const uint8_t mac[6])
{
    if (!s_cache || !mac || private_or_zero(mac)) return NULL;
    uint8_t k[5];
    key_of(mac, k);
    const char *name = NULL;
    bool queue = false;
    portENTER_CRITICAL(&s_mux);
    cent_t *e = cache_slot(k, false);
    if (e) {
        if (e->state == C_FOUND) name = e->name;
    } else if ((e = cache_slot(k, true)) != NULL) {
        e->state = C_PENDING;
        queue = true;
    }
    portEXIT_CRITICAL(&s_mux);
    if (queue && s_missq) {
        uint8_t m[6];
        memcpy(m, mac, 6);
        if (xQueueSend(s_missq, m, 0) == pdTRUE) s_queued++;
        else {                                  // full: forget it, a later sighting retries
            portENTER_CRITICAL(&s_mux);
            cent_t *p = cache_slot(k, false);
            if (p && p->state == C_PENDING) p->state = C_EMPTY;
            portEXIT_CRITICAL(&s_mux);
        }
    }
    return name;
}

bool oui_lookup(const uint8_t mac[6], char *buf, size_t len)
{
    if (!buf || !len) return false;
    buf[0] = '\0';
    if (!mac) return false;
    if (mac[0] & 0x02) { strlcpy(buf, OUI_PRIVATE, len); return true; }
    if (private_or_zero(mac) || !s_cache || !s_fmux) goto fallback;
    s_lookups++;

    uint8_t k[5];
    key_of(mac, k);
    portENTER_CRITICAL(&s_mux);
    cent_t *e = cache_slot(k, false);
    uint8_t st = e ? e->state : C_EMPTY;
    const char *cn = e ? e->name : NULL;
    portEXIT_CRITICAL(&s_mux);
    if (st == C_FOUND && cn) { s_hits++; strlcpy(buf, cn, len); return true; }
    if (st == C_NONE) { s_hits++; goto fallback; }

    char name[OUI_NAME_MAX] = "";
    bool found = false;
    xSemaphoreTake(s_fmux, portMAX_DELAY);
    if (hdr_refresh()) {
        FILE *f = fopen(OUI_PATH, "rb");
        if (f) {
            static const uint8_t BITS[3] = { 36, 28, 24 };
            for (int i = 0; i < 3 && !found; i++) {
                uint8_t key[6];
                memcpy(key, mac, 6);
                key[5] = 0;
                if (BITS[i] == 36) key[4] &= 0xf0;
                else { key[4] = 0; key[3] = BITS[i] == 28 ? (uint8_t)(key[3] & 0xf0) : 0; }
                uint32_t off;
                if (file_find(f, key, BITS[i], &off)) found = file_name(f, off, name, sizeof(name));
            }
            fclose(f);
        }
    }
    xSemaphoreGive(s_fmux);

    portENTER_CRITICAL(&s_mux);
    e = cache_slot(k, true);
    if (e) {
        e->state = found ? C_FOUND : C_NONE;
        e->name = found ? intern(name) : NULL;
    }
    portEXIT_CRITICAL(&s_mux);
    if (found) { strlcpy(buf, name, len); return true; }

fallback:
    {
        const char *v = wifi_manager_mac_vendor(mac);   // the compact table (cache says no)
        strlcpy(buf, v, len);
        return v[0] != '\0';
    }
}

void oui_service(int n)
{
    if (!s_missq) return;
    if (s_fmux && xSemaphoreTake(s_fmux, 0) == pdTRUE) { hdr_refresh(); xSemaphoreGive(s_fmux); }
    uint8_t m[6];
    char tmp[OUI_NAME_MAX];
    for (int i = 0; i < n && xQueueReceive(s_missq, m, 0) == pdTRUE; i++) oui_lookup(m, tmp, sizeof(tmp));
}

void oui_invalidate(void) { s_dirty = true; }

void oui_status(oui_status_t *out)
{
    memset(out, 0, sizeof(*out));
    if (s_fmux) {
        xSemaphoreTake(s_fmux, portMAX_DELAY);
        hdr_refresh();
        out->present  = s_hdr.present;
        out->count    = s_hdr.present ? s_hdr.count : 0;
        out->build_ts = s_hdr.present ? s_hdr.build_ts : 0;
        out->size     = s_hdr.present ? s_hdr.size : 0;
        xSemaphoreGive(s_fmux);
    }
    out->lookups = s_lookups;
    out->hits = s_hits;
    out->misses_queued = s_queued;
    out->pool_used = (uint32_t)s_pool_used;
}

void oui_init(void)
{
    s_cache = heap_caps_calloc(OUI_CACHE_N, sizeof(cent_t), MALLOC_CAP_SPIRAM);
    s_pool  = heap_caps_malloc(OUI_POOL_BYTES, MALLOC_CAP_SPIRAM);
    s_fmux  = xSemaphoreCreateMutex();
    s_missq = xQueueCreateWithCaps(MISSQ_DEPTH, 6, MALLOC_CAP_SPIRAM);
    if (!s_cache || !s_pool || !s_fmux || !s_missq) {
        ESP_LOGE(TAG, "No memory for the vendor cache, database lookups off");
        s_cache = NULL;                     // oui_cached() and oui_lookup() fall back
        return;
    }
}
