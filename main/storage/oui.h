#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sd_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MAC vendor database on the microSD card (fork addition, Robert Mech)
 *
 * /sd/oui.bin is built on the PC from the IEEE Registration Authority's public
 * registry (MA-L, MA-M, MA-S and IAB) by tools/make_oui.py and uploaded with
 * POST /api/oui (tools/oui_upload.py or the Settings page). Little-endian:
 *
 *   header, 24 B   magic "SSOU", u16 version (1), u16 record size (12),
 *                  u32 count, u32 build time (unix), u32 string table offset
 *                  (= 24 + 12 * count), u32 string table length
 *   records        count x { u8 prefix[6] (bits past the length zero),
 *                  u8 bits (24, 28 or 36), u8 0, u32 name offset }, sorted by
 *                  (prefix, bits)
 *   strings        NUL-terminated vendor names, deduplicated, ASCII, at most
 *                  OUI_NAME_MAX - 1 characters each
 *
 * oui_lookup() reads the card (a binary search per prefix length, 36 then 28
 * then 24 bits, each read bounded and checked), so it runs only on the
 * discovery task or the admin task. Results go into a 64-entry LRU cache in
 * PSRAM; names are interned into an append-only pool, so a pointer handed
 * out stays valid for ever. oui_cached() reads only that cache and never
 * touches the card: it is safe from any task (wifi_manager_mac_vendor() uses
 * it), and queues a miss for oui_service() on the discovery task.
 *
 * A locally administered MAC (phones randomise theirs) is never looked up.
 * Without the file, or for a prefix it does not have, the compact table in
 * wifi_manager_mac_vendor() answers.
 */

#define OUI_PATH        SD_MOUNT_POINT "/oui.bin"
#define OUI_VERSION     1
#define OUI_REC_SIZE    12
#define OUI_HDR_SIZE    24
#define OUI_MAX_BYTES   (4u * 1024u * 1024u)
#define OUI_MAX_COUNT   300000u
#define OUI_NAME_MAX    41              // 40 characters and the NUL
#define OUI_CACHE_N     64
#define OUI_POOL_BYTES  (16 * 1024)     // interned names
#define OUI_PRIVATE     "randomized (private)"   // as wifi_manager_mac_vendor()

typedef struct {
    bool     present;                   // the file is there and its header is valid
    uint32_t count, build_ts, size;
    uint32_t lookups, hits, misses_queued, pool_used;
} oui_status_t;

// After sd_log_init(). Cache, name pool and miss queue in PSRAM.
void oui_init(void);

// Vendor of mac into buf (len bytes): the database, else the compact table,
// "" if neither knows it, OUI_PRIVATE for a locally administered MAC. May read
// the card: discovery or admin task only. True when a name was written.
bool oui_lookup(const uint8_t mac[6], char *buf, size_t len);

// The cached database name for mac, or NULL (not cached, not in the file, or
// private). Never touches the card; a miss is queued for oui_service(). Any task.
const char *oui_cached(const uint8_t mac[6]);

// Resolve up to n queued misses. Discovery task.
void oui_service(int n);

// The file changed (an upload was queued): re-read its header on next use.
void oui_invalidate(void);

// Status, re-reading the header if needed. Discovery or admin task.
void oui_status(oui_status_t *out);

// Header checks for an upload of len bytes: magic, version, record size,
// count, string table offset and length against len. Fills count and build_ts.
bool oui_header_ok(const uint8_t *buf, size_t len, uint32_t *count, uint32_t *build_ts);

#ifdef __cplusplus
}
#endif
