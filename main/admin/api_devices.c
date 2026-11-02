// Seen-devices route on the admin port. See api_devices.h.

#include "api_devices.h"
#include "discovery.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEND_TIMEOUT_S  10              // a client that stops reading can't hold the admin task
#define DEVICES_JSON_MAX (256 * 1024)   // 64 devices at about 0.9 KB each, plus up to about
                                        // 2.6 KB of Pi-hole data each (top domains with their
                                        // allowed and blocked counts; PSRAM, per request)

static bool send_all(int sock, const void *p, size_t n)
{
    const char *c = p;
    while (n) {
        int r = send(sock, c, n, 0);
        if (r <= 0) return false;
        c += r;
        n -= (size_t)r;
    }
    return true;
}

static bool send_head(int sock, const char *status, size_t len)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, (unsigned)len);
    if (n <= 0 || n >= (int)sizeof(hdr)) return false;
    return send_all(sock, hdr, (size_t)n);
}

bool api_devices_handle(int sock, const char *req, int req_len)
{
    (void)req_len;
    static const char pfx[] = "GET /api/devices";
    if (strncmp(req, pfx, sizeof(pfx) - 1) != 0) return false;
    const char *p = req + sizeof(pfx) - 1;
    if (*p != ' ' && *p != '?') return false;   // some other path

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char *buf = heap_caps_malloc(DEVICES_JSON_MAX, MALLOC_CAP_SPIRAM);
    if (!buf) {
        static const char e[] = "{\"error\":\"out of memory\"}";
        if (send_head(sock, "503 Service Unavailable", sizeof(e) - 1)) send_all(sock, e, sizeof(e) - 1);
        return true;
    }
    size_t n = discovery_devices_json(buf, DEVICES_JSON_MAX);
    if (send_head(sock, "200 OK", n)) send_all(sock, buf, n);
    free(buf);
    return true;
}
