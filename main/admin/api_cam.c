// Camera routes on the admin port. See api_cam.h.

#include "api_cam.h"
#include "cam.h"
#include "lwip/sockets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEND_TIMEOUT_S  10      // a client that stops reading can't hold the admin task

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

static bool send_head(int sock, const char *status, const char *ctype, size_t len)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n",
        status, ctype, (unsigned)len);
    if (n <= 0 || n >= (int)sizeof(hdr)) return false;
    return send_all(sock, hdr, (size_t)n);
}

static void get_jpeg(int sock)
{
    size_t len = 0;
    uint8_t *jpg = cam_last_dup(&len, NULL);    // private copy: send at leisure
    if (!jpg) {
        static const char e[] = "{\"error\":\"no snapshot\"}";
        if (send_head(sock, "404 Not Found", "application/json", sizeof(e) - 1))
            send_all(sock, e, sizeof(e) - 1);
        return;
    }
    if (send_head(sock, "200 OK", "image/jpeg", len))
        send_all(sock, jpg, len);
    free(jpg);
}

static void get_meta(int sock)
{
    cam_meta_t m;
    cam_last_meta(&m);
    // action is [a-z0-9_-] and file is built from it and digits (cam.c), so
    // neither needs JSON escaping.
    char body[256];
    int n = snprintf(body, sizeof(body),
        "{\"camera\":%s,\"seq\":%lu,\"ts\":%lu,\"action\":\"%s\",\"file\":\"%s\","
        "\"size\":%lu,\"width\":%u,\"height\":%u}",
        cam_ready() ? "true" : "false", (unsigned long)m.seq, (unsigned long)m.ts,
        m.action, m.file, (unsigned long)m.size, (unsigned)m.width, (unsigned)m.height);
    if (n <= 0 || n >= (int)sizeof(body)) return;
    if (send_head(sock, "200 OK", "application/json", (size_t)n))
        send_all(sock, body, (size_t)n);
}

bool api_cam_handle(int sock, const char *req, int req_len)
{
    (void)req_len;
    static const char pfx[] = "GET /api/snap/last";
    if (strncmp(req, pfx, sizeof(pfx) - 1) != 0) return false;
    const char *p = req + sizeof(pfx) - 1;
    bool json = strncmp(p, ".json", 5) == 0;
    if (json) p += 5;
    if (*p != ' ' && *p != '?') return false;   // some other path

    struct timeval tv = { .tv_sec = SEND_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (json) get_meta(sock);
    else      get_jpeg(sock);
    return true;
}
