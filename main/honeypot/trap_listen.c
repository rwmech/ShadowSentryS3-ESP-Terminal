#include "trap_listen.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include <errno.h>
#include <string.h>

static const char *TAG = "LISTEN";

// ── Listen sockets ────────────────────────────────────────────────────────────

int trap_listen(uint16_t port, int backlog)
{
    if (port == 0) return -1;

    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv < 0) {
        ESP_LOGE(TAG, "socket() for port %u failed: errno %d", (unsigned)port, errno);
        return -1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(srv, backlog) != 0) {
        ESP_LOGE(TAG, "bind/listen on port %u failed: errno %d", (unsigned)port, errno);
        close(srv);
        return -1;
    }
    return srv;
}

// ── Accept on any ─────────────────────────────────────────────────────────────

int trap_accept_any(const int *srv, const uint16_t *ports, int n,
                    struct sockaddr_in *client, uint16_t *port)
{
    fd_set rd;
    FD_ZERO(&rd);
    int maxfd = -1;
    for (int i = 0; i < n; i++) {
        if (srv[i] < 0) continue;
        FD_SET(srv[i], &rd);
        if (srv[i] > maxfd) maxfd = srv[i];
    }
    if (maxfd < 0) {                         // nothing to listen on: idle, don't spin
        vTaskDelay(pdMS_TO_TICKS(1000));
        return -1;
    }

    if (select(maxfd + 1, &rd, NULL, NULL, NULL) <= 0) return -1;

    for (int i = 0; i < n; i++) {
        if (srv[i] < 0 || !FD_ISSET(srv[i], &rd)) continue;
        socklen_t clen = sizeof(*client);
        int csock = accept(srv[i], (struct sockaddr *)client, &clen);
        if (csock < 0) {
            // Out of sockets (CONFIG_LWIP_MAX_SOCKETS): the connection stays
            // pending and select() stays ready, so back off instead of spinning.
            ESP_LOGW(TAG, "accept on port %u failed: errno %d", (unsigned)ports[i], errno);
            vTaskDelay(pdMS_TO_TICKS(200));
            return -1;
        }
        *port = ports[i];
        return csock;
    }
    return -1;
}
