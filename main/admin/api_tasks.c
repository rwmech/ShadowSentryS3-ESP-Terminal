#include "api_tasks.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"
#include <stdio.h>
#include <string.h>

#define TASKS_MAX     48          // snapshot slots; more tasks than this are cut
#define OUT_MAX       (8 * 1024)  // JSON body, PSRAM
#define SAMPLE_MS     1000

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

static void reply(int sock, const char *status, const char *body, size_t len)
{
    char hdr[192];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n", status, (unsigned)len);
    if (n > 0 && n < (int)sizeof(hdr) && send_all(sock, hdr, (size_t)n)) send_all(sock, body, len);
}

static int find(const TaskStatus_t *a, int n, TaskHandle_t h)
{
    for (int i = 0; i < n; i++) if (a[i].xHandle == h) return i;
    return -1;
}

bool api_tasks_handle(int sock, const char *req, int req_len)
{
    (void)req_len;
    if (strncmp(req, "GET /api/tasks", 14) != 0 || (req[14] != ' ' && req[14] != '?')) return false;

    TaskStatus_t *a = heap_caps_calloc(TASKS_MAX, sizeof(TaskStatus_t), MALLOC_CAP_SPIRAM);
    TaskStatus_t *b = heap_caps_calloc(TASKS_MAX, sizeof(TaskStatus_t), MALLOC_CAP_SPIRAM);
    char *out = heap_caps_malloc(OUT_MAX, MALLOC_CAP_SPIRAM);
    if (!a || !b || !out) {
        free(a); free(b); free(out);
        static const char e[] = "{\"error\":\"out of memory\"}";
        reply(sock, "503 Service Unavailable", e, sizeof(e) - 1);
        return true;
    }

    configRUN_TIME_COUNTER_TYPE t0 = 0, t1 = 0;
    int na = (int)uxTaskGetSystemState(a, TASKS_MAX, &t0);
    vTaskDelay(pdMS_TO_TICKS(SAMPLE_MS));
    int nb = (int)uxTaskGetSystemState(b, TASKS_MAX, &t1);
    // The counters are per core; the total is wall time on both cores.
    uint64_t window = (uint64_t)(t1 - t0) * portNUM_PROCESSORS;
    uint64_t total  = (uint64_t)t1 * portNUM_PROCESSORS;

    size_t o = 0;
    o += (size_t)snprintf(out + o, OUT_MAX - o, "{\"sample_ms\":%d,\"cores\":%d,\"tasks\":[",
                          SAMPLE_MS, portNUM_PROCESSORS);
    for (int i = 0; i < nb && o < OUT_MAX - 200; i++) {
        int j = find(a, na, b[i].xHandle);
        uint64_t d = j >= 0 ? (uint64_t)(b[i].ulRunTimeCounter - a[j].ulRunTimeCounter) : 0;
        unsigned pct10  = window ? (unsigned)(d * 1000 / window) : 0;
        unsigned boot10 = total ? (unsigned)((uint64_t)b[i].ulRunTimeCounter * 1000 / total) : 0;
        BaseType_t cid = xTaskGetCoreID(b[i].xHandle);
        int core = cid == tskNO_AFFINITY ? -1 : (int)cid;
        o += (size_t)snprintf(out + o, OUT_MAX - o,
            "%s{\"name\":\"%.16s\",\"cpu_pct\":%u.%u,\"boot_pct\":%u.%u,\"prio\":%u,\"core\":%d,"
            "\"stack_free\":%u}",
            i ? "," : "", b[i].pcTaskName, pct10 / 10, pct10 % 10, boot10 / 10, boot10 % 10,
            (unsigned)b[i].uxCurrentPriority, core,
            (unsigned)(b[i].usStackHighWaterMark * sizeof(StackType_t)));
    }
    if (o > OUT_MAX - 3) o = OUT_MAX - 3;
    out[o++] = ']';
    out[o++] = '}';
    reply(sock, "200 OK", out, o);
    free(a);
    free(b);
    free(out);
    return true;
}
