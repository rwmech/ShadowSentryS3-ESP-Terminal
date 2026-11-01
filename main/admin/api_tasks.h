#pragma once
/*
 * GET /api/tasks: per-task CPU share and stack high-water, for a board with
 * no serial console (fork, network diagnosis 2026-11-01).
 *
 * Takes two snapshots of every task's run-time counter one second apart and
 * reports, per task: the share of that second ("cpu_pct", of both cores
 * together, so 50 is one core), the share since boot, priority, core
 * affinity (-1 = either) and the stack high-water in bytes. Holds the admin
 * task for about a second. Needs CONFIG_FREERTOS_USE_TRACE_FACILITY and
 * CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS (sdkconfig.defaults).
 */
#include <stdbool.h>

// Handles GET /api/tasks; false for anything else.
bool api_tasks_handle(int sock, const char *req, int req_len);
