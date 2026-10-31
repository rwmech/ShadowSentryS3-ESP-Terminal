#pragma once
#include <stdbool.h>
#include <stdint.h>

/*
 * WhatsApp alerts via CallMeBot, Core 1 (fork addition, Robert Mech)
 *
 * A notification-layer backend (notify.h): sends the boot "online" message
 * and incidents (opened, acknowledged, closed) to one WhatsApp number through
 * CallMeBot's free personal API, an HTTPS GET:
 *
 *   https://api.callmebot.com/whatsapp.php?phone=<number>&text=<urlencoded>&apikey=<key>
 *
 * Set up: follow the activation steps on
 * https://www.callmebot.com/blog/free-api-whatsapp-messages/ (add CallMeBot's
 * number as a contact and message it from WhatsApp); it replies with the
 * apikey. CallMeBot only sends to the number that registered the key, and the
 * free API is for personal use.
 *
 * Not the high-volume event log: only boot and incident transitions. Messages
 * are short plain text built from device data (no attacker text). CallMeBot
 * documents no rate limit, so the sender is conservative: one message every
 * WHATSAPP_MIN_GAP_MS and at most WHATSAPP_HOURLY_MAX per hour; anything over
 * the cap is dropped and counted.
 *
 * Settings: whatsapp_phone and whatsapp_apikey (a secret: never logged or
 * returned by the API, and the request URL that carries it is never logged).
 * Both set means on; applies at once.
 *
 * Meta's WhatsApp Cloud API (business account, templates, access tokens) is
 * the heavier official route and is not implemented.
 */

#define WHATSAPP_QUEUE_DEPTH    8
#define WHATSAPP_MIN_GAP_MS     10000   // between messages
#define WHATSAPP_HOURLY_MAX     20      // messages per hour (fixed window from the first send)
#define WHATSAPP_TASK_STACK     6144    // bytes; the high-water mark is logged after the first send

// Create the queue and register with the notification layer. Call once at
// boot, after notify_init(). Never blocks.
void whatsapp_init(void);

// FreeRTOS task entry point, Core 1. Spawn after whatsapp_init().
void whatsapp_task(void *arg);

// Queue a test message. Returns its request number (compare with test_done
// in whatsapp_status_t), or 0 when the task is not running.
uint32_t whatsapp_request_test(void);

typedef struct {
    uint32_t test_req;      // last test requested
    uint32_t test_done;     // last test finished
    int      test_status;   // its HTTP status, -1 transport error, 0 not configured
    bool     test_ok;
    int      last_status;   // last send's HTTP status (same coding)
    uint32_t sent;          // messages CallMeBot accepted (HTTP 2xx)
    uint32_t failed;        // messages given up on
    uint32_t dropped;       // lost to a full queue or the hourly cap
} whatsapp_status_t;

void whatsapp_get_status(whatsapp_status_t *out);
