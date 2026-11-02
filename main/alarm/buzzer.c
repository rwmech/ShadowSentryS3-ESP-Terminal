#include "buzzer.h"
#include "board.h"
#include "settings.h"
#include "driver/ledc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_log.h"

static const char *TAG = "BUZZER";

// LEDC timer/channel 1; timer/channel 0 drive the backlight.
#define BUZ_TIMER    LEDC_TIMER_1
#define BUZ_CHANNEL  LEDC_CHANNEL_1

// ── Loudness ─────────────────────────────────────────────────────────────────
// A passive piezo's loudness follows the fundamental of the square wave. At
// duty D the fundamental's amplitude is sin(pi * D) of the 50 % one: 20 % is
// 0.59 (about -5 dB), 12.5 % 0.38 (-8 dB), 8 % 0.25 (-12 dB), 6.25 % 0.20
// (-14 dB), 3 % 0.094 (-20.5 dB). Counts of the 10-bit timer (1024 = 100 %).
// UI sounds (ui_volume: off, low, medium, high): 0, 3 %, 8 %, 20 %.
static const uint16_t UI_DUTY[4]     = { 0, 31, 82, 205 };
// Klaxon (alarm_volume: low, medium, high): 8 %, 20 %, 50 %. High is the
// loudest a piezo gets; low is the floor (an alarm is never silent, the alarm
// sound setting is the off switch). Index 0 is never used.
static const uint16_t KLAX_DUTY[4]   = { 82, 82, 205, 512 };
// Yellow call, softer than the klaxon at each level: 3 %, 6.25 %, 12.5 %.
static const uint16_t YELLOW_DUTY[4] = { 32, 32, 64, 128 };

static uint16_t ui_duty(void)
{
    uint8_t v = settings_get()->ui_volume;
    return UI_DUTY[v <= 3 ? v : 1];
}

static uint8_t alarm_level(void)
{
    uint8_t v = settings_get()->alarm_volume;
    return v >= 1 && v <= 3 ? v : 3;
}

// ── Tone tables ──────────────────────────────────────────────────────────────
// Every sound the buzzer plays is in this section, so a retune is one edit.

// Red alert klaxon, after the DS9 / Voyager red alert: a deep two-tone warble
// with a rising tail, three bursts. The piezo is weak far below its 2.7 kHz
// resonance, so the low notes are chosen for their harmonics: a 50 % square
// wave carries odd harmonics (1/3 of the fundamental at 3f, 1/5 at 5f), and the
// 3rd harmonics of 860 Hz (2580 Hz) and 1000 Hz (3000 Hz) sit either side of
// the resonance, so both notes come out loud and about equally so, while the
// ear still hears the 860 / 1000 Hz pitch. A lower pair puts the 3rd harmonic
// below 2.3 kHz and leans on the 5th, at a fifth of the level.
// Per burst: 12 notes of 75 ms alternating low and high (900 ms), then a rise
// from 2300 to 3100 Hz in 8 steps of 20 ms across the resonance (the loudest
// part), then 200 ms quiet. 3 bursts, 3.28 s with no gap after the last.
#define KLAX_LO_HZ          860
#define KLAX_HI_HZ          1000
#define KLAX_NOTE_MS        75
#define KLAX_NOTES          12
#define KLAX_RISE_LO_HZ     2300
#define KLAX_RISE_HI_HZ     3100
#define KLAX_RISE_STEPS     8
#define KLAX_RISE_STEP_MS   20
#define KLAX_GAP_MS         200
#define KLAX_BURSTS         3
#define KLAX_POLL_MS        25      // a STOP ends the klaxon within this

// Steps are played back to back, the tone held across frequency changes;
// hz 0 is a silence.
typedef struct { uint16_t hz, ms; } step_t;

// Console sounds, after the LCARS panel taps: very short tones near the
// resonance. Rising for a tap and a confirm, falling for a cancel, a held
// two-tone for a completed hold.
static const step_t TAP[]     = { { 2600, 18 }, { 3200, 18 } };
static const step_t CONFIRM[] = { { 2400, 20 }, { 2900, 20 }, { 3400, 25 } };
static const step_t CANCEL[]  = { { 3200, 25 }, { 2400, 35 } };
static const step_t ACKED[]   = { { 3000, 60 }, { 0, 30 }, { 3400, 120 } };

// Boot (replaces the startup melody): three short rising computer beeps, TNG
// style, 290 ms. Designed, not measured from a sample.
static const step_t BOOT[]    = { { 2500, 45 }, { 0, 50 }, { 2900, 45 }, { 0, 50 }, { 3300, 100 } };

// YELLOW incident opened (buzzer_yellow): one soft two-note "attention" call,
// rising, 290 ms, at YELLOW_DUTY.
static const step_t ATTENTION[] = { { 2000, 100 }, { 0, 30 }, { 2600, 160 } };

#define STEPS(a) { a, sizeof(a) / sizeof(a[0]) }
typedef struct { const step_t *s; uint8_t n; } steps_t;
static const steps_t CHIRPS[] = {
    [BUZZER_CHIRP_TAP]     = STEPS(TAP),
    [BUZZER_CHIRP_CONFIRM] = STEPS(CONFIRM),
    [BUZZER_CHIRP_CANCEL]  = STEPS(CANCEL),
    [BUZZER_CHIRP_ACK]     = STEPS(ACKED),
};
_Static_assert(sizeof(CHIRPS) / sizeof(CHIRPS[0]) == BUZZER_CHIRP_COUNT, "CHIRPS: one per buzzer_chirp_t");
static const steps_t BOOT_STEPS   = STEPS(BOOT);
static const steps_t YELLOW_STEPS = STEPS(ATTENTION);

// ── Task ─────────────────────────────────────────────────────────────────────

// The siren plays on its own task, so the alarm task (whose queue takes every
// event from the traps) and the admin task never block for 3 s.
#define BUZ_TASK_STACK   3072
#define BUZ_TASK_PRIO    3          // below the alarm task (4), above the UI (2)
#define BUZ_QUEUE_DEPTH  8

// CMD_CHIRP + a buzzer_chirp_t is that chirp.
typedef enum { CMD_SIREN, CMD_TEST, CMD_STOP, CMD_YELLOW, CMD_BOOT, CMD_CHIRP } buz_cmd_t;

static bool              s_ok = false;
static SemaphoreHandle_t s_lock;    // the buzzer task and a caller without one share it
static QueueHandle_t     s_cmds;    // NULL: no buzzer task, play on the caller
static uint16_t          s_klax_duty = 512; // from alarm_volume, as a klaxon starts

static void buzzer_task(void *arg);

void buzzer_init(void)
{
    ledc_timer_config_t t = {
        .speed_mode      = LEDC_LOW_SPEED_MODE,
        .duty_resolution = LEDC_TIMER_10_BIT,
        .timer_num       = BUZ_TIMER,
        .freq_hz         = BOARD_BUZZER_HZ,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    ledc_channel_config_t c = {
        .gpio_num   = BOARD_BUZZER,
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .channel    = BUZ_CHANNEL,
        .timer_sel  = BUZ_TIMER,
        .duty       = 0,
        .hpoint     = 0,
    };
    if (ledc_timer_config(&t) != ESP_OK || ledc_channel_config(&c) != ESP_OK) {
        ESP_LOGE(TAG, "LEDC setup failed, buzzer disabled");
        return;
    }
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        ESP_LOGE(TAG, "No heap for the buzzer mutex, buzzer disabled");
        return;
    }
    s_ok = true;

    s_cmds = xQueueCreate(BUZ_QUEUE_DEPTH, sizeof(uint8_t));
    // Stack in PSRAM: the task only drives LEDC and reads the live settings,
    // never flash or NVS.
    if (!s_cmds || xTaskCreatePinnedToCoreWithCaps(buzzer_task, "buzzer", BUZ_TASK_STACK, NULL,
                                                   BUZ_TASK_PRIO, NULL, 1,
                                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        ESP_LOGW(TAG, "No heap for the buzzer task, the siren plays on the caller");
        if (s_cmds) vQueueDelete(s_cmds);
        s_cmds = NULL;
    }
}

// Play steps at a duty, the tone held across frequency changes; hz 0 is a
// silence. Caller holds s_lock. The timer goes back to BOARD_BUZZER_HZ.
static void play_steps(const step_t *st, size_t n, uint32_t duty)
{
    bool on = false;
    for (size_t i = 0; i < n; i++) {
        bool want = st[i].hz != 0;
        if (want) ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, st[i].hz);
        if (want != on) {
            on = want;
            ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, on ? duty : 0);
            ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
        }
        vTaskDelay(pdMS_TO_TICKS(st[i].ms));
    }
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, BOARD_BUZZER_HZ);
}

// A STOP at the head of the queue ends the siren early. A SIREN or TEST
// queued behind the one playing waits its turn, so the order holds.
static bool stop_requested(void)
{
    uint8_t c;
    if (!s_cmds || xQueuePeek(s_cmds, &c, 0) != pdTRUE || c != CMD_STOP) return false;
    xQueueReceive(s_cmds, &c, 0);
    return true;
}

// Hold one klaxon note (hz 0: quiet) for ms, in KLAX_POLL_MS slices. False as
// soon as a STOP is at the head of the queue.
static bool klax_hold(int hz, int ms)
{
    if (hz) ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, hz);
    // Duty is a count, so it stays the same share at any frequency.
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, hz ? s_klax_duty : 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    while (ms > 0) {
        int step = ms < KLAX_POLL_MS ? ms : KLAX_POLL_MS;
        vTaskDelay(pdMS_TO_TICKS(step));
        ms -= step;
        if (stop_requested()) return false;
    }
    return true;
}

// The red alert klaxon. Takes s_lock for the whole of it; the timer goes back
// to BOARD_BUZZER_HZ before the lock is released.
static void siren_play(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_klax_duty = KLAX_DUTY[alarm_level()];
    bool go = true;
    for (int b = 0; b < KLAX_BURSTS && go; b++) {
        for (int i = 0; i < KLAX_NOTES && go; i++)
            go = klax_hold(i & 1 ? KLAX_HI_HZ : KLAX_LO_HZ, KLAX_NOTE_MS);
        for (int i = 0; i < KLAX_RISE_STEPS && go; i++)
            go = klax_hold(KLAX_RISE_LO_HZ + i * (KLAX_RISE_HI_HZ - KLAX_RISE_LO_HZ) / (KLAX_RISE_STEPS - 1),
                           KLAX_RISE_STEP_MS);
        if (go && b + 1 < KLAX_BURSTS) go = klax_hold(0, KLAX_GAP_MS);
    }
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, BOARD_BUZZER_HZ);
    xSemaphoreGive(s_lock);
}

static void buzzer_task(void *arg)
{
    (void)arg;
    for (;;) {
        uint8_t c;
        if (xQueueReceive(s_cmds, &c, portMAX_DELAY) != pdTRUE) continue;
        if (c >= CMD_CHIRP && c < CMD_CHIRP + BUZZER_CHIRP_COUNT) {
            // Touch feedback, so the click setting and the UI volume govern
            // it. Skipped, not queued, while the klaxon holds the buzzer.
            uint16_t duty = ui_duty();
            if (settings_get()->touch_click && duty && xSemaphoreTake(s_lock, 0) == pdTRUE) {
                play_steps(CHIRPS[c - CMD_CHIRP].s, CHIRPS[c - CMD_CHIRP].n, duty);
                xSemaphoreGive(s_lock);
            }
            continue;
        }
        if (c == CMD_BOOT) {
            // The boot setting and the UI volume govern the boot beeps.
            uint16_t duty = ui_duty();
            if (settings_get()->boot_chirp && duty && xSemaphoreTake(s_lock, pdMS_TO_TICKS(300)) == pdTRUE) {
                play_steps(BOOT_STEPS.s, BOOT_STEPS.n, duty);
                xSemaphoreGive(s_lock);
            }
            continue;
        }
        if (c == CMD_YELLOW) {
            // An alarm sound, so the alarm sound setting governs it, at the
            // alarm volume. Waits out a chirp; skipped while the klaxon plays.
            if (settings_get()->alarm_sound && xSemaphoreTake(s_lock, pdMS_TO_TICKS(300)) == pdTRUE) {
                play_steps(YELLOW_STEPS.s, YELLOW_STEPS.n, YELLOW_DUTY[alarm_level()]);
                xSemaphoreGive(s_lock);
            }
            continue;
        }
        // The alarm sound setting is read when the siren starts, not when queued.
        if (c == CMD_TEST || (c == CMD_SIREN && settings_get()->alarm_sound)) {
            siren_play();
            static bool logged = false;
            if (!logged) {
                logged = true;
                ESP_LOGI(TAG, "First siren done, stack high-water %u B",
                         (unsigned)uxTaskGetStackHighWaterMark(NULL));
            }
        }
        // A STOP with nothing playing has nothing to stop.
    }
}

static void request(buz_cmd_t cmd)
{
    if (!s_ok) return;
    if (cmd >= CMD_YELLOW) {
        // Chirps, the boot beeps and the yellow call play only on the buzzer
        // task (no task: skipped, the UI never blocks), and a full queue drops
        // them quietly.
        uint8_t c = (uint8_t)cmd;
        if (s_cmds) xQueueSend(s_cmds, &c, 0);
        return;
    }
    if (s_cmds) {
        uint8_t c = (uint8_t)cmd;
        if (xQueueSend(s_cmds, &c, 0) != pdTRUE) ESP_LOGW(TAG, "Buzzer queue full, request dropped");
        return;
    }
    // No buzzer task: play here, blocking the caller for the siren.
    if (cmd == CMD_TEST || (cmd == CMD_SIREN && settings_get()->alarm_sound)) siren_play();
}

void buzzer_alarm(void)  { request(CMD_SIREN); }
void buzzer_remind(void) { request(CMD_SIREN); }
void buzzer_test(void)   { request(CMD_TEST); }
void buzzer_yellow(void) { request(CMD_YELLOW); }
void buzzer_boot(void)   { request(CMD_BOOT); }
void buzzer_chirp(buzzer_chirp_t k)
{
    if ((unsigned)k < BUZZER_CHIRP_COUNT) request((buz_cmd_t)(CMD_CHIRP + (int)k));
}

// To the front of the queue: stop_requested() only looks at the head, so a
// CONFIRM (or anything else) queued behind the playing siren must not hide it.
void buzzer_stop(void)
{
    if (!s_ok || !s_cmds) return;
    uint8_t c = CMD_STOP;
    if (xQueueSendToFront(s_cmds, &c, 0) != pdTRUE) ESP_LOGW(TAG, "Buzzer queue full, stop dropped");
}

// Every press on the glass: the tap chirp, on the buzzer task (36 ms, too long
// to play on the UI task as the old 10 ms click did).
void buzzer_click(void) { buzzer_chirp(BUZZER_CHIRP_TAP); }
