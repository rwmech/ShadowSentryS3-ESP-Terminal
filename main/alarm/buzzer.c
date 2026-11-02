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
#include <string.h>

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

// Red alert klaxon, after the TNG red alert: a rising "whoop", cut off at the
// top, repeated. Designed, not measured: the meWho Titan samples
// (https://www.mewho.com/titan/assets/redalert1a-lTLACCH2.mp3 and
// redalert2a-8uSShXFi.mp3) are MP3 and could not be decoded here. Timing from
// a hobbyist description of the TNG klaxon (homemade-circuits.com, 555
// recreation): a rise from low to high over about 1.15 s, then 0.35 s off,
// repeated. No published pitch, so the sweep is placed for the piezo: 1600 to
// 3000 Hz, an octave less a tone, rising into and through the 2.7 kHz
// resonance, so it swells to its loudest at the top as the real one does.
// Per whoop: 46 steps of 25 ms (1150 ms), then 350 ms quiet. 3 whoops, 4.15 s
// with no gap after the last. Duty from alarm_volume (KLAX_DUTY).
#define KLAX_SWEEP_LO_HZ    1600
#define KLAX_SWEEP_HI_HZ    3000
#define KLAX_SWEEP_STEPS    46
#define KLAX_STEP_MS        25
#define KLAX_GAP_MS         350
#define KLAX_WHOOPS         3
#define KLAX_POLL_MS        25      // a STOP ends the klaxon within this

// Steps are played back to back, the tone held across frequency changes;
// hz 0 is a silence.
typedef struct { uint16_t hz, ms; } step_t;

// Console sounds, TNG / LCARS style: short square-wave tones near the
// resonance (2.4 to 3.4 kHz, where the piezo is loudest, so even the low UI
// volume carries). Designed from descriptions of the TNG panel sounds (short,
// bright, two or three quick pitches; a rising "commit" chirp for an accepted
// entry, a falling pair for a refusal), not measured: the thelcars.com
// beep1..5.mp3 samples could not be decoded here.
// Tap, every press (Rob: "sound right"): a quick rising blip, 36 ms.
static const step_t TAP[]     = { { 2600, 18 }, { 3200, 18 } };
// Commit (BUZZER_CHIRP_CONFIRM: a dialog confirmed): the TNG computer's
// accepted-entry chirp, two quick rising pips and a held top, 165 ms.
static const step_t CONFIRM[] = { { 2600, 30 }, { 0, 15 }, { 3000, 30 }, { 0, 15 }, { 3400, 75 } };
// Cancel (cancelled or refused): a falling pair, the commit turned over, 90 ms.
static const step_t CANCEL[]  = { { 3200, 35 }, { 0, 15 }, { 2400, 55 } };
// Ack (a hold completed): the commit's held two-tone, longer, 190 ms.
static const step_t ACKED[]   = { { 3000, 50 }, { 0, 30 }, { 3400, 110 } };

// Boot (replaces the startup melody): three short rising computer beeps, TNG
// style, 290 ms. Designed, not measured from a sample.
static const step_t BOOT[]    = { { 2500, 45 }, { 0, 50 }, { 2900, 45 }, { 0, 50 }, { 3300, 100 } };

// YELLOW incident opened (buzzer_yellow): one short, soft whoop, the red
// alert's shape in small: 2000 to 2800 Hz in 10 steps of 25 ms (250 ms), at
// YELLOW_DUTY. Designed, not measured (no yellow alert sample found).
static const step_t ATTENTION[] = {
    { 2000, 25 }, { 2089, 25 }, { 2178, 25 }, { 2267, 25 }, { 2356, 25 },
    { 2444, 25 }, { 2533, 25 }, { 2622, 25 }, { 2711, 25 }, { 2800, 25 },
};

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

// CMD_CHIRP + a buzzer_chirp_t is that chirp; CMD_PREVIEW + a buzzer_sound_t
// is that sound for the Settings test player.
typedef enum { CMD_SIREN, CMD_TEST, CMD_STOP, CMD_YELLOW, CMD_BOOT, CMD_CHIRP,
               CMD_PREVIEW = CMD_CHIRP + BUZZER_CHIRP_COUNT } buz_cmd_t;
_Static_assert(CMD_PREVIEW + BUZZER_SOUND_COUNT <= 255, "buzzer commands fit a byte");

// Test player names (POST /api/buzzer/test {"sound":...}), one per buzzer_sound_t.
static const char *const SOUND_KEY[] = {
    [BUZZER_SOUND_KLAXON] = "klaxon",
    [BUZZER_SOUND_YELLOW] = "yellow",
    [BUZZER_SOUND_BOOT]   = "boot",
    [BUZZER_SOUND_TAP]    = "tap",
    [BUZZER_SOUND_COMMIT] = "commit",
    [BUZZER_SOUND_CANCEL] = "cancel",
    [BUZZER_SOUND_ACK]    = "ack",
};
_Static_assert(sizeof(SOUND_KEY) / sizeof(SOUND_KEY[0]) == BUZZER_SOUND_COUNT, "SOUND_KEY: one per buzzer_sound_t");

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
    for (int w = 0; w < KLAX_WHOOPS && go; w++) {
        for (int i = 0; i < KLAX_SWEEP_STEPS && go; i++)
            go = klax_hold(KLAX_SWEEP_LO_HZ + i * (KLAX_SWEEP_HI_HZ - KLAX_SWEEP_LO_HZ) / (KLAX_SWEEP_STEPS - 1),
                           KLAX_STEP_MS);
        if (go && w + 1 < KLAX_WHOOPS) go = klax_hold(0, KLAX_GAP_MS);
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
        if (c > CMD_PREVIEW && c < CMD_PREVIEW + BUZZER_SOUND_COUNT) {
            // Test player: plays whatever the on/off settings say, at the
            // current volumes (a UI volume of off is silent). The klaxon
            // preview is CMD_TEST.
            buzzer_sound_t k = (buzzer_sound_t)(c - CMD_PREVIEW);
            const steps_t *st = &YELLOW_STEPS;
            uint16_t duty = ui_duty();
            switch (k) {
            case BUZZER_SOUND_YELLOW: duty = YELLOW_DUTY[alarm_level()]; break;
            case BUZZER_SOUND_BOOT:   st = &BOOT_STEPS; break;
            case BUZZER_SOUND_TAP:    st = &CHIRPS[BUZZER_CHIRP_TAP]; break;
            case BUZZER_SOUND_COMMIT: st = &CHIRPS[BUZZER_CHIRP_CONFIRM]; break;
            case BUZZER_SOUND_CANCEL: st = &CHIRPS[BUZZER_CHIRP_CANCEL]; break;
            default:                  st = &CHIRPS[BUZZER_CHIRP_ACK]; break;
            }
            if (duty && xSemaphoreTake(s_lock, pdMS_TO_TICKS(300)) == pdTRUE) {
                play_steps(st->s, st->n, duty);
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

void buzzer_preview(buzzer_sound_t k)
{
    if (k == BUZZER_SOUND_KLAXON) request(CMD_TEST);
    else if ((unsigned)k < BUZZER_SOUND_COUNT) request((buz_cmd_t)(CMD_PREVIEW + (int)k));
}

int buzzer_sound_from_key(const char *key)
{
    if (!key) return -1;
    for (int i = 0; i < BUZZER_SOUND_COUNT; i++)
        if (!strcmp(key, SOUND_KEY[i])) return i;
    return -1;
}
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
