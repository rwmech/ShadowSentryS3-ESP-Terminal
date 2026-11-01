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
#define BUZ_DUTY_ON  512            // 50 % of 10-bit: loudest for a passive piezo

// Siren: a sweep up and down across the piezo's 2.7 kHz resonance, the duty
// held at 50 % throughout. 2300 to 3100 Hz in 50 Hz steps of 25 ms: 16 steps
// up and 16 down make an 800 ms cycle, 4 cycles make 3.2 s.
#define SIREN_LO_HZ      2300
#define SIREN_HI_HZ      3100
#define SIREN_STEP_HZ    50
#define SIREN_STEP_MS    25
#define SIREN_CYCLES     4

// The siren plays on its own task, so the alarm task (whose queue takes every
// event from the traps) and the admin task never block for 3 s.
#define BUZ_TASK_STACK   3072
#define BUZ_TASK_PRIO    3          // below the alarm task (4), above the UI (2)
#define BUZ_QUEUE_DEPTH  8

typedef enum { CMD_SIREN, CMD_TEST, CMD_STOP, CMD_CONFIRM, CMD_YELLOW } buz_cmd_t;

// YELLOW condition opened: one soft falling tone, about 300 ms, well off the
// piezo's resonance and at a low duty, so it reads as a notice, not the siren.
#define YELLOW_HI_HZ     1400
#define YELLOW_LO_HZ     1050
#define BUZ_DUTY_SOFT    64             // 6 % of 10-bit

// Hold-to-confirm done: two short rising pips, about 110 ms.
#define CONFIRM_LO_HZ    2700
#define CONFIRM_HI_HZ    3400

static bool              s_ok = false;
static SemaphoreHandle_t s_lock;    // buzzer, melody and UI tasks share the buzzer
static QueueHandle_t     s_cmds;    // NULL: no buzzer task, play on the caller
// A siren is waiting for the buzzer. Set on request, cleared once it holds the
// lock. A tune playing checks it every 10 ms and gives way. A flag, not a peek
// at the queue: the buzzer task takes the SIREN off the queue at once and then
// waits on the lock, so the queue head never shows it.
static volatile bool     s_siren_wanted;

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

static void tone(int hz, int on_ms, int off_ms)
{
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, hz);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, BUZ_DUTY_ON);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    vTaskDelay(pdMS_TO_TICKS(on_ms));
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    if (off_ms) vTaskDelay(pdMS_TO_TICKS(off_ms));
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

// Takes s_lock for the whole siren; the timer goes back to BOARD_BUZZER_HZ
// before the lock is released.
static void siren_play(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_siren_wanted = false;
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, SIREN_LO_HZ);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, BUZ_DUTY_ON);   // duty is a count: holds 50 % across frequencies
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    bool stop = false;
    const int half = (SIREN_HI_HZ - SIREN_LO_HZ) / SIREN_STEP_HZ;   // 16 steps
    for (int c = 0; c < SIREN_CYCLES && !stop; c++) {
        // i 0..16 climbs 2300..3100, i 17..31 falls 3050..2350.
        for (int i = 0; i < 2 * half; i++) {
            int up = i <= half ? i : 2 * half - i;
            ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, SIREN_LO_HZ + up * SIREN_STEP_HZ);
            vTaskDelay(pdMS_TO_TICKS(SIREN_STEP_MS));
            if ((stop = stop_requested())) break;
        }
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
        if (c == CMD_CONFIRM) {
            // Touch feedback, so the click setting governs it. Skipped, not
            // queued, while the boot tune holds the buzzer.
            if (settings_get()->touch_click && xSemaphoreTake(s_lock, 0) == pdTRUE) {
                tone(CONFIRM_LO_HZ, 40, 30);
                tone(CONFIRM_HI_HZ, 40, 0);
                ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, BOARD_BUZZER_HZ);
                xSemaphoreGive(s_lock);
            }
            continue;
        }
        if (c == CMD_YELLOW) {
            // The alarm sound setting governs it; waits out a click, not the
            // boot tune or a siren.
            if (settings_get()->alarm_sound && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
                ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, YELLOW_HI_HZ);
                ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, BUZ_DUTY_SOFT);
                ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
                vTaskDelay(pdMS_TO_TICKS(120));
                ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, YELLOW_LO_HZ);
                vTaskDelay(pdMS_TO_TICKS(180));
                ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
                ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
                ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, BOARD_BUZZER_HZ);
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
        } else if (c == CMD_SIREN) {
            s_siren_wanted = false;     // switched off since it was queued
        }
        // A STOP with nothing playing has nothing to stop.
    }
}

static void request(buz_cmd_t cmd)
{
    if (!s_ok) return;
    if (cmd == CMD_TEST || (cmd == CMD_SIREN && settings_get()->alarm_sound))
        s_siren_wanted = true;          // a tune playing stops for it
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
void buzzer_confirm(void){ if (s_cmds) request(CMD_CONFIRM); }   // no task: skip, never block the UI
void buzzer_yellow(void) { if (s_cmds) request(CMD_YELLOW); }    // no task: skip, never block the alarm

// To the front of the queue: stop_requested() only looks at the head, so a
// CONFIRM (or anything else) queued behind the playing siren must not hide it.
void buzzer_stop(void)
{
    if (!s_ok || !s_cmds) return;
    uint8_t c = CMD_STOP;
    if (xQueueSendToFront(s_cmds, &c, 0) != pdTRUE) ESP_LOGW(TAG, "Buzzer queue full, stop dropped");
}

// Wait ms in steps of 10 ms. False as soon as a siren wants the buzzer.
static bool tune_wait(int ms)
{
    while (ms > 0) {
        if (s_siren_wanted) return false;
        int step = ms < 10 ? ms : 10;
        vTaskDelay(pdMS_TO_TICKS(step));
        ms -= step;
    }
    return !s_siren_wanted;
}

// Caller holds s_lock. Each note sounds for ms, then is silent for the rest
// of its slot; the last note's silence is skipped. A rest (hz 0), or a note
// LEDC refuses, waits out its slot so the rhythm holds. A siren request ends
// the tune within 10 ms. The timer goes back to BOARD_BUZZER_HZ before the
// lock is released.
static void play_melody_locked(const melody_note_t *notes, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        bool last = i + 1 == n;
        int on   = notes[i].ms;
        int slot = notes[i].slot > notes[i].ms ? notes[i].slot : notes[i].ms;
        int rest = last ? 0 : slot - on;
        if (notes[i].hz == 0 ||
            ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, notes[i].hz) != ESP_OK) {
            if (!tune_wait(on + rest)) break;
            continue;
        }
        ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, BUZ_DUTY_ON);
        ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
        bool go = tune_wait(on);
        ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
        ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
        if (!go || !tune_wait(rest)) {
            ESP_LOGI(TAG, "Tune cut at note %u of %u for the siren", (unsigned)(i + 1), (unsigned)n);
            break;
        }
    }
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZ_TIMER, BOARD_BUZZER_HZ);
}

void buzzer_play_melody(const melody_note_t *notes, size_t n)
{
    if (!s_ok || !notes) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    play_melody_locked(notes, n);
    xSemaphoreGive(s_lock);
}

void buzzer_boot(void)
{
    if (!s_ok || !settings_get()->boot_chirp) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    play_melody_locked(MELODY_STARTUP, MELODY_STARTUP_LEN);
    xSemaphoreGive(s_lock);
}

void buzzer_click(void)
{
    if (!s_ok || !settings_get()->touch_click) return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;   // a pattern is playing
    tone(BOARD_BUZZER_HZ, 10, 0);
    xSemaphoreGive(s_lock);
}
