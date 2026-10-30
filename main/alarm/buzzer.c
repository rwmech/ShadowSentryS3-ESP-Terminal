#include "buzzer.h"
#include "board.h"
#include "settings.h"
#include "driver/ledc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"

static const char *TAG = "BUZZER";

// LEDC timer/channel 1; timer/channel 0 drive the backlight.
#define BUZ_TIMER    LEDC_TIMER_1
#define BUZ_CHANNEL  LEDC_CHANNEL_1
#define BUZ_DUTY_ON  512            // 50 % of 10-bit: loudest for a passive piezo

static bool              s_ok = false;
static SemaphoreHandle_t s_lock;    // alarm task and UI task share the buzzer

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
    s_ok = true;
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

void buzzer_alarm(void)
{
    if (!s_ok || !settings_get()->alarm_sound) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < 3; i++) tone(BOARD_BUZZER_HZ, 150, 100);
    xSemaphoreGive(s_lock);
}

void buzzer_test(void)
{
    if (!s_ok) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < 3; i++) tone(BOARD_BUZZER_HZ, 150, 100);
    xSemaphoreGive(s_lock);
}

void buzzer_remind(void)
{
    if (!s_ok || !settings_get()->alarm_sound) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    tone(BOARD_BUZZER_HZ, 200, 0);
    xSemaphoreGive(s_lock);
}

void buzzer_boot(void)
{
    if (!s_ok || !settings_get()->boot_chirp) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    tone(2000, 60, 30);
    tone(BOARD_BUZZER_HZ, 80, 0);
    xSemaphoreGive(s_lock);
}

void buzzer_click(void)
{
    if (!s_ok || !settings_get()->touch_click) return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;   // a pattern is playing
    tone(BOARD_BUZZER_HZ, 10, 0);
    xSemaphoreGive(s_lock);
}
