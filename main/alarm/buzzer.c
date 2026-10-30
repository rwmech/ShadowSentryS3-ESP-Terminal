#include "buzzer.h"
#include "board.h"
#include "driver/ledc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

static const char *TAG = "BUZZER";

// LEDC timer/channel 1; timer/channel 0 are left free for the backlight.
#define BUZ_TIMER    LEDC_TIMER_1
#define BUZ_CHANNEL  LEDC_CHANNEL_1
#define BUZ_DUTY_ON  512            // 50 % of 10-bit: loudest for a passive piezo

static bool s_ok = false;

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
        ESP_LOGE(TAG, "LEDC setup failed — buzzer disabled");
        return;
    }
    s_ok = true;
}

static void tone(int on_ms, int off_ms)
{
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, BUZ_DUTY_ON);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    vTaskDelay(pdMS_TO_TICKS(on_ms));
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL, 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZ_CHANNEL);
    if (off_ms) vTaskDelay(pdMS_TO_TICKS(off_ms));
}

void buzzer_alarm(void)
{
    if (!s_ok) return;
    for (int i = 0; i < 3; i++) tone(150, 100);
}

void buzzer_remind(void)
{
    if (!s_ok) return;
    tone(200, 0);
}
