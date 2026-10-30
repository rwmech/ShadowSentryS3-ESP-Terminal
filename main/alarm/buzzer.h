#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * The alarm/remind/boot patterns block for their length (under a second), so
 * call them only from the alarm task, app_main or the admin task (the test
 * from the Settings page). buzzer_click() is a few
 * milliseconds and never waits: if a pattern is playing, the click is skipped.
 */

void buzzer_init(void);

// Incident opened: three short beeps (~0.7 s).
void buzzer_alarm(void);

// The alarm pattern, played even when the alarm sound is switched off.
void buzzer_test(void);

// Unacknowledged-incident reminder: one short beep.
void buzzer_remind(void);

// Boot: a short rising two-tone chirp.
void buzzer_boot(void);

// Touch feedback: a ~10 ms click. Safe from the UI task.
void buzzer_click(void);

#ifdef __cplusplus
}
#endif
