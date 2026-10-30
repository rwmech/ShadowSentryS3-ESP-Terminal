#pragma once

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * The play functions block for the length of the pattern (under a second), so
 * call them only from the alarm task, never from a honeypot or httpd task.
 */

void buzzer_init(void);

// Incident opened: three short beeps (~0.7 s).
void buzzer_alarm(void);

// Unacknowledged-incident reminder: one short beep.
void buzzer_remind(void);
