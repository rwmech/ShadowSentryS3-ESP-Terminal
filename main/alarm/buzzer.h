#pragma once

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * The play functions block for the length of the pattern (under a second), so
 * call them only from the alarm task, never from a honeypot or httpd task.
 */

#include <stddef.h>
#include "melody.h"

void buzzer_init(void);

// Incident opened: three short beeps (~0.7 s).
void buzzer_alarm(void);

// Unacknowledged-incident reminder: one short beep.
void buzzer_remind(void);

// Play a note table (see melody.h), then put the tone back to BOARD_BUZZER_HZ.
// Blocks for the whole tune, so run it from a task of its own at boot.
void buzzer_play_melody(const melody_note_t *notes, size_t n);
