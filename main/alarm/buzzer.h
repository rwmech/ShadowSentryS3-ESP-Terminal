#pragma once

#include <stddef.h>
#include "melody.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * The alarm/remind patterns block for their length (under a second), so call
 * them only from the alarm task or the admin task (the test from the Settings
 * page). buzzer_boot() and buzzer_play_melody() block for the whole tune
 * (about 1.8 s for the startup melody), so run them from a task of their own.
 * buzzer_click() is a few milliseconds and never waits: if a pattern or tune
 * is playing, the click is skipped.
 */

void buzzer_init(void);

// Incident opened: three short beeps (~0.7 s).
void buzzer_alarm(void);

// The alarm pattern, played even when the alarm sound is switched off.
void buzzer_test(void);

// Unacknowledged-incident reminder: one short beep.
void buzzer_remind(void);

// Boot: the startup melody (MELODY_STARTUP), if the boot sound setting is on.
void buzzer_boot(void);

// Touch feedback: a ~10 ms click. Safe from the UI task.
void buzzer_click(void);

// Play a note table (see melody.h), then put the tone back to BOARD_BUZZER_HZ.
// Blocks for the whole tune.
void buzzer_play_melody(const melody_note_t *notes, size_t n);

#ifdef __cplusplus
}
#endif
