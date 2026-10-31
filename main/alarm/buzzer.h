#pragma once

#include <stddef.h>
#include "melody.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * buzzer_alarm(), buzzer_remind() and buzzer_test() only queue a request and
 * return at once: the siren (about 3.2 s) plays on the buzzer's own task, one
 * request after another, so call them from any task. buzzer_stop() ends the
 * siren that is playing. buzzer_boot() and buzzer_play_melody() block for the
 * whole tune (about 8 s for the startup melody), so run them from a task of
 * their own. A siren requested meanwhile cuts the tune short within 10 ms and
 * plays at once.
 * buzzer_click() is a few milliseconds and never waits: if a siren or tune is
 * playing, the click is skipped. buzzer_confirm() queues a short tone for the
 * buzzer task and returns at once.
 */

void buzzer_init(void);

// Incident opened: the siren, if the alarm sound setting is on.
void buzzer_alarm(void);

// The siren, played even when the alarm sound is switched off.
void buzzer_test(void);

// Unacknowledged-incident reminder: the same siren, if the setting is on.
void buzzer_remind(void);

// Incident acknowledged or cleared: cut the siren short.
void buzzer_stop(void);

// Boot: the startup melody (MELODY_STARTUP), if the boot sound setting is on.
void buzzer_boot(void);

// Touch feedback: a ~10 ms click. Safe from the UI task.
void buzzer_click(void);

// A hold-to-confirm button completed: two short rising pips (~110 ms), queued
// to the buzzer task, so it returns at once. Follows the touch click setting;
// skipped while the boot tune plays or if there is no buzzer task.
void buzzer_confirm(void);

// Play a note table (see melody.h), then put the tone back to BOARD_BUZZER_HZ.
// Blocks for the whole tune.
void buzzer_play_melody(const melody_note_t *notes, size_t n);

#ifdef __cplusplus
}
#endif
