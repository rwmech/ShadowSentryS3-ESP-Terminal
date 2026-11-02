#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Passive buzzer on BOARD_BUZZER, driven with an LEDC tone.
 *
 * buzzer_alarm(), buzzer_remind() and buzzer_test() only queue a request and
 * return at once: the red alert klaxon (about 3.3 s) plays on the buzzer's own
 * task, one request after another, so call them from any task. buzzer_stop()
 * ends the klaxon that is playing.
 * buzzer_boot(), buzzer_click(), buzzer_chirp() and buzzer_yellow() queue a
 * short sound for the buzzer task and return at once; with no buzzer task they
 * are skipped.
 * Loudness is the LEDC duty: the ui_volume setting for the chirps and the boot
 * beeps (0 is off), alarm_volume for the klaxon and the yellow call.
 */

void buzzer_init(void);

// Red incident opened: the klaxon, if the alarm sound setting is on.
void buzzer_alarm(void);

// The klaxon, played even when the alarm sound is switched off.
void buzzer_test(void);

// Unacknowledged red incident reminder: the same klaxon, if the setting is on.
void buzzer_remind(void);

// Incident acknowledged or cleared: cut the klaxon short.
void buzzer_stop(void);

// YELLOW incident opened (SEV2 events only): one soft two-note attention call
// (about 290 ms), never the klaxon, if the alarm sound setting is on. No
// reminders. Queued to the buzzer task; skipped if there is no buzzer task or
// the boot tune or the klaxon is playing.
void buzzer_yellow(void);

// Boot: a few short beeps (under 0.3 s), if the boot sound setting is on and
// the UI volume is not off.
void buzzer_boot(void);

// Console sounds: short chirps near the piezo's resonance, at the UI volume.
// They follow the touch click setting and are skipped while the klaxon plays.
typedef enum {
    BUZZER_CHIRP_TAP,       // any press: rising, 2600 then 3200 Hz, 36 ms
    BUZZER_CHIRP_CONFIRM,   // a dialog confirmed: rising three notes, 65 ms
    BUZZER_CHIRP_CANCEL,    // cancelled or refused: falling two notes, 60 ms
    BUZZER_CHIRP_ACK,       // a hold completed: two tones, 210 ms
    BUZZER_CHIRP_COUNT
} buzzer_chirp_t;
void buzzer_chirp(buzzer_chirp_t kind);

// Touch feedback on every press: BUZZER_CHIRP_TAP. Safe from the UI task.
void buzzer_click(void);

#ifdef __cplusplus
}
#endif
