#pragma once

/*
 * Note tables for the buzzer. Data only: buzzer_play_melody() plays them.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t hz;    // tone frequency, 0 for a rest
    uint16_t ms;    // how long the tone sounds
    uint16_t slot;  // the note's written value: the tone, then silence to fill it.
                    // Below ms counts as ms. The last note's trailing silence is skipped.
} melody_note_t;

#ifdef __cplusplus
extern "C" {
#endif

// Boot sound: the opening of Grieg's "In the Hall of the Mountain King"
// (1875, public domain), at the score's tempo, closing on the tonic. About 3.7 s.
extern const melody_note_t MELODY_STARTUP[];
extern const size_t        MELODY_STARTUP_LEN;

#ifdef __cplusplus
}
#endif
