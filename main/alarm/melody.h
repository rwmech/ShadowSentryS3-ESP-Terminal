#pragma once

/*
 * Note tables for the buzzer. Data only: buzzer_play_melody() plays them.
 */

#include <stddef.h>
#include <stdint.h>

// Silence after every note but the last, so repeated pitches articulate.
#define MELODY_GAP_MS   50

typedef struct {
    uint16_t hz;    // tone frequency, 0 for a rest
    uint16_t ms;    // how long the tone sounds (or the rest lasts)
} melody_note_t;

#ifdef __cplusplus
extern "C" {
#endif

// Boot sound: the opening of Grieg's "In the Hall of the Mountain King"
// (1875, public domain), two octaves up, closing on the tonic. About 3.6 s.
extern const melody_note_t MELODY_STARTUP[];
extern const size_t        MELODY_STARTUP_LEN;

#ifdef __cplusplus
}
#endif
