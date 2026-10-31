#include "melody.h"

// Equal temperament, A4 = 440 Hz, rounded to the nearest Hz (LEDC takes whole Hz).
#define B5    988       // 987.77
#define CS6  1109       // 1108.73
#define D6   1175       // 1174.66
#define E6   1319       // 1318.51
#define ES6  1397       // 1396.91, E sharp (sounds as F6)
#define FS6  1480       // 1479.98
#define B6   1976       // 1975.53

// Grieg's march tempo: one note every 260 ms (210 ms sounding plus the
// MELODY_GAP_MS articulation gap, so it stays staccato). 11 x 260 + 700 =
// 3560 ms in all.
#define Q     210       // staccato quarter, sounding part
#define HOLD  700       // final tonic

// B minor. The creep B C# D E F# D F#, the answer E# C# E#, then E# rises to
// F# (dominant) and F# leaps up a fourth to B (tonic), as Grieg's own phrase
// does at the end of the fourth bar. The high B also sits nearer the piezo's
// 2.7 kHz resonance, so the held note carries.
const melody_note_t MELODY_STARTUP[] = {
    { B5,  Q }, { CS6, Q }, { D6,  Q }, { E6,  Q },
    { FS6, Q }, { D6,  Q }, { FS6, Q },
    { ES6, Q }, { CS6, Q }, { ES6, Q },
    { FS6, Q }, { B6,  HOLD },
};

const size_t MELODY_STARTUP_LEN = sizeof(MELODY_STARTUP) / sizeof(MELODY_STARTUP[0]);
