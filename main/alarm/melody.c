#include "melody.h"

// Equal temperament, A4 = 440 Hz, rounded to the nearest Hz (LEDC takes whole Hz).
#define B5    988       // 987.77
#define CS6  1109       // 1108.73
#define D6   1175       // 1174.66
#define E6   1319       // 1318.51
#define ES6  1397       // 1396.91, E sharp (sounds as F6)
#define FS6  1480       // 1479.98
#define B6   1976       // 1975.53

// Source: Grieg's own piano arrangement, Peer Gynt Suite No. 1, Op. 46 No. 4,
// The University Society, New York, 1918 (scan on IMSLP), as engraved by the
// Mutopia Project, piece 1888:
//   https://www.mutopiaproject.org/cgibin/piece-info.cgi?id=1888
//   https://www.mutopiaproject.org/ftp/GriegE/O46/Dans_l_antre_du_roi_de_la_montagne/Dans_l_antre_du_roi_de_la_montagne.ly
// Marking: "Alla marcia molto marcato", crotchet = 138, 4/4, B minor. After a
// held F# (bar 1) the theme enters pp, "e sempre staccato", every note dotted:
//   bar 2: B C# D E F# D (quavers), F# (crotchet)
//   bar 3: E# C# (quavers), E# (crotchet); then E C E, which we leave out
// The score has it at B1, in the bass; we play it four octaves up, where the
// piezo is loud.
//
// At crotchet = 138 a crotchet is 434.8 ms and a quaver 217.4 ms. Pizzicato and
// staccato as written: every note sounds 110 ms, about half a quaver, and the
// rest of its value is silence. Our cadence, after the first ten notes, keeps
// the tempo: F# as a quaver, then B as a held minim, as the theme's own fourth
// bar runs quavers into a minim.
//   2 crotchets + 9 quavers + 1 minim = 2 x 435 + 9 x 217 + 870 = 3693 ms
#define BPM     138
#define CROTCHET ((60000 + BPM / 2) / BPM)      // 435 ms
#define QUAVER   (60000 / (2 * BPM))            // 217 ms
#define MINIM    (2 * CROTCHET)                 // 870 ms
#define STACC    110                            // sounding part of a staccato note

const melody_note_t MELODY_STARTUP[] = {
    { B5,  STACC, QUAVER }, { CS6, STACC, QUAVER }, { D6,  STACC, QUAVER },
    { E6,  STACC, QUAVER }, { FS6, STACC, QUAVER }, { D6,  STACC, QUAVER },
    { FS6, STACC, CROTCHET },
    { ES6, STACC, QUAVER }, { CS6, STACC, QUAVER }, { ES6, STACC, CROTCHET },
    { FS6, STACC, QUAVER }, { B6,  MINIM, MINIM },  // cadence: dominant, then the held tonic
};

const size_t MELODY_STARTUP_LEN = sizeof(MELODY_STARTUP) / sizeof(MELODY_STARTUP[0]);
