#include "melody.h"

// Equal temperament, A4 = 440 Hz, rounded to the nearest Hz (LEDC takes whole Hz).
// The range, 988 to 1976 Hz, sits inside what the piezo plays well.
#define B5    988       // 987.77
#define C6   1047       // 1046.50
#define CS6  1109       // 1108.73
#define D6   1175       // 1174.66
#define E6   1319       // 1318.51
#define ES6  1397       // 1396.91, E sharp (sounds as F6)
#define FS6  1480       // 1479.98
#define A6   1760       // 1760.00
#define B6   1976       // 1975.53

// Source: Grieg's own piano arrangement, Peer Gynt Suite No. 1, Op. 46 No. 4,
// The University Society, New York, 1918 (scan on IMSLP), as engraved by the
// Mutopia Project, piece 1888:
//   https://www.mutopiaproject.org/cgibin/piece-info.cgi?id=1888
//   https://www.mutopiaproject.org/ftp/GriegE/O46/Dans_l_antre_du_roi_de_la_montagne/Dans_l_antre_du_roi_de_la_montagne.ly
// Marking: "Alla marcia molto marcato", crotchet = 138, 4/4, B minor. After a
// held F# (bar 1) the theme enters pp, "e sempre staccato", every note dotted
// but the closing minim. Its first statement, bars 2 to 5:
//   bar 2: B C# D E F# D (quavers), F# (crotchet)
//   bar 3: E# C# (quavers), E# (crotchet), E C (quavers), E (crotchet)
//   bar 4: B C# D E F# D F# B (quavers, the last B an octave up)
//   bar 5: A F# D F# (quavers), A (minim, accented, held)
// Bar 6 repeats it an octave higher, and bar 10 moves it to F# major, so the
// tune stops at bar 5. The score has it at B1, in the bass; we play it four
// octaves up, where the piezo is loud.
//
// The phrase ends open, on the held A. We add a short close in the same tempo
// to land on the tonic: F# as a quaver, then B held a minim.
//
// At crotchet = 138 a crotchet is 434.8 ms and a quaver 217.4 ms. Pizzicato and
// staccato as written: every dotted note sounds 110 ms, about half a quaver,
// and the rest of its value is silence. The held A sounds 820 of its 870 ms.
//   4 bars of 4 crotchets + close (217 + 870) = 1737 + 1738 + 1736 + 1738 + 1087 = 8036 ms
#define BPM     138
#define CROTCHET ((60000 + BPM / 2) / BPM)      // 435 ms
#define QUAVER   (60000 / (2 * BPM))            // 217 ms
#define MINIM    (2 * CROTCHET)                 // 870 ms
#define STACC    110                            // sounding part of a staccato note
#define HELD     (MINIM - 50)                   // a written held minim, then a breath

#define Q(n)  { n, STACC, QUAVER }
#define C(n)  { n, STACC, CROTCHET }

const melody_note_t MELODY_STARTUP[] = {
    Q(B5), Q(CS6), Q(D6), Q(E6), Q(FS6), Q(D6), C(FS6),            // bar 2
    Q(ES6), Q(CS6), C(ES6), Q(E6), Q(C6), C(E6),                    // bar 3
    Q(B5), Q(CS6), Q(D6), Q(E6), Q(FS6), Q(D6), Q(FS6), Q(B6),     // bar 4
    Q(A6), Q(FS6), Q(D6), Q(FS6), { A6, HELD, MINIM },             // bar 5
    Q(FS6), { B6, MINIM, MINIM },                                   // our close on the tonic
};

const size_t MELODY_STARTUP_LEN = sizeof(MELODY_STARTUP) / sizeof(MELODY_STARTUP[0]);
