#include "json_esc.h"
#include <stdio.h>
#include <string.h>

// Length of the well-formed UTF-8 sequence at s (n bytes available), 0 if
// there is none there (RFC 3629, table 3-7 of the Unicode standard).
static size_t utf8_len(const unsigned char *s, size_t n)
{
    unsigned c = s[0];
    if (c < 0x80) return 1;
    unsigned lo = 0x80, hi = 0xBF;
    size_t len;
    if      (c >= 0xC2 && c <= 0xDF) len = 2;
    else if (c == 0xE0)              { len = 3; lo = 0xA0; }
    else if (c >= 0xE1 && c <= 0xEC) len = 3;
    else if (c == 0xED)              { len = 3; hi = 0x9F; }    // no surrogates
    else if (c >= 0xEE && c <= 0xEF) len = 3;
    else if (c == 0xF0)              { len = 4; lo = 0x90; }
    else if (c >= 0xF1 && c <= 0xF3) len = 4;
    else if (c == 0xF4)              { len = 4; hi = 0x8F; }    // at most U+10FFFF
    else return 0;
    if (n < len) return 0;
    if (s[1] < lo || s[1] > hi) return 0;
    for (size_t k = 2; k < len; k++) if (s[k] < 0x80 || s[k] > 0xBF) return 0;
    return len;
}

size_t json_esc(const char *in, size_t in_max, char *out, size_t cap)
{
    if (!out || !cap) return 0;
    size_t o = 0, i = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (in && i < in_max && s[i]) {
        unsigned c = s[i];
        char t[8];
        size_t tn = 1, adv = 1;
        if (c == '"' || c == '\\')  { t[0] = '\\'; t[1] = (char)c; tn = 2; }
        else if (c == '\n')         { t[0] = '\\'; t[1] = 'n'; tn = 2; }
        else if (c == '\r')         { t[0] = '\\'; t[1] = 'r'; tn = 2; }
        else if (c == '\t')         { t[0] = '\\'; t[1] = 't'; tn = 2; }
        else if (c < 0x20 || c == 0x7f) tn = (size_t)snprintf(t, sizeof(t), "\\u%04x", c);
        else if (c < 0x80)          t[0] = (char)c;
        else {
            size_t avail = in_max - i, L;
            for (L = 0; L < 4 && L < avail && s[i + L]; L++) {}  // bytes before a NUL
            L = utf8_len(s + i, L);
            if (L) { memcpy(t, s + i, L); tn = adv = L; }
            else   { t[0] = (char)0xEF; t[1] = (char)0xBF; t[2] = (char)0xBD; tn = 3; }   // U+FFFD
        }
        if (o + tn + 1 > cap) break;            // whole characters and escapes only
        memcpy(out + o, t, tn);
        o += tn;
        i += adv;
    }
    out[o] = '\0';
    return o;
}

void utf8_sanitize(char *p, size_t n)
{
    unsigned char *s = (unsigned char *)p;
    size_t i = 0;
    while (i < n) {
        size_t L = s[i] < 0x80 ? 1 : utf8_len(s + i, n - i);
        if (L) i += L;
        else   s[i++] = '?';
    }
}
