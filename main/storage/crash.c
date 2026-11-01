// Crash capture: a panic record in RTC memory, written by a wrapper around
// esp_panic_handler(), and turned into a report on the next boot. See crash.h.
// Fork addition, Robert Mech.
//
// Panic side (everything marked IRAM_ATTR): runs with the other core stalled
// and interrupts off, maybe on a corrupt heap or a blown stack. It only reads
// the exception frame, the stack it walks (each step checked the way IDF's own
// backtrace printer checks it), the TCBs of the running tasks and the heap
// counters (plain reads, no lock in IDF 5.4's heap_caps_get_free_size), and
// writes a DRAM staging copy that is then copied word by word into RTC memory
// with a CRC. No allocation, no lock, no flash, no filesystem, no libc string
// call. A second fault inside the hook re-enters the wrapper, which seals what
// was copied so far (flag "nested") and goes straight to the IDF handler.
//
// Boot side (crash_init(), app_main, before the tasks): SPIFFS writes, then a
// short task with a PSRAM stack that only queues to sd_log's writer.

#include "crash.h"
#include "json_esc.h"
#include "notify.h"
#include "sd_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"
#include "esp_rom_crc.h"
#include "esp_debug_helpers.h"
#include "esp_memory_utils.h"
#include "esp_cpu_utils.h"
#include "esp_private/panic_internal.h"
#include "xtensa_context.h"
#include "xtensa/corebits.h"
#include "soc/soc.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "CRASH";

// ── Record (RTC memory) ───────────────────────────────────────────────────────

#define CRASH_MAGIC     0x48535243u     // "CRSH"
#define CRASH_VERSION   1
#define CLOCK_VALID     1704067200      // 2024-01-01: anything earlier is "not set"
#define CLOCK_SAMPLE_US (30 * 1000000LL)

#define CF_NESTED       0x01            // a second fault hit inside the hook
#define CF_BT_CORRUPT   0x02            // the stack walk stopped at a bad frame
#define CF_BT_MORE      0x04            // the stack goes on past CRASH_BT_MAX
#define CF_ABORT        0x08            // abort() or assert, reason is its text

typedef struct {
    uint32_t magic;
    uint16_t version, size;
    uint8_t  exc;                       // panic_exception_t
    uint8_t  core;
    uint8_t  pseudo;                    // exccause holds a PANIC_RSN_* value
    uint8_t  flags;                     // CF_*
    uint8_t  bt_n;
    uint8_t  _pad[3];
    uint32_t pc, exccause, excvaddr, ps, a0, sp;
    uint32_t bt[CRASH_BT_MAX];
    uint32_t epoch;                     // wall clock at the crash, 0 not set
    uint32_t up_lo, up_hi;              // esp_timer microseconds
    uint32_t heap_int, heap_total, heap_int_min;
    char     reason[96];                // info->reason, or the abort/assert text
    char     task[2][16];               // running task per core
    char     ver[32];                   // esp_app_desc version
    char     elf[20];                   // ELF SHA256, first 16 hex digits
    uint32_t crc;                       // CRC-32 of everything above
} crash_rec_t;

_Static_assert(sizeof(crash_rec_t) % 4 == 0, "crash_rec_t: word copies");
#define REC_WORDS (sizeof(crash_rec_t) / 4)

// IDF's panic state (esp_system/panic.c); task_wdt.c declares them the same way.
extern bool  g_panic_abort;
extern char *g_panic_abort_details;

void __real_esp_panic_handler(panic_info_t *info);

static RTC_NOINIT_ATTR uint32_t s_rtc[REC_WORDS];   // survives the panic reset
static DRAM_ATTR crash_rec_t    s_stage;            // built here, then copied
static DRAM_ATTR volatile uint32_t s_hook_state;    // 0 idle, 1 copying, 2 sealed

// Panic-time inputs, set in normal context.
static DRAM_ATTR char              s_ver[32];
static DRAM_ATTR char              s_elf[20];
static DRAM_ATTR volatile uint32_t s_clock_epoch;   // time(NULL) at the last sample
static DRAM_ATTR volatile int64_t  s_clock_up;      // esp_timer at that sample, 0 none

// ── Panic side ────────────────────────────────────────────────────────────────

// Data addresses a read can't fault on in practice: internal DRAM, and the
// cached flash/PSRAM data window (SOC_DROM and SOC_EXTRAM_DATA are the same
// range on the S3).
static inline bool IRAM_ATTR readable(const void *p)
{
    uintptr_t a = (uintptr_t)p;
    return (a >= SOC_DRAM_LOW && a < SOC_DRAM_HIGH) ||
           (a >= SOC_EXTRAM_DATA_LOW && a < SOC_EXTRAM_DATA_HIGH);
}

// Printable ASCII only, bounded, every byte's address checked.
static void IRAM_ATTR copy_str(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    if (src) {
        for (; i + 1 < cap && readable(src + i) && src[i]; i++) {
            char c = src[i];
            dst[i] = (c >= 0x20 && c < 0x7f) ? c : ' ';
        }
    }
    for (size_t k = i; k < cap; k++) dst[k] = '\0';
}

static void IRAM_ATTR seal(void)
{
    s_stage.magic   = CRASH_MAGIC;
    s_stage.version = CRASH_VERSION;
    s_stage.size    = sizeof(crash_rec_t);
    s_stage.crc     = esp_rom_crc32_le(0, (const uint8_t *)&s_stage, offsetof(crash_rec_t, crc));
    const volatile uint32_t *src = (const volatile uint32_t *)&s_stage;
    for (size_t i = 0; i < REC_WORDS; i++) s_rtc[i] = src[i];
}

static void IRAM_ATTR capture(const panic_info_t *info)
{
    volatile uint32_t *w = (volatile uint32_t *)&s_stage;
    for (size_t i = 0; i < REC_WORDS; i++) w[i] = 0;
    s_rtc[0] = 0;                           // the old record is gone from here on

    crash_rec_t *r = &s_stage;
    r->exc    = (uint8_t)info->exception;
    r->core   = (uint8_t)info->core;
    r->pseudo = info->pseudo_excause ? 1 : 0;
    if (g_panic_abort) {                    // esp_panic_handler() overrides this itself
        r->exc    = PANIC_EXCEPTION_ABORT;
        r->flags |= CF_ABORT;
        copy_str(r->reason, sizeof(r->reason), g_panic_abort_details);
    } else {
        copy_str(r->reason, sizeof(r->reason), info->reason);
    }
    copy_str(r->ver, sizeof(r->ver), s_ver);
    copy_str(r->elf, sizeof(r->elf), s_elf);

    int64_t up = esp_timer_get_time();
    r->up_lo = (uint32_t)up;
    r->up_hi = (uint32_t)((uint64_t)up >> 32);
    int64_t ref = s_clock_up;
    // Unsigned 64-bit division: libgcc's __udivdi3, in the S3's ROM.
    if (ref > 0 && up >= ref) r->epoch = s_clock_epoch + (uint32_t)((uint64_t)(up - ref) / 1000000u);

    const XtExcFrame *f = (const XtExcFrame *)info->frame;
    if (f && readable(f)) {
        r->pc       = (uint32_t)f->pc;
        r->exccause = (uint32_t)f->exccause;
        r->excvaddr = (uint32_t)f->excvaddr;
        r->ps       = (uint32_t)f->ps;
        r->a0       = (uint32_t)f->a0;
        r->sp       = (uint32_t)f->a1;

        // The walk of esp_backtrace_print_from_frame(), PCs only.
        esp_backtrace_frame_t bf = { .pc = f->pc, .sp = f->a1, .next_pc = f->a0, .exc_frame = f };
        uint32_t n = 0;
        r->bt[n++] = esp_cpu_process_stack_pc(bf.pc);
        bool bad = !(esp_stack_ptr_is_sane(bf.sp) &&
                     (esp_ptr_executable((void *)esp_cpu_process_stack_pc(bf.pc)) ||
                      f->exccause == EXCCAUSE_INSTR_PROHIBITED));
        while (n < CRASH_BT_MAX && bf.next_pc != 0 && !bad) {
            if (!esp_backtrace_get_next_frame(&bf)) bad = true;
            r->bt[n++] = esp_cpu_process_stack_pc(bf.pc);
        }
        r->bt_n = (uint8_t)n;
        if (bad) r->flags |= CF_BT_CORRUPT;
        else if (bf.next_pc != 0) r->flags |= CF_BT_MORE;
    }

    for (int c = 0; c < portNUM_PROCESSORS && c < 2; c++) {
        TaskHandle_t h = xTaskGetCurrentTaskHandleForCore(c);
        if (h && readable(h)) copy_str(r->task[c], sizeof(r->task[c]), pcTaskGetName(h));
    }
    seal();                                 // the essentials are safe now

    // Last, as the likeliest to meet corruption: heap_t list and TLSF headers.
    r->heap_int     = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    r->heap_total   = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    r->heap_int_min = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    seal();
}

// Linked in place of esp_panic_handler() (port/panic_handler.c's only call).
void IRAM_ATTR __wrap_esp_panic_handler(panic_info_t *info)
{
    if (s_hook_state == 0) {
        s_hook_state = 1;
        if (info) capture(info);
        s_hook_state = 2;
    } else if (s_hook_state == 1) {
        // A fault inside capture(): keep what was copied, then hand over.
        s_stage.flags |= CF_NESTED;
        seal();
        s_hook_state = 2;
    }
    __real_esp_panic_handler(info);
}

void crash_debug_abort(void)
{
    ESP_LOGE(TAG, "Deliberate abort() from POST /api/debug/crash");
    abort();
}

// ── Clock sample (esp_timer task) ─────────────────────────────────────────────

static void clock_sample(void *arg)
{
    (void)arg;
    time_t now = time(NULL);
    if (now < CLOCK_VALID) return;
    s_clock_up    = 0;                      // the hook ignores a half-written pair
    s_clock_epoch = (uint32_t)now;
    s_clock_up    = esp_timer_get_time();
}

// ── Boot side: state served to the API ───────────────────────────────────────

static char           *s_log;               // crash.log, oldest first, '\n' after each
static size_t          s_log_len;
static char           *s_report;            // newest full report
static size_t          s_report_len;
static crash_summary_t s_last;

const char *crash_log_text(size_t *len)    { *len = s_log ? s_log_len : 0; return s_log ? s_log : ""; }
const char *crash_report_text(size_t *len) { *len = s_report ? s_report_len : 0; return s_report ? s_report : ""; }

bool crash_last(crash_summary_t *out)
{
    *out = s_last;
    return s_last.valid;
}

// ── Formatting ────────────────────────────────────────────────────────────────

static bool rec_valid(const crash_rec_t *r)
{
    return r->magic == CRASH_MAGIC && r->version == CRASH_VERSION && r->size == sizeof(*r) &&
           r->crc == esp_rom_crc32_le(0, (const uint8_t *)r, offsetof(crash_rec_t, crc)) &&
           r->bt_n <= CRASH_BT_MAX && r->core < 2;
}

static const char *exc_name(uint8_t e)
{
    switch (e) {
    case PANIC_EXCEPTION_DEBUG: return "debug";
    case PANIC_EXCEPTION_IWDT:  return "interrupt watchdog";
    case PANIC_EXCEPTION_TWDT:  return "task watchdog";
    case PANIC_EXCEPTION_ABORT: return "abort";
    case PANIC_EXCEPTION_FAULT: return "fault";
    default:                    return "unknown";
    }
}

// Short cause: the exception name for a fault, the kind of abort, the watchdog.
static void cause_of(const crash_rec_t *r, char *out, size_t n)
{
    switch (r->exc) {
    case PANIC_EXCEPTION_IWDT: strlcpy(out, "Interrupt watchdog", n); return;
    case PANIC_EXCEPTION_TWDT: strlcpy(out, "Task watchdog", n); return;
    case PANIC_EXCEPTION_ABORT:
        if (strstr(r->reason, "assert failed"))        strlcpy(out, "assert", n);
        else if (strstr(r->reason, "stack overflow"))  strlcpy(out, "stack overflow", n);
        else                                           strlcpy(out, "abort", n);
        return;
    default:
        if (strstr(r->reason, "Stack canary") || strstr(r->reason, "Stack protection"))
            strlcpy(out, "stack overflow", n);
        else
            strlcpy(out, r->reason[0] ? r->reason : exc_name(r->exc), n);
        return;
    }
}

static void fmt_time(uint32_t ts, char *out, size_t n)
{
    if (ts < CLOCK_VALID) { strlcpy(out, "unknown (clock not set)", n); return; }
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%d %H:%M:%S %Z", &tm);
}

static size_t fmt_bt(const crash_rec_t *r, char *out, size_t n)
{
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < r->bt_n && o + 12 < n; i++)
        o += (size_t)snprintf(out + o, n - o, "%s0x%08lx", i ? " " : "", (unsigned long)r->bt[i]);
    return o;
}

// Appends one JSON string, escaped by json_esc(), to out at *o.
static void put_str(char *out, size_t cap, size_t *o, const char *key, const char *s)
{
    char esc[256];
    json_esc(s, (size_t)-1, esc, sizeof(esc));
    int k = snprintf(out + *o, cap - *o, ",\"%s\":\"%s\"", key, esc);
    if (k > 0 && (size_t)k < cap - *o) *o += (size_t)k;
}

// The one-line summary for crash.log (no newline). rec NULL: reset reason only.
static size_t fmt_summary(char *out, size_t cap, const crash_rec_t *rec, esp_reset_reason_t rr,
                          uint32_t boot_ts, const char *cause)
{
    size_t o = 0;
    int k = snprintf(out, cap, "{\"ts\":%lu,\"boot_ts\":%lu,\"record\":%s",
                     (unsigned long)(rec ? rec->epoch : 0), (unsigned long)boot_ts, rec ? "true" : "false");
    if (k <= 0 || (size_t)k >= cap) return 0;
    o = (size_t)k;
    put_str(out, cap, &o, "reset", notify_reset_reason_str(rr));
    put_str(out, cap, &o, "cause", cause);
    if (rec) {
        char bt[CRASH_BT_MAX * 11 + 1];
        fmt_bt(rec, bt, sizeof(bt));
        uint64_t up = ((uint64_t)rec->up_hi << 32) | rec->up_lo;
        put_str(out, cap, &o, "detail", rec->reason);
        put_str(out, cap, &o, "exc", exc_name(rec->exc));
        put_str(out, cap, &o, "task", rec->task[rec->core]);
        put_str(out, cap, &o, "task0", rec->task[0]);
        put_str(out, cap, &o, "task1", rec->task[1]);
        put_str(out, cap, &o, "fw", rec->ver);
        put_str(out, cap, &o, "elf", rec->elf);
        k = snprintf(out + o, cap - o,
                     ",\"core\":%u,\"up_s\":%llu,\"pc\":\"0x%08lx\",\"excvaddr\":\"0x%08lx\","
                     "\"bt\":\"%s\",\"bt_corrupt\":%s,\"bt_more\":%s,\"nested\":%s,"
                     "\"heap_int\":%lu,\"heap_total\":%lu,\"heap_int_min\":%lu}",
                     rec->core, (unsigned long long)(up / 1000000), (unsigned long)rec->pc,
                     (unsigned long)rec->excvaddr, bt,
                     (rec->flags & CF_BT_CORRUPT) ? "true" : "false",
                     (rec->flags & CF_BT_MORE) ? "true" : "false",
                     (rec->flags & CF_NESTED) ? "true" : "false",
                     (unsigned long)rec->heap_int, (unsigned long)rec->heap_total,
                     (unsigned long)rec->heap_int_min);
    } else {
        const esp_app_desc_t *app = esp_app_get_description();
        put_str(out, cap, &o, "fw", app->version);
        put_str(out, cap, &o, "elf", s_elf);
        k = snprintf(out + o, cap - o, "}");
    }
    if (k <= 0 || (size_t)k >= cap - o) return 0;
    return o + (size_t)k;
}

static size_t fmt_report(char *out, size_t cap, const crash_rec_t *rec, esp_reset_reason_t rr,
                         uint32_t boot_ts, const char *cause)
{
    char t[48], bt[CRASH_BT_MAX * 11 + 1];
    size_t o = 0;
#define RP(...) do { int _k = snprintf(out + o, cap - o, __VA_ARGS__); \
                     if (_k > 0) o = ((size_t)_k < cap - o) ? o + (size_t)_k : cap - 1; } while (0)
    fmt_time(boot_ts, t, sizeof(t));
    RP("ShadowSentry S3 crash report\n");
    RP("Reported: %s, %llu s after the reset\n", t, (unsigned long long)(esp_timer_get_time() / 1000000));
    RP("Reset reason: %s (code %d)\n", notify_reset_reason_str(rr), (int)rr);
    if (!rec) {
        const esp_app_desc_t *app = esp_app_get_description();
        RP("Firmware now: %s, ELF SHA256 %s\n", app->version, s_elf);
        RP("No valid panic record in RTC memory: the reset came from outside the panic\n"
           "handler (a hardware watchdog, or the handler itself hung), so only the reset\n"
           "reason is known.\n");
        return o;
    }
    uint64_t up = ((uint64_t)rec->up_hi << 32) | rec->up_lo;
    RP("Firmware: %s, ELF SHA256 %s\n", rec->ver, rec->elf);
    RP("Cause: %s\n", cause);
    RP("Detail: %s\n", rec->reason[0] ? rec->reason : "-");
    RP("Exception: %s on core %u, EXCCAUSE %lu%s, EXCVADDR 0x%08lx, PS 0x%08lx\n",
       exc_name(rec->exc), rec->core, (unsigned long)rec->exccause,
       rec->pseudo ? " (panic reason code)" : "", (unsigned long)rec->excvaddr, (unsigned long)rec->ps);
    RP("Task: %s (core 0), %s (core 1)\n", rec->task[0][0] ? rec->task[0] : "?",
       rec->task[1][0] ? rec->task[1] : "?");
    RP("PC: 0x%08lx\n", (unsigned long)rec->pc);
    RP("A0: 0x%08lx, SP: 0x%08lx\n", (unsigned long)rec->a0, (unsigned long)rec->sp);
    fmt_bt(rec, bt, sizeof(bt));
    RP("Backtrace: %s%s\n", bt, (rec->flags & CF_BT_CORRUPT) ? " |<-CORRUPTED" :
                               (rec->flags & CF_BT_MORE) ? " |<-CONTINUES" : "");
    fmt_time(rec->epoch, t, sizeof(t));
    RP("Time of crash: %s\n", t);
    RP("Uptime at crash: %llu.%03u s\n", (unsigned long long)(up / 1000000),
       (unsigned)((up / 1000) % 1000));
    RP("Heap at crash: internal %lu B free (minimum since boot %lu B), total %lu B free\n",
       (unsigned long)rec->heap_int, (unsigned long)rec->heap_int_min, (unsigned long)rec->heap_total);
    if (rec->flags & CF_NESTED)
        RP("Note: a second fault hit while the record was written; later fields may be missing.\n");
    RP("Decode: python tools\\decode_crash.py <this file> <firmware.elf of build %s>\n", rec->ver);
#undef RP
    return o;
}

// ── Boot side: SPIFFS ─────────────────────────────────────────────────────────

static bool write_atomic(const char *path, const char *data, size_t len)
{
    char tmp[40];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return false;
    bool ok = fwrite(data, 1, len, f) == len;
    ok = (fclose(f) == 0) && ok;
    if (ok) { remove(path); ok = rename(tmp, path) == 0; }
    else remove(tmp);
    return ok;
}

static size_t read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

// A line this module wrote: {...}, printable ASCII or UTF-8 (json_esc output).
static bool line_ok(const char *p, size_t n)
{
    if (n < 2 || p[0] != '{' || p[n - 1] != '}') return false;
    for (size_t i = 0; i < n; i++) if ((unsigned char)p[i] < 0x20) return false;
    return true;
}

// Load crash.log into s_log, keeping only well-formed lines, oldest first.
static void load_log(void)
{
    char *raw = heap_caps_malloc(CRASH_LOG_MAX + 1, MALLOC_CAP_SPIRAM);
    if (!raw) return;
    size_t n = read_file(CRASH_LOG_PATH, raw, CRASH_LOG_MAX);
    s_log_len = 0;
    for (size_t i = 0; i < n; ) {
        char *nl = memchr(raw + i, '\n', n - i);
        if (!nl) break;                         // a torn last line is dropped
        size_t ll = (size_t)(nl - (raw + i));
        if (line_ok(raw + i, ll)) {
            memmove(s_log + s_log_len, raw + i, ll);
            s_log_len += ll;
            s_log[s_log_len++] = '\n';
        }
        i += ll + 1;
    }
    s_log[s_log_len] = '\0';
    free(raw);
}

static int log_lines(void)
{
    int c = 0;
    for (size_t i = 0; i < s_log_len; i++) if (s_log[i] == '\n') c++;
    return c;
}

static void log_append(const char *line, size_t ll)
{
    if (ll + 1 > CRASH_LOG_MAX) return;
    int lines = log_lines();
    while (s_log_len && (lines >= CRASH_LOG_KEEP || s_log_len + ll + 1 > CRASH_LOG_MAX)) {
        char *nl = memchr(s_log, '\n', s_log_len);
        size_t cut = nl ? (size_t)(nl - s_log) + 1 : s_log_len;
        memmove(s_log, s_log + cut, s_log_len - cut);
        s_log_len -= cut;
        lines--;
    }
    memcpy(s_log + s_log_len, line, ll);
    s_log_len += ll;
    s_log[s_log_len++] = '\n';
    s_log[s_log_len] = '\0';
    if (!write_atomic(CRASH_LOG_PATH, s_log, s_log_len))
        ESP_LOGW(TAG, "Could not write %s", CRASH_LOG_PATH);
}

// Value of "key":"..." or "key":N in one of our summary lines.
static bool field(const char *line, size_t ll, const char *key, char *out, size_t n)
{
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *end = line + ll;
    const char *p = line;
    size_t pl = strlen(pat);
    for (; p + pl <= end; p++) if (!memcmp(p, pat, pl)) break;
    if (p + pl > end) return false;
    p += pl;
    bool quoted = *p == '"';
    if (quoted) p++;
    size_t i = 0;
    while (p < end && i + 1 < n && (quoted ? *p != '"' : (*p != ',' && *p != '}'))) out[i++] = *p++;
    out[i] = '\0';
    return true;
}

// s_last from the newest line of crash.log (a crash from an earlier boot).
static void last_from_log(void)
{
    if (!s_log_len) return;
    size_t end = s_log_len - 1;                 // the final '\n'
    size_t start = end;
    while (start > 0 && s_log[start - 1] != '\n') start--;
    const char *l = s_log + start;
    size_t ll = end - start;
    char v[24];
    memset(&s_last, 0, sizeof(s_last));
    s_last.valid = true;
    if (field(l, ll, "ts", v, sizeof(v))) s_last.ts = (uint32_t)strtoul(v, NULL, 10);
    if (!field(l, ll, "cause", s_last.cause, sizeof(s_last.cause))) strlcpy(s_last.cause, "?", sizeof(s_last.cause));
    field(l, ll, "task", s_last.task, sizeof(s_last.task));
    if (field(l, ll, "pc", v, sizeof(v))) s_last.pc = (uint32_t)strtoul(v, NULL, 16);
}

// ── Boot side: the card ───────────────────────────────────────────────────────

typedef struct {
    char    *report;        // heap_caps_malloc'd, ownership passes to sd_log
    size_t   report_len;
    char    *line;          // {"kind":"crash",...}\n for the day log, same
    size_t   line_len;
    uint32_t crash_ts;      // name the file by this if set
    uint32_t up_s;          // else by the clock now, else by this
} sd_job_t;

#define SD_WAIT_MOUNT_S 120
#define SD_WAIT_CLOCK_S 60

static void crash_sd_task(void *arg)
{
    sd_job_t *j = arg;
    sd_status_t st = {0};
    for (int i = 0; i < SD_WAIT_MOUNT_S * 2; i++) {
        sd_log_status(&st);
        if (st.mounted) break;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (!st.mounted) {
        ESP_LOGW(TAG, "No microSD card after %d s: crash report kept in SPIFFS only", SD_WAIT_MOUNT_S);
        free(j->report);
        free(j->line);
    } else {
        time_t now = time(NULL);
        for (int i = 0; i < SD_WAIT_CLOCK_S && now < CLOCK_VALID && j->crash_ts < CLOCK_VALID; i++) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            now = time(NULL);
        }
        char path[64];
        uint32_t ts = j->crash_ts >= CLOCK_VALID ? j->crash_ts : (now >= CLOCK_VALID ? (uint32_t)now : 0);
        if (ts) {
            time_t t = (time_t)ts;
            struct tm tm;
            char name[24];
            localtime_r(&t, &tm);
            strftime(name, sizeof(name), "%Y-%m-%d_%H-%M-%S", &tm);
            snprintf(path, sizeof(path), CRASH_SD_DIR "/%s.txt", name);
        } else {
            snprintf(path, sizeof(path), CRASH_SD_DIR "/up%lus_%04x.txt",
                     (unsigned long)j->up_s, (unsigned)(esp_random() & 0xffff));
        }
        bool ok = sd_log_write_file(path, j->report, j->report_len);   // frees it
        ESP_LOGI(TAG, "Crash report %s %s", ok ? "queued to" : "not queued to", path);
        if (j->line) sd_log_line(j->line, j->line_len);                // frees it
    }
    free(j);
    vTaskDelete(NULL);
}

// ── Init ──────────────────────────────────────────────────────────────────────

void crash_init(void)
{
    // Inputs the hook copies (never read from flash at panic time).
    strlcpy(s_ver, esp_app_get_description()->version, sizeof(s_ver));
    esp_app_get_elf_sha256(s_elf, 17);

    static esp_timer_handle_t s_tmr;
    const esp_timer_create_args_t ta = { .callback = clock_sample, .name = "crashclk" };
    if (esp_timer_create(&ta, &s_tmr) == ESP_OK) esp_timer_start_periodic(s_tmr, CLOCK_SAMPLE_US);
    clock_sample(NULL);

    s_log    = heap_caps_malloc(CRASH_LOG_MAX + 1, MALLOC_CAP_SPIRAM);
    s_report = heap_caps_malloc(CRASH_REPORT_MAX, MALLOC_CAP_SPIRAM);
    if (!s_log || !s_report) {
        ESP_LOGE(TAG, "No PSRAM for the crash log");
        free(s_log); free(s_report);
        s_log = s_report = NULL;
        return;
    }
    s_log[0] = '\0';
    load_log();
    s_report_len = read_file(CRASH_LAST_PATH, s_report, CRASH_REPORT_MAX - 1);
    s_report[s_report_len] = '\0';
    last_from_log();

    // Off app_main's 3.5 KB stack, like the line and report buffers below.
    static crash_rec_t *s_rec;
    if (!s_rec) s_rec = heap_caps_malloc(sizeof(*s_rec), MALLOC_CAP_SPIRAM);
    if (!s_rec) return;
    crash_rec_t *recp = s_rec;
    uint32_t *w = (uint32_t *)recp;
    for (size_t i = 0; i < REC_WORDS; i++) w[i] = s_rtc[i];
    bool valid = rec_valid(recp);

    esp_reset_reason_t rr = esp_reset_reason();
    bool crash_reset = rr == ESP_RST_PANIC || rr == ESP_RST_INT_WDT ||
                       rr == ESP_RST_TASK_WDT || rr == ESP_RST_WDT;
    if (!crash_reset) {
        if (valid) ESP_LOGW(TAG, "Stale panic record dropped (reset reason %d)", (int)rr);
        s_rtc[0] = 0;
        ESP_LOGI(TAG, "No crash this boot; %d in %s", log_lines(), CRASH_LOG_PATH);
        return;
    }

    const crash_rec_t *r = valid ? recp : NULL;
    char cause[40];
    if (r) cause_of(r, cause, sizeof(cause));
    else   strlcpy(cause, "no record", sizeof(cause));
    time_t now = time(NULL);
    uint32_t boot_ts = now >= CLOCK_VALID ? (uint32_t)now : 0;

    char *line = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
    if (!line) { s_rtc[0] = 0; return; }
    size_t ll = fmt_summary(line, 1024, r, rr, boot_ts, cause);
    s_report_len = fmt_report(s_report, CRASH_REPORT_MAX, r, rr, boot_ts, cause);
    if (ll) log_append(line, ll);
    if (!write_atomic(CRASH_LAST_PATH, s_report, s_report_len))
        ESP_LOGW(TAG, "Could not write %s", CRASH_LAST_PATH);
    s_rtc[0] = 0;                               // reported: clear the record

    memset(&s_last, 0, sizeof(s_last));
    s_last.valid = true;
    s_last.this_boot = true;
    s_last.ts = r ? r->epoch : 0;
    strlcpy(s_last.cause, cause, sizeof(s_last.cause));
    if (r) {
        strlcpy(s_last.task, r->task[r->core], sizeof(s_last.task));
        s_last.pc = r->pc;
    }
    if (r)
        ESP_LOGE(TAG, "Last run crashed: %s in task %s at PC 0x%08lx (%s)",
                 cause, s_last.task[0] ? s_last.task : "?", (unsigned long)r->pc, r->reason);
    else
        ESP_LOGE(TAG, "Last run ended by %s, no panic record", notify_reset_reason_str(rr));

    // The card copy: the report and a {"kind":"crash",...} day-log line.
    sd_job_t *j = heap_caps_calloc(1, sizeof(*j), MALLOC_CAP_SPIRAM);
    char *rep = heap_caps_malloc(s_report_len + 1, MALLOC_CAP_SPIRAM);
    char *dl = ll ? heap_caps_malloc(ll + 32, MALLOC_CAP_SPIRAM) : NULL;
    if (j && rep) {
        memcpy(rep, s_report, s_report_len);
        j->report = rep;
        j->report_len = s_report_len;
        if (dl) {
            // {"kind":"crash", then the summary after its '{', and a newline
            j->line_len = (size_t)snprintf(dl, ll + 32, "{\"kind\":\"crash\",%.*s\n", (int)(ll - 1), line + 1);
            j->line = dl;
            dl = NULL;
        }
        j->crash_ts = r ? r->epoch : 0;
        j->up_s = r ? (uint32_t)((((uint64_t)r->up_hi << 32) | r->up_lo) / 1000000) : 0;
        // PSRAM stack: the task only waits, formats and queues (no flash).
        if (xTaskCreatePinnedToCoreWithCaps(crash_sd_task, "crashsd", 3072, j, 1, NULL, 1,
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) == pdPASS) {
            j = NULL;
            rep = NULL;
        } else {
            free(j->line);
        }
    }
    free(j);
    free(rep);
    free(dl);
    free(line);
}
