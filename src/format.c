/*
 * format.c — report rendering.
 *
 * Two targets: a compact text form for humans, and newline-delimited
 * JSON (JSON-Lines) for machine ingestion.
 */

#include "format.h"

#include <inttypes.h>

static const char *flag_list(uint32_t flags, char *buf, size_t buflen)
{
    size_t n = 0;
    buf[0] = '\0';

#define APPEND(name)                                             \
    do {                                                         \
        if (flags & LBR_FLAG_##name) {                           \
            int w = snprintf(buf + n, buflen - n,                \
                             n ? " " #name : #name);             \
            if (w < 0) break;                                    \
            n += (size_t)w;                                      \
            if (n >= buflen) { buf[buflen - 1] = '\0'; break; }  \
        }                                                        \
    } while (0)

    APPEND(HIGH_RET_DENSITY);
    APPEND(SHORT_GADGETS);
    APPEND(TIGHT_CLUSTERS);
    APPEND(RET_OVERFLOW);
    APPEND(IND_CALL_HEAVY);

#undef APPEND
    return buf;
}

void format_report_text(FILE *f, const lbr_report_t *r, double elapsed_s)
{
    char flagbuf[128];
    const char *susp = (r->flags & LBR_FLAG_SUSPICIOUS)
                     ? "  *** SUSPICIOUS ***" : "";

    fprintf(f, "=== t=%7.2fs  branches=%u ===\n", elapsed_s, r->total);
    fprintf(f, "  ret density     : %.3f\n", r->return_density);
    fprintf(f, "  ind-call density: %.3f\n", r->ind_call_density);
    fprintf(f, "  short gadgets   : %u pairs\n", r->short_gadget_pairs);
    fprintf(f, "  max ret chain   : %u\n", r->max_chain_len);
    fprintf(f, "  unpaired rets   : %u\n", r->unpaired_rets);
    fprintf(f, "  ret target range: %" PRIu64 " bytes\n", r->target_range);
    fprintf(f, "  score           : %.3f%s\n", r->score, susp);
    if (r->flags & ~(uint32_t)LBR_FLAG_SUSPICIOUS) {
        fprintf(f, "  flags           : %s\n",
                flag_list(r->flags, flagbuf, sizeof(flagbuf)));
    }
}

void format_report_jsonl(FILE *f, const lbr_report_t *r, double elapsed_s)
{
    fprintf(f,
        "{\"ts\":%.3f,"
        "\"total\":%u,"
        "\"ret_density\":%.3f,"
        "\"ind_call_density\":%.3f,"
        "\"short_gadget_pairs\":%u,"
        "\"max_chain\":%u,"
        "\"unpaired_rets\":%u,"
        "\"target_range\":%" PRIu64 ","
        "\"score\":%.3f,"
        "\"suspicious\":%s,"
        "\"flags\":%u}\n",
        elapsed_s,
        r->total,
        r->return_density,
        r->ind_call_density,
        r->short_gadget_pairs,
        r->max_chain_len,
        r->unpaired_rets,
        r->target_range,
        r->score,
        (r->flags & LBR_FLAG_SUSPICIOUS) ? "true" : "false",
        r->flags);
}
