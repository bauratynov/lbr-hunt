/*
 * analyzer.h — ROP/JOP detection from an LBR branch-record window.
 *
 * The analyzer is a pure function over a sequence of branches:
 * no I/O, no global state, no allocation. All kernel interaction lives
 * in collector.c — this file is deliberately portable and testable.
 */
#ifndef LBR_HUNT_ANALYZER_H
#define LBR_HUNT_ANALYZER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Branch type taxonomy — maps to perf_event PERF_SAMPLE_BRANCH_TYPE values
 * but stays independent so the analyzer builds on any platform. */
enum lbr_br_type {
    BR_UNKNOWN  = 0,
    BR_COND     = 1,
    BR_UNCOND   = 2,   /* unconditional direct jump  */
    BR_IND      = 3,   /* indirect jump              */
    BR_CALL     = 4,   /* direct call                */
    BR_IND_CALL = 5,   /* indirect call              */
    BR_RET      = 6,
    BR_SYSCALL  = 7,
    BR_SYSRET   = 8,
    BR_IRQ      = 9,
    BR_TYPE_MAX = 16
};

/* One entry from the CPU's branch record buffer. */
typedef struct {
    uint64_t from;
    uint64_t to;
    uint32_t mispred   : 1;
    uint32_t predicted : 1;
    uint32_t in_tx     : 1;
    uint32_t abort     : 1;
    uint32_t cycles    : 16;
    uint32_t type      : 4;   /* enum lbr_br_type */
    uint32_t reserved  : 8;
} lbr_branch_t;

/* Flags set on the report when a heuristic triggers. */
#define LBR_FLAG_SUSPICIOUS         (1u << 0)
#define LBR_FLAG_HIGH_RET_DENSITY   (1u << 1)
#define LBR_FLAG_SHORT_GADGETS      (1u << 2)
#define LBR_FLAG_TIGHT_CLUSTERS     (1u << 3)
#define LBR_FLAG_RET_OVERFLOW       (1u << 4)
#define LBR_FLAG_IND_CALL_HEAVY     (1u << 5)

typedef struct {
    /* raw counts */
    uint32_t total;
    uint32_t by_type[BR_TYPE_MAX];

    /* derived features */
    double   return_density;
    double   ind_call_density;
    uint32_t short_gadget_pairs;
    uint32_t target_clusters;
    uint64_t target_range;
    uint32_t unpaired_rets;
    uint32_t max_chain_len;

    /* verdict: 0.0 = clean .. 1.0 = strongly ROP-like */
    double   score;
    uint32_t flags;
} lbr_report_t;

typedef struct {
    double   ret_density_thresh;       /* default 0.60 */
    double   ind_call_density_thresh;  /* default 0.40 */
    uint32_t short_gadget_thresh;      /* default    4 */
    uint32_t min_chain_len;            /* default    5 */
    uint32_t gadget_distance_max;      /* default   32 */
    uint64_t cluster_range_max;        /* default 65536 */
    double   score_threshold;          /* default 0.70 */
} lbr_config_t;

/* Fill cfg with defaults tuned on clean kernel + glibc traces. */
void lbr_config_default(lbr_config_t *cfg);

/* Analyze one window of branches.
 * - `branches` may be NULL iff n == 0.
 * - `cfg` may be NULL; defaults will be used.
 * - `out` must not be NULL. It is fully overwritten.
 * The function is O(n), allocation-free, and thread-safe for distinct outs. */
void lbr_analyze(const lbr_branch_t *branches,
                 size_t              n,
                 const lbr_config_t *cfg,
                 lbr_report_t       *out);

#ifdef __cplusplus
}
#endif

#endif /* LBR_HUNT_ANALYZER_H */
