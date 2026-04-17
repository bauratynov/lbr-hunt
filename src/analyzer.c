/*
 * analyzer.c — pure ROP/JOP heuristics over a branch window.
 *
 * Detection philosophy (informed by academic work on kBouncer, ROPecker,
 * HDROP): no single feature is reliable; the union is. Each heuristic
 * contributes a bounded weight, weights sum to 1.0, final score is
 * clamped to [0.0, 1.0] and compared against a configurable threshold.
 *
 * Features used:
 *   1. Return density           (weight 0.35)
 *   2. Short-gadget pair count  (weight 0.25)
 *   3. Tight target clustering  (weight 0.15)
 *   4. Maximum ret chain length (weight 0.10)
 *   5. Indirect-call density    (weight 0.10)  [JOP signal]
 *   6. Unpaired-ret fraction    (weight 0.05)
 *
 * Sum of weights: 1.00. Each normalised contribution is bounded so that
 * even a worst-case input caps score at 1.00.
 */

#include "analyzer.h"
#include <string.h>
#include <stdint.h>

void lbr_config_default(lbr_config_t *cfg)
{
    cfg->ret_density_thresh      = 0.60;
    cfg->ind_call_density_thresh = 0.40;
    cfg->short_gadget_thresh     = 4;
    cfg->min_chain_len           = 5;
    cfg->gadget_distance_max     = 32;
    cfg->cluster_range_max       = (uint64_t)64 * 1024;
    cfg->score_threshold         = 0.70;
}

static uint64_t abs_delta_u64(uint64_t a, uint64_t b)
{
    return a > b ? a - b : b - a;
}

void lbr_analyze(const lbr_branch_t *br,
                 size_t              n,
                 const lbr_config_t *cfg,
                 lbr_report_t       *out)
{
    lbr_config_t defaults;

    memset(out, 0, sizeof(*out));
    if (n == 0 || br == NULL) {
        return;
    }

    if (cfg == NULL) {
        lbr_config_default(&defaults);
        cfg = &defaults;
    }

    out->total = (uint32_t)n;

    /* ---------- 1. type histogram ---------- */
    for (size_t i = 0; i < n; i++) {
        uint32_t t = br[i].type;
        if (t < BR_TYPE_MAX) {
            out->by_type[t]++;
        }
    }

    out->return_density   = (double)out->by_type[BR_RET]      / (double)n;
    out->ind_call_density = (double)out->by_type[BR_IND_CALL] / (double)n;

    /* ---------- 2. call/ret balance, unpaired rets ---------- */
    int32_t  balance  = 0;
    uint32_t unpaired = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t t = br[i].type;
        if (t == BR_CALL || t == BR_IND_CALL) {
            balance++;
        } else if (t == BR_RET) {
            if (balance == 0) {
                unpaired++;
            } else {
                balance--;
            }
        }
    }
    out->unpaired_rets = unpaired;

    /* ---------- 3. RET target range ---------- */
    uint64_t min_to = UINT64_MAX;
    uint64_t max_to = 0;
    int      seen_ret = 0;
    for (size_t i = 0; i < n; i++) {
        if (br[i].type == BR_RET) {
            if (br[i].to < min_to) min_to = br[i].to;
            if (br[i].to > max_to) max_to = br[i].to;
            seen_ret = 1;
        }
    }
    if (seen_ret) {
        out->target_range = max_to - min_to;
        if (out->target_range < cfg->cluster_range_max) {
            out->target_clusters = 1;
        }
    }

    /* ---------- 4. short gadgets + max chain ---------- */
    uint32_t short_pairs  = 0;
    uint32_t chain        = 0;
    uint32_t max_chain    = 0;
    int      prev_was_ret = 0;
    uint64_t prev_from    = 0;

    for (size_t i = 0; i < n; i++) {
        if (br[i].type == BR_RET) {
            if (prev_was_ret) {
                uint64_t d = abs_delta_u64(br[i].from, prev_from);
                if (d > 0 && d <= cfg->gadget_distance_max) {
                    short_pairs++;
                }
                chain++;
            } else {
                chain = 1;
            }
            if (chain > max_chain) max_chain = chain;
            prev_was_ret = 1;
            prev_from    = br[i].from;
        } else {
            prev_was_ret = 0;
            chain = 0;
        }
    }
    out->short_gadget_pairs = short_pairs;
    out->max_chain_len      = max_chain;

    /* ---------- 5. score synthesis ---------- */
    double s = 0.0;

    /* (a) return density — scaled between threshold and 1.0 */
    if (out->return_density > cfg->ret_density_thresh) {
        double span = 1.0 - cfg->ret_density_thresh;
        double over = span > 0.0
            ? (out->return_density - cfg->ret_density_thresh) / span
            : 1.0;
        if (over > 1.0) over = 1.0;
        s += 0.35 * over;
        out->flags |= LBR_FLAG_HIGH_RET_DENSITY;
    }

    /* (b) short gadget pairs — normalised against 4x threshold */
    if (out->short_gadget_pairs >= cfg->short_gadget_thresh) {
        double norm = (double)out->short_gadget_pairs
                    / (double)(cfg->short_gadget_thresh * 4);
        if (norm > 1.0) norm = 1.0;
        s += 0.25 * norm;
        out->flags |= LBR_FLAG_SHORT_GADGETS;
    }

    /* (c) tight target clusters (only meaningful if enough rets) */
    if (out->target_clusters > 0 && out->by_type[BR_RET] >= 4) {
        s += 0.15;
        out->flags |= LBR_FLAG_TIGHT_CLUSTERS;
    }

    /* (d) long ret chain */
    if (out->max_chain_len >= cfg->min_chain_len) {
        double norm = (double)(out->max_chain_len - cfg->min_chain_len + 1)
                    / (double)cfg->min_chain_len;
        if (norm > 1.0) norm = 1.0;
        s += 0.10 * norm;
    }

    /* (e) indirect-call heavy — JOP/COP signal */
    if (out->ind_call_density > cfg->ind_call_density_thresh) {
        s += 0.10;
        out->flags |= LBR_FLAG_IND_CALL_HEAVY;
    }

    /* (f) unpaired rets — stack unwind beyond window or ROP pivot */
    if (out->unpaired_rets > 0) {
        double norm = (double)out->unpaired_rets / (double)n;
        if (norm > 1.0) norm = 1.0;
        s += 0.05 * norm;
        if (norm > 0.3) {
            out->flags |= LBR_FLAG_RET_OVERFLOW;
        }
    }

    if (s > 1.0) s = 1.0;
    if (s < 0.0) s = 0.0;
    out->score = s;

    if (out->score > cfg->score_threshold) {
        out->flags |= LBR_FLAG_SUSPICIOUS;
    }
}
