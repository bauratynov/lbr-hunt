/*
 * test_analyzer.c — unit tests for the pure LBR heuristics.
 *
 * No external framework; trivial harness keeps the project dependency-free.
 * Each test populates a synthetic branch window and asserts expected
 * features and score.
 */

#include "analyzer.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int fails = 0;
static int passes = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (cond) { passes++; }                                               \
        else { fails++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);} \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                 \
    do {                                                                      \
        double _a = (double)(a), _b = (double)(b), _e = (double)(eps);        \
        double _d = _a - _b; if (_d < 0) _d = -_d;                            \
        if (_d <= _e) { passes++; }                                           \
        else { fails++;                                                       \
            printf("FAIL %s:%d  %s (%.4f) !~ %s (%.4f) eps %.4f\n",           \
                   __FILE__, __LINE__, #a, _a, #b, _b, _e); }                 \
    } while (0)

static void zeroed(lbr_branch_t *b)
{
    memset(b, 0, sizeof(*b));
}

static void test_empty(void)
{
    lbr_report_t r;
    lbr_analyze(NULL, 0, NULL, &r);
    CHECK(r.total == 0);
    CHECK(r.score == 0.0);
    CHECK(r.flags == 0);
}

static void test_clean_call_ret_alternating(void)
{
    lbr_branch_t br[20];
    for (int i = 0; i < 20; i++) {
        zeroed(&br[i]);
        br[i].type = (i % 2 == 0) ? BR_CALL : BR_RET;
        br[i].from = 0x400000u + (uint64_t)i * 0x100u;
        br[i].to   = 0x500000u + (uint64_t)i * 0x100u;
    }
    lbr_report_t r;
    lbr_analyze(br, 20, NULL, &r);
    CHECK(r.total == 20);
    CHECK(r.by_type[BR_CALL] == 10);
    CHECK(r.by_type[BR_RET]  == 10);
    CHECK_NEAR(r.return_density, 0.5, 0.01);
    CHECK(r.short_gadget_pairs == 0);
    CHECK(r.max_chain_len == 1);
    CHECK(r.unpaired_rets == 0);
    CHECK((r.flags & LBR_FLAG_SUSPICIOUS) == 0);
    CHECK((r.flags & LBR_FLAG_HIGH_RET_DENSITY) == 0);
    CHECK(r.score < 0.5);
}

static void test_rop_chain_detected(void)
{
    /* 32 rets in a row: high density, short gadgets, tight clusters, long chain. */
    lbr_branch_t br[32];
    for (int i = 0; i < 32; i++) {
        zeroed(&br[i]);
        br[i].type = BR_RET;
        br[i].from = 0x400010u + (uint64_t)i * 8u;    /* gadget-sized */
        br[i].to   = 0x403000u + (uint64_t)i * 16u;   /* tightly clustered */
    }
    lbr_report_t r;
    lbr_analyze(br, 32, NULL, &r);
    CHECK(r.total == 32);
    CHECK(r.by_type[BR_RET] == 32);
    CHECK_NEAR(r.return_density, 1.0, 0.01);
    CHECK(r.short_gadget_pairs >= 20);
    CHECK(r.max_chain_len == 32);
    CHECK((r.flags & LBR_FLAG_HIGH_RET_DENSITY) != 0);
    CHECK((r.flags & LBR_FLAG_SHORT_GADGETS)    != 0);
    CHECK((r.flags & LBR_FLAG_TIGHT_CLUSTERS)   != 0);
    CHECK((r.flags & LBR_FLAG_SUSPICIOUS)       != 0);
    CHECK(r.score > 0.70);
}

static void test_jop_ind_call_heavy(void)
{
    lbr_branch_t br[20];
    for (int i = 0; i < 20; i++) {
        zeroed(&br[i]);
        br[i].type = BR_IND_CALL;
        br[i].from = 0x400000u + (uint64_t)i * 0x40u;
        br[i].to   = 0x500000u + (uint64_t)i * 0x1000u;
    }
    lbr_report_t r;
    lbr_analyze(br, 20, NULL, &r);
    CHECK(r.by_type[BR_IND_CALL] == 20);
    CHECK_NEAR(r.ind_call_density, 1.0, 0.01);
    CHECK((r.flags & LBR_FLAG_IND_CALL_HEAVY) != 0);
    CHECK(r.score >= 0.10);
}

static void test_config_threshold_raised(void)
{
    /* A moderately ROP-like signal should drop below score_threshold
     * when the operator raises it. */
    lbr_config_t cfg;
    lbr_config_default(&cfg);
    cfg.score_threshold = 0.95;

    lbr_branch_t br[16];
    for (int i = 0; i < 16; i++) {
        zeroed(&br[i]);
        br[i].type = (i % 2) ? BR_RET : BR_COND;
        br[i].from = 0x400000u + (uint64_t)i * 0x100u;
        br[i].to   = 0x500000u + (uint64_t)i * 0x100u;
    }
    lbr_report_t r;
    lbr_analyze(br, 16, &cfg, &r);
    CHECK((r.flags & LBR_FLAG_SUSPICIOUS) == 0);
}

static void test_unpaired_rets_counted(void)
{
    lbr_branch_t br[10];
    for (int i = 0; i < 10; i++) {
        zeroed(&br[i]);
        br[i].type = BR_RET;
        br[i].from = 0x400000u + (uint64_t)i * 0x1000u;
        br[i].to   = 0x500000u + (uint64_t)i * 0x1000u;
    }
    lbr_report_t r;
    lbr_analyze(br, 10, NULL, &r);
    CHECK(r.unpaired_rets == 10);
    CHECK((r.flags & LBR_FLAG_RET_OVERFLOW) != 0);
}

static void test_short_gadget_pair_boundary(void)
{
    /* Two rets close (8 bytes apart) — one pair expected. */
    lbr_branch_t br[2];
    zeroed(&br[0]); zeroed(&br[1]);
    br[0].type = BR_RET; br[0].from = 0x400000; br[0].to = 0x500000;
    br[1].type = BR_RET; br[1].from = 0x400008; br[1].to = 0x500008;
    lbr_report_t r;
    lbr_analyze(br, 2, NULL, &r);
    CHECK(r.short_gadget_pairs == 1);
    CHECK(r.max_chain_len == 2);
}

static void test_score_monotone_in_density(void)
{
    /* Synthesise two inputs: one 10% rets, one 90% rets.
     * The high-density window must score >= the low-density one. */
    lbr_branch_t lo[50], hi[50];
    for (int i = 0; i < 50; i++) {
        zeroed(&lo[i]);
        lo[i].type = (i % 10 == 0) ? BR_RET : BR_COND;
        lo[i].from = 0x400000u + (uint64_t)i * 0x100u;
        lo[i].to   = 0x500000u + (uint64_t)i * 0x100u;

        zeroed(&hi[i]);
        hi[i].type = (i % 10 == 0) ? BR_COND : BR_RET;
        hi[i].from = 0x400000u + (uint64_t)i * 0x100u;
        hi[i].to   = 0x500000u + (uint64_t)i * 0x100u;
    }
    lbr_report_t rlo, rhi;
    lbr_analyze(lo, 50, NULL, &rlo);
    lbr_analyze(hi, 50, NULL, &rhi);
    CHECK(rhi.score >= rlo.score);
    CHECK(rhi.return_density > rlo.return_density);
}

int main(void)
{
    test_empty();
    test_clean_call_ret_alternating();
    test_rop_chain_detected();
    test_jop_ind_call_heavy();
    test_config_threshold_raised();
    test_unpaired_rets_counted();
    test_short_gadget_pair_boundary();
    test_score_monotone_in_density();

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
