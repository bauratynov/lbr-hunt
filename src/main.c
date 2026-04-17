/*
 * main.c — CLI driver.
 *
 * Two operating modes:
 *   lbr-hunt -p PID                 attach to running process
 *   lbr-hunt [opts] -- CMD [ARGS]   fork + exec, then attach to child
 *
 * Every `--window` branches we feed the window to the analyzer and
 * emit one line (text or JSON). Suspicious windows are flagged; with
 * `--stop-on-first` the first hit exits non-zero so lbr-hunt can be
 * chained into a canary / fuzz harness.
 */

#define _GNU_SOURCE

#include "analyzer.h"
#include "collector.h"
#include "format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

static void usage(const char *prog)
{
    fprintf(stderr,
"lbr-hunt — runtime ROP/JOP detector using Intel LBR\n"
"\n"
"Usage:\n"
"  %s -p PID [options]\n"
"  %s [options] -- CMD [ARGS...]\n"
"\n"
"Attach modes:\n"
"  -p, --pid PID            monitor an existing process\n"
"  -- CMD ...               fork/exec a child and monitor it\n"
"\n"
"Output:\n"
"      --jsonl              emit JSON-lines instead of text\n"
"      --stop-on-first      exit on first suspicious window (code 3)\n"
"\n"
"Tuning:\n"
"      --window N           branches per analysis window   [1024]\n"
"      --mmap PAGES         ring size in pages, pow2       [64]\n"
"      --ret-density X      threshold for ret density      [0.60]\n"
"      --ind-call-density X threshold for indirect calls   [0.40]\n"
"      --short-gadget N     min short-gadget pairs         [4]\n"
"      --min-chain N        min ret chain length           [5]\n"
"      --gadget-distance B  max distance considered short  [32]\n"
"      --cluster-range B    max target range for cluster   [65536]\n"
"      --score-threshold X  verdict threshold              [0.70]\n"
"\n"
"  -h, --help               this message\n"
"\n"
"Notes:\n"
"  Requires Linux >= 5.11 for branch type info, CAP_PERFMON or root,\n"
"  and Intel CPU with LBR (Nehalem+) or AMD with BRS.\n"
"\n", prog, prog);
}

static int parse_size(const char *s, size_t *out)
{
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (!end || *end) return -1;
    *out = (size_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    pid_t  pid            = 0;
    int    jsonl          = 0;
    int    stop_on_first  = 0;
    size_t window         = 1024;
    size_t mmap_pages     = 64;
    int    spawned_child  = 0;

    lbr_config_t cfg;
    lbr_config_default(&cfg);

    enum {
        OPT_JSONL = 1001, OPT_WIN, OPT_MMAP,
        OPT_RET_DENS, OPT_IND_DENS, OPT_SHORT_G,
        OPT_MIN_CHAIN, OPT_GAD_DIST, OPT_CLU_RANGE,
        OPT_SCORE, OPT_STOP
    };

    static const struct option opts[] = {
        {"pid",               required_argument, 0, 'p'},
        {"jsonl",             no_argument,       0, OPT_JSONL},
        {"window",            required_argument, 0, OPT_WIN},
        {"mmap",              required_argument, 0, OPT_MMAP},
        {"ret-density",       required_argument, 0, OPT_RET_DENS},
        {"ind-call-density",  required_argument, 0, OPT_IND_DENS},
        {"short-gadget",      required_argument, 0, OPT_SHORT_G},
        {"min-chain",         required_argument, 0, OPT_MIN_CHAIN},
        {"gadget-distance",   required_argument, 0, OPT_GAD_DIST},
        {"cluster-range",     required_argument, 0, OPT_CLU_RANGE},
        {"score-threshold",   required_argument, 0, OPT_SCORE},
        {"stop-on-first",     no_argument,       0, OPT_STOP},
        {"help",              no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c, idx;
    /* '+' = stop at first non-option so "-- CMD ARGS" works */
    while ((c = getopt_long(argc, argv, "+p:h", opts, &idx)) != -1) {
        switch (c) {
        case 'p': pid = (pid_t)atoi(optarg); break;
        case OPT_JSONL:     jsonl = 1; break;
        case OPT_STOP:      stop_on_first = 1; break;
        case OPT_WIN:       if (parse_size(optarg, &window) < 0) goto bad; break;
        case OPT_MMAP:      if (parse_size(optarg, &mmap_pages) < 0) goto bad; break;
        case OPT_RET_DENS:  cfg.ret_density_thresh      = atof(optarg); break;
        case OPT_IND_DENS:  cfg.ind_call_density_thresh = atof(optarg); break;
        case OPT_SHORT_G:   cfg.short_gadget_thresh     = (uint32_t)atoi(optarg); break;
        case OPT_MIN_CHAIN: cfg.min_chain_len           = (uint32_t)atoi(optarg); break;
        case OPT_GAD_DIST:  cfg.gadget_distance_max     = (uint32_t)atoi(optarg); break;
        case OPT_CLU_RANGE: cfg.cluster_range_max       = strtoull(optarg, NULL, 0); break;
        case OPT_SCORE:     cfg.score_threshold         = atof(optarg); break;
        case 'h':           usage(argv[0]); return 0;
        default: goto bad;
        }
    }

    /* Command mode: fork + exec */
    if (pid == 0 && optind < argc) {
        pid_t child = fork();
        if (child < 0) { perror("fork"); return 1; }
        if (child == 0) {
            execvp(argv[optind], &argv[optind]);
            perror("execvp");
            _exit(127);
        }
        pid = child;
        spawned_child = 1;
        /* let the child settle before we attach */
        usleep(50 * 1000);
    }

    if (pid == 0) {
    bad:
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    lbr_collector_t *col = NULL;
    if (lbr_collector_open(&col, pid, mmap_pages) < 0) {
        fprintf(stderr, "lbr_collector_open(%d): %s\n", (int)pid, strerror(errno));
        if (errno == EACCES || errno == EPERM) {
            fprintf(stderr,
                "hint: try one of:\n"
                "  - run as root\n"
                "  - grant CAP_PERFMON (setcap cap_perfmon=ep ./lbr-hunt)\n"
                "  - sysctl -w kernel.perf_event_paranoid=2 (or lower)\n");
        } else if (errno == ENODEV || errno == EOPNOTSUPP) {
            fprintf(stderr,
                "hint: CPU doesn't expose LBR / BRS, "
                "or the running kernel was built without it.\n");
        }
        if (spawned_child) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
        return 1;
    }

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    lbr_branch_t *win = calloc(window, sizeof(*win));
    if (!win) { lbr_collector_close(col); return 1; }
    size_t have = 0;
    int exit_code = 0;

    while (!g_stop) {
        int n = lbr_collector_poll(col, win + have, window - have, 200);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "poll: %s\n", strerror(errno));
            exit_code = 1;
            break;
        }
        have += (size_t)n;
        if (have < window) {
            /* check child still alive if we spawned it */
            if (spawned_child) {
                int st;
                pid_t r = waitpid(pid, &st, WNOHANG);
                if (r == pid) break;  /* child exited */
            }
            continue;
        }

        struct timespec tn;
        clock_gettime(CLOCK_MONOTONIC, &tn);
        double elapsed = (double)(tn.tv_sec - t0.tv_sec) +
                         (double)(tn.tv_nsec - t0.tv_nsec) * 1e-9;

        lbr_report_t rep;
        lbr_analyze(win, have, &cfg, &rep);

        if (jsonl) format_report_jsonl(stdout, &rep, elapsed);
        else       format_report_text (stdout, &rep, elapsed);
        fflush(stdout);

        if (stop_on_first && (rep.flags & LBR_FLAG_SUSPICIOUS)) {
            exit_code = 3;
            break;
        }
        have = 0;
    }

    free(win);
    lbr_collector_close(col);

    if (spawned_child) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }

    return exit_code;
}
