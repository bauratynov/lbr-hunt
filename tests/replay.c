/*
 * replay.c — log-file driven analyzer harness.
 *
 * Consumes a human-editable branch log and prints the resulting report.
 * Used for integration tests and for reasoning about detection thresholds
 * on real traces captured from perf.
 *
 * Line format ("#" introduces a comment):
 *     <from-hex> <to-hex> <type-name> [cycles]
 *
 * Type names: cond, uncond, ind, call, ind_call, ret, syscall, sysret, irq.
 */

#include "analyzer.h"
#include "format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

static int parse_type(const char *s, uint32_t *out)
{
    struct { const char *n; uint32_t v; } map[] = {
        {"unknown",  BR_UNKNOWN},
        {"cond",     BR_COND},
        {"uncond",   BR_UNCOND},
        {"ind",      BR_IND},
        {"call",     BR_CALL},
        {"ind_call", BR_IND_CALL},
        {"ret",      BR_RET},
        {"syscall",  BR_SYSCALL},
        {"sysret",   BR_SYSRET},
        {"irq",      BR_IRQ},
    };
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (strcmp(map[i].n, s) == 0) { *out = map[i].v; return 0; }
    }
    return -1;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <log-file> [--jsonl]\n", argv[0]);
        return 2;
    }
    int jsonl = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--jsonl") == 0) jsonl = 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 1; }

    size_t cap = 64, n = 0;
    lbr_branch_t *buf = calloc(cap, sizeof(*buf));
    if (!buf) { fclose(f); return 1; }

    char line[256];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;

        uint64_t from, to;
        char type_s[32] = {0};
        unsigned cycles = 0;

        int got = sscanf(p, "%" SCNx64 " %" SCNx64 " %31s %u",
                         &from, &to, type_s, &cycles);
        if (got < 3) {
            fprintf(stderr, "%s:%d: malformed line\n", argv[1], lineno);
            free(buf); fclose(f); return 1;
        }

        uint32_t t;
        if (parse_type(type_s, &t) < 0) {
            fprintf(stderr, "%s:%d: unknown type '%s'\n",
                    argv[1], lineno, type_s);
            free(buf); fclose(f); return 1;
        }

        if (n == cap) {
            size_t nc = cap * 2;
            void *nb = realloc(buf, nc * sizeof(*buf));
            if (!nb) { free(buf); fclose(f); return 1; }
            buf = nb; cap = nc;
        }

        memset(&buf[n], 0, sizeof(buf[n]));
        buf[n].from   = from;
        buf[n].to     = to;
        buf[n].type   = t;
        buf[n].cycles = cycles & 0xFFFF;
        n++;
    }
    fclose(f);

    lbr_report_t rep;
    lbr_analyze(buf, n, NULL, &rep);

    if (jsonl) format_report_jsonl(stdout, &rep, 0.0);
    else       format_report_text (stdout, &rep, 0.0);

    free(buf);
    return (rep.flags & LBR_FLAG_SUSPICIOUS) ? 3 : 0;
}
