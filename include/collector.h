/*
 * collector.h — thin wrapper around perf_event_open for LBR sampling.
 *
 * The collector opens a branch-stack counter for a given pid, mmaps the
 * ring buffer, decodes PERF_RECORD_SAMPLE records, and hands back an
 * array of lbr_branch_t ready for the analyzer.
 *
 * Linux x86-64 only at runtime. On other OSes the functions return -1
 * with errno = ENOSYS so the rest of the program still links.
 */
#ifndef LBR_HUNT_COLLECTOR_H
#define LBR_HUNT_COLLECTOR_H

#include "analyzer.h"
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lbr_collector lbr_collector_t;

/* Open a branch-stack sampler attached to `pid` (use target pid; cpu=-1
 * under the hood). `mmap_pages` must be a power of two; 64 (256 KB) is
 * a reasonable default.
 * Returns 0 on success and writes a heap-allocated collector to *out.
 * Returns -1 and sets errno on failure. */
int  lbr_collector_open(lbr_collector_t **out,
                        pid_t             pid,
                        size_t            mmap_pages);

/* Release resources. Safe to call on NULL. */
void lbr_collector_close(lbr_collector_t *c);

/* Block up to `timeout_ms` for new data, then decode up to `buf_max`
 * branches into `buf`.
 *   > 0  number of branches written
 *   = 0  timeout, nothing available
 *   < 0  error (errno set)
 * Wake up on SIGINT/SIGTERM is handled by poll(2) returning EINTR. */
int  lbr_collector_poll(lbr_collector_t *c,
                        lbr_branch_t    *buf,
                        size_t           buf_max,
                        int              timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* LBR_HUNT_COLLECTOR_H */
