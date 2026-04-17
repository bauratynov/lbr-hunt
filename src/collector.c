/*
 * collector.c — perf_event_open branch-stack sampler.
 *
 * Architecture:
 *   - open PERF_COUNT_HW_BRANCH_INSTRUCTIONS with sample_period ~= 10k so
 *     we get one PERF_RECORD_SAMPLE per ~10k taken branches;
 *   - each sample carries the CPU's 32-entry LBR via PERF_SAMPLE_BRANCH_STACK;
 *   - kernel delivers records into a shared ring (mmap), producer index
 *     lives in perf_event_mmap_page.data_head, consumer in .data_tail.
 *
 * The branch type field requires PERF_SAMPLE_BRANCH_TYPE_SAVE (kernel
 * >= 5.11). On older kernels every record comes back with type == 0;
 * the analyzer degrades gracefully (it becomes a pure density signal).
 *
 * We keep a single bounce buffer for records that wrap the ring edge.
 * No per-sample allocation; poll() handles wakeups.
 */

#include "collector.h"

#if defined(__linux__) && defined(__x86_64__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#ifndef PERF_SAMPLE_BRANCH_TYPE_SAVE
#define PERF_SAMPLE_BRANCH_TYPE_SAVE (1U << 16)
#endif

struct lbr_collector {
    int       fd;
    void     *mmap_base;
    size_t    mmap_size;
    size_t    data_size;    /* power of two */
    uint8_t  *data;         /* mmap_base + page */
};

static long perf_event_open_syscall(struct perf_event_attr *a,
                                    pid_t pid, int cpu,
                                    int group_fd, unsigned long flags)
{
    return syscall(SYS_perf_event_open, a, pid, cpu, group_fd, flags);
}

int lbr_collector_open(lbr_collector_t **out, pid_t pid, size_t mmap_pages)
{
    if (!out) { errno = EINVAL; return -1; }
    *out = NULL;

    /* power-of-two check */
    if (mmap_pages == 0 || (mmap_pages & (mmap_pages - 1)) != 0) {
        errno = EINVAL; return -1;
    }

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;

    struct perf_event_attr pea;
    memset(&pea, 0, sizeof(pea));
    pea.type           = PERF_TYPE_HARDWARE;
    pea.size           = sizeof(pea);
    pea.config         = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    pea.sample_period  = 10000;
    pea.sample_type    = PERF_SAMPLE_IP
                       | PERF_SAMPLE_TIME
                       | PERF_SAMPLE_BRANCH_STACK;
    pea.branch_sample_type = PERF_SAMPLE_BRANCH_USER
                           | PERF_SAMPLE_BRANCH_ANY
                           | PERF_SAMPLE_BRANCH_TYPE_SAVE;
    pea.disabled       = 1;
    pea.exclude_kernel = 1;
    pea.exclude_hv     = 1;
    pea.wakeup_events  = 1;
    pea.enable_on_exec = 0;

    int fd = (int)perf_event_open_syscall(&pea, pid, -1, -1, 0);
    if (fd < 0) return -1;

    size_t mmap_size = (mmap_pages + 1) * (size_t)page;
    void  *base     = mmap(NULL, mmap_size,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { close(fd); return -1; }

    lbr_collector_t *c = calloc(1, sizeof(*c));
    if (!c) { munmap(base, mmap_size); close(fd); return -1; }

    c->fd        = fd;
    c->mmap_base = base;
    c->mmap_size = mmap_size;
    c->data_size = mmap_pages * (size_t)page;
    c->data      = (uint8_t *)base + page;

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        int saved = errno;
        lbr_collector_close(c);
        errno = saved;
        return -1;
    }

    *out = c;
    return 0;
}

void lbr_collector_close(lbr_collector_t *c)
{
    if (!c) return;
    if (c->fd >= 0) {
        ioctl(c->fd, PERF_EVENT_IOC_DISABLE, 0);
        close(c->fd);
    }
    if (c->mmap_base) {
        munmap(c->mmap_base, c->mmap_size);
    }
    free(c);
}

/* Map PERF_BR_* (kernel uapi) to our BR_*. */
static uint32_t map_branch_type(uint32_t t)
{
    switch (t) {
    case 0:  return BR_UNKNOWN;
    case 1:  return BR_COND;
    case 2:  return BR_UNCOND;
    case 3:  return BR_IND;
    case 4:  return BR_CALL;
    case 5:  return BR_IND_CALL;
    case 6:  return BR_RET;
    case 7:  return BR_SYSCALL;
    case 8:  return BR_SYSRET;
    case 12: return BR_IRQ;
    default: return BR_UNKNOWN;
    }
}

/* Ring byte from an offset, wrapping modulo data_size. */
static inline uint8_t ring_byte(const lbr_collector_t *c, size_t off)
{
    return c->data[off & (c->data_size - 1)];
}

static void ring_copy(const lbr_collector_t *c,
                      size_t off, size_t len, void *dst)
{
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < len; i++) {
        d[i] = ring_byte(c, off + i);
    }
}

int lbr_collector_poll(lbr_collector_t *c,
                       lbr_branch_t    *buf,
                       size_t           buf_max,
                       int              timeout_ms)
{
    if (!c || (!buf && buf_max > 0)) { errno = EINVAL; return -1; }

    struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0) return -1;
    if (pr == 0) return 0;

    struct perf_event_mmap_page *page =
        (struct perf_event_mmap_page *)c->mmap_base;

    uint64_t head = __atomic_load_n(&page->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = page->data_tail;

    size_t written = 0;

    while (tail < head && written < buf_max) {
        size_t off = (size_t)tail & (c->data_size - 1);

        struct perf_event_header hdr;
        ring_copy(c, off, sizeof(hdr), &hdr);

        if (hdr.size < sizeof(hdr) || hdr.size > c->data_size) {
            /* malformed — reset consumer to producer and bail */
            tail = head;
            break;
        }

        uint8_t scratch[4096];
        uint8_t *rec;

        if (off + hdr.size <= c->data_size) {
            rec = c->data + off;
        } else if (hdr.size <= sizeof(scratch)) {
            ring_copy(c, off, hdr.size, scratch);
            rec = scratch;
        } else {
            tail += hdr.size;
            continue;
        }

        if (hdr.type == PERF_RECORD_SAMPLE) {
            const uint8_t *p = rec + sizeof(hdr);
            /* PERF_SAMPLE_IP */
            p += 8;
            /* PERF_SAMPLE_TIME */
            p += 8;
            /* PERF_SAMPLE_BRANCH_STACK: u64 nr, then nr entries */
            uint64_t nr;
            memcpy(&nr, p, 8); p += 8;

            uint64_t max_possible = (uint64_t)
                ((rec + hdr.size - p) / 24);
            if (nr > max_possible) nr = max_possible;

            for (uint64_t i = 0; i < nr && written < buf_max; i++) {
                uint64_t from, to, flags;
                memcpy(&from,  p,      8);
                memcpy(&to,    p + 8,  8);
                memcpy(&flags, p + 16, 8);
                p += 24;

                lbr_branch_t *b = &buf[written++];
                memset(b, 0, sizeof(*b));
                b->from      = from;
                b->to        = to;
                b->mispred   = (uint32_t)((flags >>  0) & 0x1);
                b->predicted = (uint32_t)((flags >>  1) & 0x1);
                b->in_tx     = (uint32_t)((flags >>  2) & 0x1);
                b->abort     = (uint32_t)((flags >>  3) & 0x1);
                b->cycles    = (uint32_t)((flags >>  4) & 0xFFFF);
                b->type      = (uint32_t)
                    map_branch_type((uint32_t)((flags >> 20) & 0xF));
            }
        }

        tail += hdr.size;
    }

    __atomic_store_n(&page->data_tail, tail, __ATOMIC_RELEASE);
    return (int)written;
}

#else /* !Linux x86-64: stubs so main.c still links for portability checks */

#include <errno.h>

struct lbr_collector { int unused; };

int lbr_collector_open(lbr_collector_t **out, pid_t pid, size_t mmap_pages)
{
    (void)pid; (void)mmap_pages;
    if (out) *out = NULL;
    errno = ENOSYS;
    return -1;
}

void lbr_collector_close(lbr_collector_t *c) { (void)c; }

int lbr_collector_poll(lbr_collector_t *c,
                       lbr_branch_t    *buf,
                       size_t           buf_max,
                       int              timeout_ms)
{
    (void)c; (void)buf; (void)buf_max; (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

#endif
