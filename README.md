# lbr-hunt

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: C99](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform: Linux x86-64](https://img.shields.io/badge/Platform-Linux%20x86__64-green.svg)](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)

Runtime ROP / JOP detector built on the Intel Last Branch Record
facility. Attaches to a running process via `perf_event_open`, streams
the CPU's 32‑entry branch-stack through the kernel ring buffer, and
scores each sample window against a bundle of compressed heuristics.

> **Status:** Sprint 1 complete — pure analyzer core + unit tests.
> Sprints 2–5 add the `perf_event_open` collector, CLI, CI, and docs.

---

## Why

Control‑Flow Hijacking via return-oriented programming stays the
primary mechanism for turning a memory-corruption bug into code
execution. Modern mitigations (shadow stacks, CET IBT) are excellent
where available, but large chunks of the fleet — older CPUs, embedded
targets, legacy binaries — ship without them.

The Intel LBR (since Nehalem / Haswell) keeps a rolling record of the
last 32 taken branches per core. ROP chains leave a distinctive
signature in that record: dense `RET`s, short inter-gadget distances,
tight target clusters, call/ret imbalance. `lbr-hunt` reads that
record from userspace and scores it. No binary instrumentation. No
recompilation of the target. No kernel module.

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                target process (victim)                    │
 │       ─── taken branches recorded by CPU LBR ───          │
 └──────────────────────────────────────────────────────────┘
                              │ perf_event_open
                              │ PERF_SAMPLE_BRANCH_STACK
                              ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   kernel ring buffer                      │
 │           (mmapped, read without syscalls)                │
 └──────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌──────────────────────────────────────────────────────────┐
 │  collector.c — decode PERF_RECORD_SAMPLE, fill            │
 │                 lbr_branch_t[] window                     │
 └──────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌──────────────────────────────────────────────────────────┐
 │  analyzer.c — PURE heuristics, no I/O, no allocation      │
 │                 → lbr_report_t { score, flags, ... }      │
 └──────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌──────────────────────────────────────────────────────────┐
 │  format.c — text / JSON-lines output to stdout / log      │
 └──────────────────────────────────────────────────────────┘
```

## Heuristics (what the analyzer looks for)

| # | Feature                          | Weight | Signal                                       |
|---|----------------------------------|-------:|----------------------------------------------|
| 1 | Return density                   |  0.35  | ROP windows are >60% `RET`                   |
| 2 | Short-gadget pair count          |  0.25  | Adjacent `RET`s with source IPs <32B apart   |
| 3 | Tight target clustering          |  0.15  | `RET` targets span <64 KB                    |
| 4 | Max consecutive `RET` chain      |  0.10  | Clean code rarely chains 5+ rets             |
| 5 | Indirect-call density            |  0.10  | JOP / COP signal                             |
| 6 | Unpaired-ret fraction            |  0.05  | Rets without preceding call in window        |

Each contribution is bounded; the final score is clamped to `[0, 1]`
and compared against `score_threshold` (default `0.70`). Thresholds
and weights are exposed in `lbr_config_t`.

## Building

```bash
make            # builds lbr-hunt binary (requires Linux to be useful)
make test       # runs the analyzer unit tests (portable)
make clean
```

Tests are pure C99 and build on macOS / Windows MinGW / any libc‑free
sandbox — the analyzer core has no `perf_event_open` dependency.

## Usage (once Sprint 2 lands)

```bash
# attach to an existing process
sudo ./lbr-hunt -p 1234

# attach and emit JSON lines
sudo ./lbr-hunt -p 1234 --jsonl > events.jsonl

# fire a command under supervision
sudo ./lbr-hunt -- ./victim arg1 arg2

# tune thresholds
sudo ./lbr-hunt -p 1234 \
    --ret-density 0.55 \
    --min-chain   6    \
    --score-threshold 0.8
```

Requires one of:
- `root`
- `CAP_PERFMON` capability, or
- `kernel.perf_event_paranoid <= 2`

## Testing philosophy

The analyzer is deliberately separated from the kernel interface so
every heuristic can be tested on any host. `tests/test_analyzer.c`
feeds synthetic `lbr_branch_t[]` windows — a balanced call/ret
sequence, a synthetic ROP chain, an indirect-call‑heavy JOP trace —
and asserts against the resulting `lbr_report_t`.

## Roadmap

- [x] Sprint 1: analyzer core + unit tests
- [ ] Sprint 2: `perf_event_open` collector + ring-buffer parser
- [ ] Sprint 3: CLI + JSON-lines output + process-attach mode
- [ ] Sprint 4: integration test with a synthetic ROP binary
- [ ] Sprint 5: CI (clang + gcc), man page, packaging, release tag

## References

- Intel SDM Vol. 3B, Chapter 18 — "Debug, Branch Profile, TSC, and Intel Resource Director Technology".
- `perf_event_open(2)` — `PERF_SAMPLE_BRANCH_STACK`, `PERF_SAMPLE_BRANCH_TYPE`.
- V. Pappas et al., "Transparent ROP Exploit Mitigation using Indirect Branch Tracing", USENIX Security 2013.
- Y. Cheng et al., "ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks", NDSS 2014.
- Paired with [GhostRing](https://github.com/bauratynov/GhostRing) for ring‑1 kernel integrity monitoring.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Baurzhan Atynov** — [bauratynov@gmail.com](mailto:bauratynov@gmail.com)
