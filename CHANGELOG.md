# Changelog

All notable changes to `lbr-hunt` are listed here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-17

Initial public release. First end-to-end usable slice of the tool.

### Added
- **Analyzer core** (`src/analyzer.c`). Pure, O(n), allocation-free.
  Six heuristics weighted into a single verdict score; thresholds
  exposed via `lbr_config_t`.
- **Collector** (`src/collector.c`). `perf_event_open` with
  `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`, branch-stack sampling,
  `BRANCH_TYPE_SAVE`; mmapped ring buffer with wrap-safe decoding.
- **CLI** (`src/main.c`). Attach-to-PID and fork-and-exec modes,
  text and JSON-Lines output, full tuning surface for all thresholds,
  `--stop-on-first` for canary integration.
- **Replay harness** (`tests/replay.c`). Log-file driven analyzer for
  reproducible traces and fixture authoring.
- **Integration tests**. Three hand-written fixtures (clean, ROP, JOP)
  with documented expected verdicts.
- **Unit tests**. Eight tests covering empty input, balanced traffic,
  synthetic ROP, JOP, threshold tuning, unpaired rets, short-gadget
  boundary, monotonicity of score in density.
- **CI**. GitHub Actions: gcc + clang on ubuntu-22.04 and ubuntu-24.04,
  cppcheck static analysis, AddressSanitizer + UBSan unit tests.
- **Docs**. README with architecture, heuristics, usage; SECURITY.md
  reporting procedure.

### Known limitations
- Linux x86-64 only at runtime. Analyzer / replay build anywhere.
- Branch type field requires Linux >= 5.11 (`PERF_SAMPLE_BRANCH_TYPE_SAVE`).
  On older kernels every branch decodes as `BR_UNKNOWN`; the density
  heuristic still works but the JOP / COP signals do not.
- No binary-aware target resolution; mismatched-call detection works
  only from the call/ret counts inside the current window.

### Next
- 0.2.0: reading `/proc/<pid>/maps` + `/proc/<pid>/mem` to resolve
  branch targets, validating that returns land on call-preceded bytes.
- 0.2.0: multi-thread attach (one fd per tid via `pid > 0, cpu = -1`
  with the `PERF_FLAG_FD_CLOEXEC` + inherit settings).
- 0.3.0: Prometheus metrics exporter; long-running daemon mode.
