# Security Policy

## Scope

`lbr-hunt` is a defensive tool. It reads the Intel LBR / AMD BRS facility
via `perf_event_open(2)` and scores branch patterns for ROP / JOP signals.
It does **not** modify target processes, does **not** inject code, does
**not** require a kernel module, and holds no offensive payload.

## Reporting a vulnerability

If you believe you have found a security issue in `lbr-hunt` itself —
memory safety bug in the collector or analyzer, confused-deputy in the
CLI privilege handling, or a bypass of a documented guarantee — please
email the maintainer directly rather than opening a public issue:

**Baurzhan Atynov** — `bauratynov@gmail.com`

Please include:
- a description of the issue,
- a reproducer (crash input, synthetic branch log, or command line),
- the affected commit / version,
- your expectation of the correct behaviour.

You will get a response within 72 hours. Fixes are prioritised over
features.

## Non-issues

- Detection misses on novel ROP variants are **not** security bugs;
  they are detection-quality bugs. Please open a regular issue with
  a replayable fixture.
- False positives on exotic but benign traffic (JITs, aggressive
  tail-call optimisation, coroutines) are likewise detection-quality
  issues. Please attach a trace.

## Out of scope

- Bugs in the Linux kernel's `perf_event_open` implementation.
- Bugs in hardware LBR / BRS sampling. Report those to the vendor.
- Configuration issues (CAP_PERFMON, `perf_event_paranoid`). See
  the README for the supported deployment model.
