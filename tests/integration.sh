#!/usr/bin/env bash
#
# integration.sh — end-to-end test of the replay pipeline.
# Builds the replay harness, feeds it the fixtures, and asserts on the
# resulting JSON-line reports (score/flags).
#
# Exit non-zero on any failure.

set -euo pipefail

cd "$(dirname "$0")"

CC=${CC:-cc}
$CC -std=c99 -Wall -Wextra -O2 -g -I../include \
    -o replay replay.c ../src/analyzer.c ../src/format.c -lm

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

run() {
    local fixture=$1
    local expect=$2
    # replay exits with 3 on suspicious (our own canary convention);
    # that's not a harness failure — let the grep below decide.
    ./replay "fixtures/$fixture" --jsonl > "$out/$fixture.json" || true
    if ! grep -q "\"suspicious\":$expect" "$out/$fixture.json"; then
        echo "FAIL: $fixture expected suspicious=$expect"
        cat "$out/$fixture.json"
        exit 1
    fi
    echo "PASS: $fixture (suspicious=$expect)"
}

run clean.log false
run rop.log   true
run jop.log   false   # ind-call alone should not cross the 0.70 verdict threshold

echo
echo "integration tests passed"
