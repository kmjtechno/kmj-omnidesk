#!/usr/bin/env bash
# Runs a bounded fuzzing pass over the signed-entitlement boundary.
#
# The signed entitlement is the gate between an untrusted server response and
# paid product access, so it is the one boundary worth fuzzing continuously.
# A short pass is a regression gate, not a substitute for a long campaign:
# it proves known-shaped inputs still fail closed, it does not replace a
# dedicated fuzzing run whose corpus is kept.
#
# Usage:
#   scripts/run_fuzz_smoke.sh [seconds]
#
# Requires a nightly toolchain (cargo-fuzz targets need sanitizer support).
set -euo pipefail

SECONDS_TO_RUN="${1:-120}"
TARGET="signed_entitlement"

if ! cargo fuzz --version >/dev/null 2>&1; then
  echo "cargo-fuzz is not installed: cargo install cargo-fuzz --locked" >&2
  exit 1
fi

# Prefer the nightly toolchain, since that is what cargo-fuzz builds with.
# Match the *active* toolchain's host triple so a machine with several
# nightlies installed does not silently build for a different target than the
# one whose std library is present.
HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
NIGHTLY="$(rustup toolchain list | awk -v host="$HOST" '/^nightly/ && index($0, host) {print $1; exit}')"
if [ -z "$NIGHTLY" ]; then
  NIGHTLY="$(rustup toolchain list | awk '/^nightly/ {print $1; exit}')"
fi
if [ -z "$NIGHTLY" ]; then
  echo "a nightly toolchain is required for sanitizer builds" >&2
  exit 1
fi
echo "using nightly toolchain: $NIGHTLY (host $HOST)"

CORPUS_DIR="fuzz/corpus/$TARGET"
mkdir -p "$CORPUS_DIR"

echo "Fuzzing '$TARGET' for ${SECONDS_TO_RUN}s with $NIGHTLY"
cargo "+$NIGHTLY" fuzz run "$TARGET" -- \
  -max_total_time="$SECONDS_TO_RUN" \
  -max_len=16384 \
  -timeout=10 \
  "$CORPUS_DIR"

# A crash writes an artifact; treat any artifact as a gate failure rather
# than letting a future run silently absorb it.
ARTIFACTS="fuzz/artifacts/$TARGET"
if [ -d "$ARTIFACTS" ] && [ -n "$(ls -A "$ARTIFACTS" 2>/dev/null)" ]; then
  echo "fuzzing produced crash artifacts in $ARTIFACTS" >&2
  ls -la "$ARTIFACTS" >&2
  exit 1
fi

echo "fuzz gate passed: no crashes in ${SECONDS_TO_RUN}s"