#!/usr/bin/env bash
#
# Build the aesc CLI (unless AESC_BIN is set) and run the Ruby/minitest
# end-to-end suite. Any arguments are passed through to minitest, e.g.:
#
#   tests/e2e/run.sh                  # run the whole suite
#   tests/e2e/run.sh -n /round_trip/  # run cases matching a name
#   tests/e2e/run.sh --seed 1234      # fix the randomization seed
#
# Test a non-default binary:
#   AESC_BIN=target/release/aesc tests/e2e/run.sh
#
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${AESC_BIN:-}" ]]; then
  echo "Building aesc CLI (debug) ..."
  cargo build --quiet -p aesc-cli
fi

exec ruby "${HERE}/runner.rb" "$@"
