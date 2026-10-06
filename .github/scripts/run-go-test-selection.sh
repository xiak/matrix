#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 || -z "$1" ]]; then
  echo "usage: run-go-test-selection.sh TestOne[,TestTwo...] go-test-arguments..." >&2
  exit 2
fi

expected_csv="$1"
shift
log_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/matrix-go-test-selection-XXXXXX.json")"
trap 'rm -f "$log_file"' EXIT

# `go test` exits successfully when an anchored selector matches no test or
# when the selected top-level test skips. Those outcomes must not satisfy a
# real-runtime gate whose fixture was deliberately removed from the generic
# storage lane.
go test -json "$@" | tee "$log_file"

IFS=',' read -r -a expected_tests <<< "$expected_csv"
for test_name in "${expected_tests[@]}"; do
  if [[ ! "$test_name" =~ ^Test[A-Za-z0-9_]+$ ]]; then
    echo "invalid expected top-level test name: $test_name" >&2
    exit 2
  fi
  if ! grep -F '"Action":"run"' "$log_file" | grep -F "\"Test\":\"${test_name}\"" >/dev/null; then
    echo "expected top-level test did not run: $test_name" >&2
    exit 1
  fi
  if grep -F '"Action":"skip"' "$log_file" | grep -F "\"Test\":\"${test_name}\"" >/dev/null; then
    echo "expected top-level test skipped: $test_name" >&2
    exit 1
  fi
  if ! grep -F '"Action":"pass"' "$log_file" | grep -F "\"Test\":\"${test_name}\"" >/dev/null; then
    echo "expected top-level test did not pass: $test_name" >&2
    exit 1
  fi
done
