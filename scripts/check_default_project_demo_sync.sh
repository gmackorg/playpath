#!/bin/sh
set -eu

repo_root="${1:-.}"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

check_contains() {
  file="$1"
  pattern="$2"
  if ! rg -F -q "$pattern" "$repo_root/$file"; then
    fail "$file missing pattern: $pattern"
  fi
}

check_contains "default.project.json" "\"ReplicatedStorage\""
check_contains "default.project.json" "\"PlayPathDemo\""
check_contains "default.project.json" "\"ServerScriptService\""
check_contains "default.project.json" "\"StarterPlayer\""
check_contains "default.project.json" "\"PlayPathDemoController\""

echo "PASS: default.project.json exposes the demo tree"
