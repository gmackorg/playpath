#!/bin/sh
set -eu

repo_root="${1:-.}"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

check_file() {
  file="$1"
  [ -f "$repo_root/$file" ] || fail "missing $file"
}

check_contains() {
  file="$1"
  pattern="$2"
  if ! rg -F -q "$pattern" "$repo_root/$file"; then
    fail "$file missing pattern: $pattern"
  fi
}

check_file "demo/math-ela/Client/Controller.client.lua"
check_file "examples/production/Server/PlayPathGameService.lua"
check_file "docs/guides/integration-guide.md"

check_contains "demo/math-ela/Client/Controller.client.lua" "createDemoGui()"
check_contains "demo/math-ela/Client/Controller.client.lua" "screenGui.Name = \"PlayPathDemoGui\""
check_contains "demo/math-ela/Client/Controller.client.lua" "submitButton.MouseButton1Click:Connect"
check_contains "examples/production/Server/PlayPathGameService.lua" "function M.startSession"
check_contains "examples/production/Server/PlayPathGameService.lua" "function M.submitAnswer"
check_contains "docs/guides/integration-guide.md" "Production wrapper sample"

echo "PASS: partner package artifacts are present"
