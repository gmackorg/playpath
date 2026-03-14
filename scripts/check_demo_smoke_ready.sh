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

check_file "demo.project.json"
check_file "demo/math-ela/Server/GameRouter.server.lua"
check_file "demo/math-ela/Client/Controller.client.lua"

check_contains "demo.project.json" "\"PlayPathDemo\""
check_contains "demo/math-ela/Server/GameRouter.server.lua" "ReplicatedStorage:WaitForChild(\"PlayPathDemo\")"
check_contains "demo/math-ela/Server/GameRouter.server.lua" "script:WaitForChild(\"PlayPathSessionManager\")"
check_contains "demo/math-ela/Server/GameRouter.server.lua" "script:WaitForChild(\"MathFlow\")"
check_contains "demo/math-ela/Server/GameRouter.server.lua" "script:WaitForChild(\"ELAFlow\")"
check_contains "demo/math-ela/Client/Controller.client.lua" "ReplicatedStorage:WaitForChild(\"PlayPathDemo\")"
check_contains "demo/math-ela/Client/Controller.client.lua" "_G.DemoCommands = DemoCommands"

echo "PASS: demo smoke wiring is present"
