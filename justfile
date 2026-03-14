set shell := ["/bin/bash", "-eu", "-o", "pipefail", "-c"]

# Prefer Aftman-managed tool shims when available.
AFTMAN_SHIMS := env_var("HOME") + "/.aftman/bin"
export PATH := AFTMAN_SHIMS + ":" + env_var("PATH")

default:
	just --list

# If Aftman shims are not writable, run this once.
fix-aftman-perms:
	chmod u+w "$HOME/.aftman/bin"/* || true


install: fix-aftman-perms
	aftman install
	wally install

setup: install

test-generic:
	lua tests/run.lua

fmt:
	stylua src/PlayPath.lua

fmt-check:
	stylua --check src/PlayPath.lua

lint:
	selene --allow-warnings src/PlayPath.lua

lint-strict:
	selene src/PlayPath.lua

build out="PlayPath.rbxm":
	rojo build package.project.json -o {{out}}

demo-build out="PlayPathDemo.rbxlx":
	rojo build default.project.json -o {{out}}

demo-serve:
	rojo serve default.project.json

ci: install fmt-check lint build

verify: ci

clean:
	rm -f PlayPath.rbxm
