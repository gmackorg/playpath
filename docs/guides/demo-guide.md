# Math + ELA Demo Guide

The demo in this repo is an integration reference, not just a toy sample. Its purpose is to show studios how to structure a PlayPath-backed Roblox experience with a clean server/client boundary.

## What the demo demonstrates

- session creation and cleanup
- capability negotiation
- mode-based question routing for Math and ELA
- normalized question rendering on the client
- telemetry events emitted from the client and ingested on the server
- optional profile and standards calls
- grade submission at session end

## Project entrypoint

Use [demo.project.json](/Volumes/dev/roblox/playpath-sdk/demo.project.json) with Rojo:

```bash
rojo serve
```

Equivalent explicit forms:

```bash
rojo serve default.project.json
rojo serve demo.project.json
```

Studio mapping:
- `ReplicatedStorage/PlayPath`
- `ReplicatedStorage/PlayPathDemo`
- `ServerScriptService/PlayPathDemo`
- `StarterPlayer/StarterPlayerScripts/PlayPathDemoController`

## Demo architecture

### Server

- [PlayPathSessionManager.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/PlayPathSessionManager.lua)
  - owns SDK init, session cache, and thin wrappers
- [GameRouter.server.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/GameRouter.server.lua)
  - owns Remote handling and capability-aware command routing
- [MathFlow.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/MathFlow.lua)
  - chooses Math skill/context defaults
- [ELAFlow.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/ELAFlow.lua)
  - chooses ELA skill/context defaults

### Client

- [Controller.client.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Client/Controller.client.lua)
  - exposes `_G.DemoCommands`
  - renders questions
  - emits telemetry
- `Client/Renderers/*`
  - dispatches by normalized `question.kind`

## Running in mock mode

By default the demo boots in mock mode. That makes it safe for evaluation with no credentials.

Use these commands in Studio:

```lua
_G.DemoCommands.startMath()
_G.DemoCommands.autoSubmit()
_G.DemoCommands.hint()
_G.DemoCommands.skip()
_G.DemoCommands.submitGrade(1, 1)
_G.DemoCommands.endSession()
```

Repeat with:

```lua
_G.DemoCommands.startELA()
```

## Running against beta

Set attributes on `ServerScriptService/PlayPathDemo/GameRouter`:

- `PlayPathMockMode = false`
- `PlayPathBaseUrl = "https://beta.play.gmac.io"`
- `PlayPathGameKeyId = "<issued key>"`
- `PlayPathApiKeySecret = "<issued secret>"`
- `PlayPathGameId = "<your game id>"`

Then rerun the same command sequence.

## Expected runtime outputs

You should see:

- `Session started`
- `Pairing code` when unlinked
- `New question`
- `Answer result`
- `Hint`
- `Question skipped`
- `Grade`

Use `getCapabilities`, `getProfile`, and `getStandards` to verify optional surfaces:

```lua
_G.DemoCommands.getCapabilities()
_G.DemoCommands.getProfile("<profile-id>")
_G.DemoCommands.getStandards({ "<skill-id>" }, "TEKS")
```

## How studios should adapt the demo

Replace:
- command-bar driven answer submission
- console-style rendering
- demo skill selection defaults

Keep:
- server-owned SDK boundary
- client/server Remote contract
- capability gating
- session cleanup on `PlayerRemoving`
- normalized question renderer dispatch
