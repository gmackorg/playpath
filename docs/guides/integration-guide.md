# Integration Guide

This guide describes the recommended integration shape for external Roblox games.

## Architectural rule

Keep PlayPath server-owned.

The SDK holds credentials, signs requests, manages retries, and owns session lifecycle. Client code should only receive normalized question state and send player intent back to the server through Remotes.

## Recommended integration layers

### 1. SDK boundary

Create one server module that wraps:

- `PlayPath.init`
- `PlayPath.createSession`
- `session:getNextQuestion`
- `session:submitAnswer`
- `session:skipQuestion`
- `session:getHint`
- `session:trackEvent`
- `session:endSession`

This gives your gameplay code one stable interface even if the upstream contract evolves.

Production wrapper sample:
- [PlayPathGameService.lua](/Volumes/dev/roblox/playpath-sdk/examples/production/Server/PlayPathGameService.lua)

### 2. Game flow boundary

Create game-specific orchestration that decides:

- when to request the next question
- which `skill` and `context` values to send
- how to transform a correct/incorrect answer into gameplay consequences
- when to request hints, standards, grades, or profile info

### 3. Client rendering boundary

The client should render normalized questions by `question.kind`:

- `multiple_choice`
- `number_input`
- `fraction_visual`
- `angle_input`
- `number_line`

Unsupported types should fail soft: show a fallback panel and allow skip.

## Core runtime loop

1. Server creates session for player.
2. Server requests question with optional `skill` and `context`.
3. Server sends normalized question to client.
4. Client renders and captures answer.
5. Client sends answer intent to server.
6. Server calls `submitAnswer`.
7. Server emits game consequences and requests next question when appropriate.
8. Server tracks telemetry throughout.
9. Server ends session on player leave or match completion.

## Pairing and identity

Expect both linked and anonymous starts.

If `session.linked == false`:
- show the pairing code
- optionally allow `session:verifyPairingCode(code)`
- keep gameplay functional even before linking unless your experience requires identity

Use `session:getProfile()` or `PlayPath.getProfile(profileId)` when your UX needs to confirm current link status.

## Standards and capabilities

Treat capabilities as feature negotiation.

At boot or session start:
- call `PlayPath.getCapabilities()`
- cache the response
- gate optional features such as standards lookup and profile introspection

Only call `getStandards()` when the capability payload indicates support, or when your backend contract guarantees it for the environment.

## Telemetry recommendations

Track at minimum:

- `question_viewed`
- `answer`
- `hint_requested`
- `question_skipped`
- `session_end`

Include:
- `questionId`
- `skillId`
- `difficulty`
- `responseTimeMs` when available

## Implementation references

- Demo server boundary: [PlayPathSessionManager.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/PlayPathSessionManager.lua)
- Demo router: [GameRouter.server.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Server/GameRouter.server.lua)
- Demo client controller: [Controller.client.lua](/Volumes/dev/roblox/playpath-sdk/demo/math-ela/Client/Controller.client.lua)
- Production wrapper sample: [PlayPathGameService.lua](/Volumes/dev/roblox/playpath-sdk/examples/production/Server/PlayPathGameService.lua)
- HTTP contract: [ROBLOX_SDK_API.md](/Volumes/dev/roblox/playpath-sdk/ROBLOX_SDK_API.md)
