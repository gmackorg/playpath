# PlayPath Math/ELA Demo (v1)

This folder contains a reference demo for external studios evaluating the PlayPath Roblox SDK.

It is intentionally split into server session orchestration, a Remote-based game boundary, and client render/command handling so teams can lift the architecture into a real game instead of copying isolated snippets.

## What it includes

- Server session manager wrapper: `Server/PlayPathSessionManager.lua`
- Flow routing and action dispatch: `Server/GameRouter.server.lua`
- Math and ELA request shaping: `Server/MathFlow.lua`, `Server/ELAFlow.lua`
- Shared remotes and message contracts: `Replicated/Remotes.lua`, `Replicated/QuestionTypes.lua`
- Client command loop + renderer abstraction: `Client/Controller.client.lua`, `Client/Renderers/*`

## Why this demo exists

The demo is designed to answer three studio questions quickly:

1. What is the recommended server/client boundary for PlayPath in Roblox?
2. How do Math and ELA question flows differ while using the same SDK surface?
3. What does a launch-ready integration need besides just `getNextQuestion()` and `submitAnswer()`?

## Demo architecture

### Server responsibilities

- initialize the SDK
- keep credentials server-side
- own session lifecycle
- own capability checks
- own optional profile, standards, and grade calls

### Client responsibilities

- render normalized questions
- collect player input
- emit telemetry intent
- call server commands through Remotes only

This split is the recommended production architecture.

## Core v1 API calls covered

- `POST /api/v1/sessions` via `startSession`
- `POST /api/v1/questions` via `requestQuestion`
- `POST /api/v1/questions/{id}` via `submitAnswer`
- `POST /api/v1/questions/{id}/skip` via `skipQuestion`
- `POST /api/v1/hints` via `requestHint`
- `POST /api/v1/events` via event tracking in `trackEvent`
- Telemetry uses the dedicated `Remotes.TelemetryEvent` RemoteEvent (client emits `type`, `data`, `properties`).
- `POST /api/v1/link` via `submitPairing`
- `POST /api/v1/grades` via `submitGrade`
- `GET /api/v1/profile/{profileId}` via `getProfile`
- `POST /api/v1/standards` via `getStandards`
- `GET /api/v1/capabilities` via `getCapabilities`
- `GET /api/v1/sessions/{sessionId}` via `getSessionStatus`

## Running the demo

1. Sync `demo.project.json` with Rojo:
   - `rojo serve`
   - or `rojo serve default.project.json`
   - or `rojo serve demo.project.json`
2. Open the place in Roblox Studio and connect Rojo.
3. The demo maps:
   - `ReplicatedStorage/PlayPath`
   - `ReplicatedStorage/PlayPathDemo/*`
   - `ServerScriptService/PlayPathDemo/*`
   - `StarterPlayer/StarterPlayerScripts/PlayPathDemoController`
4. In Studio output, watch flow logs for:
   - sessionStarted
   - sessionStarted.capabilities (feature gates)
   - requestQuestion
   - question_viewed / hint_requested / question_skipped / answer events
   - submitAnswer / skipQuestion / requestHint
   - submitPairing
   - submitGrade
5. In the client command bar or Studio MCP client context, use `_G.DemoCommands`:
   - `_G.DemoCommands.startMath()` for math mode
   - `_G.DemoCommands.startELA()` for ELA mode
   - `_G.DemoCommands.autoSubmit()` to auto-answer current question
   - `_G.DemoCommands.submit(answer)` for manual answer
   - `_G.DemoCommands.hint()` to request a hint
   - `_G.DemoCommands.skip()` to skip the current question
   - `_G.DemoCommands.getCapabilities()` to inspect feature availability
   - `_G.DemoCommands.submitGrade(score, maxScore)` after each run
   - `_G.DemoCommands.endSession()` to close the current session

The demo now also renders an in-game control panel so studios can evaluate the flow without relying on command bar access. `_G.DemoCommands` remains available for MCP and scripted evaluation.

## Configuring mock vs beta smoke

Set attributes on `ServerScriptService/PlayPathDemo/GameRouter`:

- `PlayPathMockMode`: `true` for local mock flow, `false` for beta/prod
- `PlayPathBaseUrl`: `https://beta.play.gmac.io` for beta smoke
- `PlayPathGameKeyId`: backend-issued key id
- `PlayPathApiKeySecret`: backend-issued secret
- `PlayPathGameId`: optional game identifier passed in question context
- `PlayPathLogLevel`: `warn` or `debug`

## v1 demo acceptance checklist

From one running server/client pair, verify:

1. Both modes can start (`sessionStarted` appears with `capabilities` payload).
2. `requestQuestion` returns `question` and each mode receives supported types:
   - Math: `multiple_choice`, `number_input`, `fraction_visual`
   - ELA: `multiple_choice`, `number_input`
3. Core loop is exercised:
   - `submitAnswer`, `skipQuestion`, `requestHint`
4. Profile/standards capabilities are honored when available.
5. `session:getProfile`, `getStandards`, `getSessionStatus`, `submitGrade` all return a structured payload.
6. `question_viewed`, `hint_requested`, `question_skipped`, `answer` events are ingested through `TelemetryEvent`.

## External studio walkthrough

### Phase 1: local evaluation

1. Run in mock mode.
2. Start Math and ELA sessions.
3. Use `autoSubmit`, `hint`, and `skip`.
4. Confirm telemetry and cleanup.

### Phase 2: backend verification

1. Disable mock mode and point to beta.
2. verify `createSession`, question loop, and pairing against real credentials
3. verify `getCapabilities`
4. verify `getProfile` and `getStandards` only when supported

### Phase 3: production adaptation

Replace command-bar testing with:

- game UI
- your own Remote contracts
- your own skill routing strategy
- your own grade completion criteria

Keep the server-owned session manager pattern.

## Recommended next steps for a real game

- Add UI buttons and input widgets tied to `Controller.client.lua` commands.
- Replace auto-answering with per-question renderer input.
- Route `question.correct` and `feedback` into gameplay outcomes.
- Store your own analytics alongside PlayPath events when needed.
- Add a game-specific wrapper module so the rest of your game never talks to the SDK directly.
