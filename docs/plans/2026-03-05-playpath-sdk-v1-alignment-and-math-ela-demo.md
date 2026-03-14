# PlayPath v1 Alignment and Math/ELA Demo Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** ship a deterministic, contract-aligned PlayPath v1 SDK surface and a first playable demo that exercises the core API in both Math and ELA workflows.

**Architecture:** keep `src/PlayPath.lua` as the single transport + session state surface; add a lightweight demo boundary that uses only public SDK APIs through Remotes. The server side owns API credentials and session lifecycle; the client owns render/routing/UX.

**Tech Stack:** Luau (ServerScriptService + Players service), Roblox RemoteEvents/RemoteFunctions, Promise-based async, minimal UI in StarterGui.

---

## 1) Source-of-truth contract check

Use the canonical reference in `../playpath/docs/ROBLOX_SDK_API.md` and keep this repo docs aligned.

- Required endpoints: `time`, `sessions`, `questions`, `hints`, `events`, `link`, `unlink`, `profile`, `standards`, `grades`, `sessions/{sessionId}`, `capabilities`.
- v1 question types documented for Math/ELA: `multiple_choice`, `number_input`, `fraction_visual`, `angle_input`, `number_line`; plus `matching`/`sorting` reserved.
- Canonical signatures, headers, and `x-request-id` handling already partially present; verify all request/response fields match.

### 1.1 Execution status (now)

- ✅ SDK parity foundations in `src/PlayPath.lua` are in place:
  - `responseTimeMs` supported on `submitAnswer`.
  - `personalization` returned from `getNextQuestion`.
  - `trackEvent` normalizes both `data` and `properties`.
  - `session:getProfile()` available.
  - Mock tests now cover capabilities, session lifecycle, question/answer/hint/skip/events/standards/grade/profile/status.
- ✅ Demo boundary now includes capability-aware routing and math/ela mode controls:
  - `PlayPathSessionManager.lua` caches normalized capabilities.
  - `GameRouter.server.lua` gates `getProfile` + `getStandards` from capabilities and normalizes launch mode.
  - `Controller.client.lua` includes mode-specific start and auto-submit helper for MCP-driven flow.
- ✅ Demo docs now contain an explicit v1 coverage checklist and command touchpoints.
- ✅ Repository docs are now aligned with v1 launch shape:
  - `README.md` includes production/beta `baseUrl` setup and Math/ELA usage examples.
  - `ROBLOX_SDK_API.md` now includes full endpoint inventory and core request/response shapes.

### 1.2 Current status snapshot (2026-03-05)

- Done in `src/PlayPath.lua`:
  - v1 path constants and request signing.
  - API methods for `getProfile`, `getStandards`, `getSessionStatus`, `unlinkProfile`.
  - Question normalization to `{id, content, prompt, choices, ...}`.
  - New question kinds and fields (`skillId`, `difficulty`, `hints`, `expectedTimeMs`).
  - Mock endpoints for profile/standards/events/idempotency/grades.
  - Retry/backoff honoring `Retry-After` for `429`.

- Remaining alignment risks:
  - [x] Mock session create response linked behavior has been made deterministic.
  - [x] Capabilities/features are now normalized and gated for demo surfaces.
  - [x] Response wrappers were expanded in mock checks and `runMockTests`.
  - [ ] Close the loop with live-beta smoke verification and UI command wiring for full showcase.

### 1.3 Checklist walk-through status (2026-03-05)

- [x] Contract and DTO parity review completed for v1 launch surface.
- [x] `getNextQuestion` request/response shape aligned to v1 options/context flow.
- [x] `submitAnswer`, `skipQuestion`, `getHint` payloads include idempotency and optional fields.
- [x] Event payload normalization and allowlist warning behavior in place.
- [x] HTTP error/request-id/Retry-After handling covers launch-critical mappings.
- [x] Mock parity improvements and launch-critical mock test chain implemented.
- [x] SDK and API docs aligned with v1 methods, endpoints, and content types.
- [x] Demo server/client path supports capability-aware Math + ELA API flow.
- [ ] Manual Studio/MCP smoke pass against mock + beta endpoint still required before launch sign-off.

Smoke gate (manual, required before v1 launch):
1. Run `DemoCommands.startMath()` and verify question loop + hint/skip + grade.
2. Run `DemoCommands.startELA()` and verify question loop + hint/skip + grade.
3. Verify `DemoCommands.getCapabilities()`, `getProfile(profileId)`, `getStandards(skillIds, framework)` response handling.
4. Confirm `question_viewed`, `answer`, `hint_requested`, `question_skipped`, `session_end` telemetry reaches server via `TelemetryEvent`.
5. End both sessions and confirm cleanup path calls `session:endSession()` on `PlayerRemoving`.

---

## 2) v1 SDK alignment work

### Task 1: Tighten contract diff for request/response DTOs (no behavior change, just stricter compatibility)

**Files:**
- `src/PlayPath.lua`
- `ROBLOX_SDK_API.md` (reference only)

**Actions:**
1. Add/confirm missing type aliases for v1 payloads:
   - `LinkResult` includes optional `student` + `error` compatibility.
   - `AnswerResult` includes `nextReviewAt`.
   - `GradeResult.status` union with documented reason codes.
2. Keep legacy fallback compatibility but expose v1 names:
   - `question.type` and `question.content` are primary parse path.
   - legacy `prompt/choices` still supported.
3. Ensure all new properties are nullable/optional so existing backends still work.

### Task 2: Correct real-session behavior in `SessionImpl:getNextQuestion`

**Files:**
- `src/PlayPath.lua`

**Actions:**
1. Keep current options-based input, but explicitly support only v1 fields:
   - `skill` requested.
   - `context` passthrough.
   - `game` set from configured `gameId`.
2. Remove any dependence on undocumented legacy `count` behavior in request payload.
3. Return `{ personalization, question, questions, raw }` with `question` normalized and raw passthrough.
4. Add guard for malformed response (table check + fail-closed decode-safe fallback).

### Task 3: Question submit and skip payload conformance

**Files:**
- `src/PlayPath.lua`

**Actions:**
1. `submitAnswer`:
   - Keep required `sessionId`, optional `studentId`, `responseTimeMs`.
   - Send optional `difficulty` when provided.
   - Ensure `idempotencyKey` always generated.
2. `skipQuestion`:
   - Keep optional `reason`, default `other`.
   - Ensure request body has `sessionId`, optional `studentId`, `idempotencyKey`.
3. `getHint`:
   - Keep default `hintIndex` fallback `0`.
   - Include `idempotencyKey`.
4. Add internal helper-level test cases (mock or comments) for:
   - integer vs string answer fields.
   - omitted optional `responseTimeMs`.

### Task 4: Event API hardening

**Files:**
- `src/PlayPath.lua`

**Actions:**
1. Validate canonical event types against allowlist and log unknowns without dropping.
2. Normalize `LearningEvent` to include both `data` and `properties`.
3. Ensure event payload always has:
   - `type`, optional `questionId`, `idempotencyKey`, `timestamp`.
4. Keep queue drop/flush behavior:
   - batch size cap with oldest-dropping policy.
5. Add explicit tests:
   - event with `properties` only.
   - event with both `data` and `properties`.

### Task 5: HTTP error and transport parity completion

**Files:**
- `src/PlayPath.lua`

**Actions:**
1. Keep mapping for `400,401,403,404,409,413,429,500,503`.
2. Preserve `x-request-id` from response headers into `PlayPathError.requestId`.
3. Ensure `Retry-After` parse path is case-insensitive in headers.
4. Preserve request IDs from transport errors for support triage.

### Task 6: Mock parity audit/fix

**Files:**
- `src/PlayPath.lua`

**Actions:**
1. Fix linked status in `POST /api/v1/sessions` mock:
   - Return `linked = student ~= nil`.
2. In mock `POST /api/v1/sessions/{sessionId}`:
   - Return `success: true`, `sessionId`, and match real contract.
3. In mock `GET /api/v1/profile/{profileId}`:
   - Return `{linked, student}` with `student=null` when unlinked.
4. In mock `POST /api/v1/standards`:
   - Respect `frameworkCode` filter if present.
5. In mock `POST /api/v1/link`:
   - Keep case-insensitive pairing and per-session binding.
6. Add reset helper assertions for `_eventHistory` and session tables.

### Task 7: Self-test coverage for launch-critical paths

**Files:**
- `src/PlayPath.lua`

**Actions (expand `_internal.runMockTests()`):**
1. Validate all core v1 methods:
   - `getServerTime()`, `createSession()`, `getNextQuestion()`, `submitAnswer()`, `skipQuestion()`, `getHint()`, `trackEvent()->flush()`, `submitGrade()`, `getProfile()`, `getStandards()`, `getCapabilities()`, `getSessionStatus()`, `endSession()`.
2. Add checks for:
   - `nextReviewAt` in answer response.
   - `question.content` handling for `multiple_choice`, `fraction_visual`, `angle_input`, `number_line`, `number_input`.
   - idempotency behavior in mock `events`.
   - `link` success/failure path.
3. Print explicit pass/fail markers for each v1 endpoint.

### Task 8: Documentation alignment

**Files:**
- `README.md`
- `ROBLOX_SDK_API.md` (this repo doc)

**Actions:**
1. Add section “Supported v1 question content types”.
2. Document methods:
   - `createSession`, `getProfile`, `getStandards`, `getSessionStatus`, `unlinkProfile`.
3. Add examples for both:
   - Math `number_input`/`fraction_visual` rendering inputs.
   - ELA `multiple_choice` and `number_input` text answer handling.
4. Add one section on optional launch config:
   - production/beta baseUrl (`https://play.gmac.io`, `https://beta.play.gmac.io`).

### Task 9: Demo feature-flag gates from capabilities

**Files:**
- `src/PlayPath.lua`
- new demo modules (below)

**Actions:**
1. Use `getCapabilities()` on game boot.
2. Gate optional features in demo:
   - standards lookup only if `features.supportsStandards`.
   - profile lookup only if `features.supportsProfileLookup`.
3. Store capability payload in a session context object to drive UI options and messaging.

---

## 3) Math + ELA demo implementation

### Directory layout

Create:
- `demo/math-ela/Server/PlayPathSessionManager.lua`
- `demo/math-ela/Server/GameRouter.server.lua`
- `demo/math-ela/Server/MathFlow.lua`
- `demo/math-ela/Server/ELAFlow.lua`
- `demo/math-ela/Client/Controller.client.lua`
- `demo/math-ela/Client/Renderers/QuestionRenderer.luau`
- `demo/math-ela/Client/Renderers/QuestionRendererMultipleChoice.luau`
- `demo/math-ela/Client/Renderers/QuestionRendererNumberInput.luau`
- `demo/math-ela/Client/Renderers/QuestionRendererFractionVisual.luau`
- `demo/math-ela/Client/Renderers/QuestionRendererAngleInput.luau`
- `demo/math-ela/Client/Renderers/QuestionRendererNumberLine.luau`
- `demo/math-ela/Replicated/Remotes.lua`
- `demo/math-ela/Replicated/QuestionTypes.lua`
- `demo/math-ela/README.md`

### 3.1 Server-side integration layer (SDK boundary)

**File:** `demo/math-ela/Server/PlayPathSessionManager.lua`

Implement single owner for session handles:
1. `init(config)`: call `PlayPath.init`.
2. `startSession(player, launchToken)` -> `createSession`.
3. `getOrCreateSession(player)` with cached table.
4. `endSession(player)` flush + `endSession`.
5. `getOrCreateStats(player)` with simple in-memory progress metrics.
6. Thin wrappers:
   - `getNextQuestion(session, skillFilter?, context?)`
   - `submitAnswer(session, ...)`
   - `skipQuestion(session, ...)`
   - `getHint(session, ...)`
   - `link(session, code)`
   - `grade(session, score, maxScore, comment)`
   - `syncProfile(session.profileId)` from `getProfile`.

### 3.2 Remote contract (Client <-> Server)

**File:** `demo/math-ela/Replicated/Remotes.lua`

Define exactly once:
- `SessionStart`
- `SessionEnd`
- `QuestionRequest`
- `AnswerSubmit`
- `QuestionSkip`
- `HintRequest`
- `PairingSubmit`
- `TelemetryEvent`
- `StandardsRequest`
- `CapabilitiesRequest`

All remotes send plain Luau tables with ids/strings only. Client never calls PlayPath methods directly.

### 3.3 Math flow

**File:** `demo/math-ela/Server/MathFlow.lua`

1. Pick skill targets from `focusSkills` (example: `math.fractions`, `math.angles`).
2. On first question:
   - call `getNextQuestion(session, { skill = "math.fractions" })`.
3. Rendering hooks to show:
   - multiple choice with shuffled options.
   - number input numeric mode (e.g., `6 x 7` etc).
   - fraction_visual fallback text when `visual.type` unknown.
4. On answer:
   - call `submitAnswer(questionId, answer, responseTimeMs, question.difficulty)`.
5. On wrong attempts:
   - expose hint flow (`getHint`) and optional `skip` route.
6. Track events:
   - `question_viewed`, `answer`, `hint_requested`, `question_skipped`, `session_end`.

### 3.4 ELA flow

**File:** `demo/math-ela/Server/ELAFlow.lua`

1. Target SoR skills by theme and context:
   - `sor.phonological`, `sor.phonics`, `sor.vocab`, `sor.fluency`.
2. Demonstrate:
   - `multiple_choice` word meaning/phonics style questions.
   - `number_input` text prompts for simple spelling prompts.
3. `responseTimeMs` should measure from `question_viewed` timestamp to submit.
4. Add audio placeholder support in UI schema (future-ready but optional).
5. Show standards if available:
   - call `getStandards([skillId], "TEKS"/"CCSS")` and render in a “What you’re learning” card.

### 3.5 Renderer layer

**Files:** `demo/math-ela/Client/Renderers/*`

- Dispatch by `question.kind` from normalized data.
- `multiple_choice`: button list.
- `number_input`: text input with accepted formats note.
- `fraction_visual`: render shape and options.
- `angle_input`: slider/angle dial fallback.
- `number_line`: range + snap.
- Unknown kind fallback:
  - show “Unsupported question type” and offer skip.

### 3.6 Client controller loop

**File:** `demo/math-ela/Client/Controller.client.lua`

1. Start and end flow through remote lifecycle events.
2. Manage two demo modes:
   - Math Mode
   - ELA Mode
3. On each question:
   - send `question_viewed` event with `questionId`, `skillId`, `difficulty`, `question.type`.
4. On submit:
   - send `answer` event with `responseTimeMs` and `correct`.
5. On skip:
   - send `question_skipped`.
6. On hint:
   - send `hint_requested`.
7. On session end:
   - fire grade submit and present result (`success`, `status`, `reasonCode`).

### 3.7 Demo-specific config + pairing UX

**File:** `demo/math-ela/README.md`

Include:
1. Pairing code panel:
   - input code -> server `verifyPairingCode`.
   - read and show `getProfile` summary after success.
2. Launch token example (for local test integration).
3. Teacher linking path vs anonymous path.
4. Environment switch: production vs beta endpoint.

### 3.8 Acceptance criteria for demo

- Math and ELA both run from one server boot.
- At least one successful roundtrip for each flow:
  - `getNextQuestion` -> `submitAnswer` (correct or incorrect),
  - `getHint` or `skipQuestion`,
  - `verifyPairingCode` success.
- `getStandards` called and rendered at least once when feature available.
- `submitGrade` invoked at session end and response parsed.
- No direct HTTP calls from client.
- `PlayerRemoving` cleanup path always calls session end.

---

## 4) Delivery order and execution gates

1. Complete v1 parity gap fixes in `src/PlayPath.lua` and mock corrections.
2. Expand `_internal.runMockTests()` coverage.
3. Update README/API docs.
4. Build demo infrastructure (`Server` + `Replicated` + `Client` modules).
5. Implement question renderers and two gameplay flows.
6. Run manual smoke pass:
   - mock mode flow.
   - beta endpoint smoke path against `/api/v1` for supported features.

## 5) Files to modify after plan execution

- `src/PlayPath.lua`
- `README.md`
- `ROBLOX_SDK_API.md`
- `docs/plans/2026-03-05-playpath-sdk-v1-alignment-and-math-ela-demo.md`
- `demo/math-ela/**/*`
