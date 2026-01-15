# PlayPath Roblox Lua SDK - Design Document

**Date**: 2026-01-14  
**Status**: Approved for Implementation  
**Effort Estimate**: 1-2 days for production-quality ModuleScript

---

## Executive Summary

Build a single-file, server-only Lua SDK for Roblox games to integrate with the PlayPath learning API. The SDK provides Promise-based methods for session management, adaptive questions, answer submission, hints, event tracking, and account linking.

### Key Design Decisions

| Aspect | Decision |
|--------|----------|
| Deployment | Single ModuleScript (drop-in to ReplicatedStorage) |
| Runtime | Server-side only (ServerScriptService) |
| API Style | Promise-based |
| Promise Library | Auto-detect `roblox-lua-promise`, fallback to embedded |
| Errors | Structured objects: `{ code, message, statusCode, retryable, raw }` |
| Retry | Built-in exponential backoff with jitter, configurable |
| State | Session object per player (OOP with metatables) |
| Config | Single `PlayPath.init({...})` at server start |
| Events | Auto-batching with interval/threshold flush triggers |
| Logging | Configurable levels: none/error/warn/debug |
| Testing | Built-in mock mode for Studio testing |

---

## Public API

### Initialization

```lua
local PlayPath = require(game.ReplicatedStorage.PlayPath)

PlayPath.init({
    gameKeyId = "your-game-key-id",      -- required
    apiKeySecret = "your-secret",         -- required
    baseUrl = "https://api.playpath.io",  -- optional, has default
    maxRetries = 3,                        -- optional
    retryBackoffMs = 1000,                 -- optional
    eventFlushInterval = 5,                -- seconds, optional
    eventFlushThreshold = 10,              -- events, optional
    logLevel = "warn",                     -- optional: none/error/warn/debug
    mockMode = false,                      -- optional
})
```

### Session Management

```lua
-- Create session for a player (returns Promise resolving to Session object)
PlayPath.createSession(player, { launchToken = "optional" })
    :andThen(function(session)
        -- Session properties (read-only)
        session.sessionId       -- string: UUID from server
        session.player          -- Player: the Roblox player
        session.linked          -- boolean: whether account is linked
        session.pairingCode     -- string or nil: code if unlinked
        session.student         -- table or nil: { id, displayName } if linked
        session.config          -- table: { theme, focusSkills } from server
    end)
```

### Session Methods

```lua
-- All return Promises except trackEvent
session:getNextQuestion(count?)        -- Promise<Question[]>
session:submitAnswer(questionId, answer, responseTimeMs)  -- Promise<AnswerResult>
session:skipQuestion(questionId, reason)                  -- Promise<void>
session:getHint(questionId, hintIndex?)                   -- Promise<Hint>

-- Events (auto-batched)
session:trackEvent(event)              -- void (queued, not a Promise)
session:flush()                        -- Promise<BatchResult> (manual flush)

-- Account linking
session:verifyPairingCode(code)        -- Promise<LinkResult>

-- Lifecycle
session:endSession()                   -- Promise<void> (flushes events first)
```

---

## Module Structure

Target size: **~1200-1800 LOC** (crypto is largest section)

```
PlayPath (ModuleScript)
├── Types              (220-360 LOC) - Luau type definitions
├── Constants/Utils    (90-140 LOC)  - Defaults, helpers
├── Logger             (70-120 LOC)  - Level-filtered logging
├── Promise            (260-420 LOC) - Detection + fallback
├── Crypto             (350-1000 LOC) - SHA256 + HMAC-SHA256
├── Errors             (120-200 LOC) - Error creation/mapping
├── HttpClient         (260-380 LOC) - Signing, retries, requests
├── Mock               (220-420 LOC) - Fake responses
├── Session            (360-520 LOC) - Player session class
├── PlayPath API       (120-200 LOC) - init(), createSession()
└── Self-tests         (80-160 LOC)  - Crypto vectors, smoke tests
```

---

## Type Definitions

```lua
--!strict

export type LogLevel = "none" | "error" | "warn" | "debug"

export type InitConfig = {
    gameKeyId: string,
    apiKeySecret: string,
    baseUrl: string?,
    maxRetries: number?,
    retryBackoffMs: number?,
    eventFlushInterval: number?,
    eventFlushThreshold: number?,
    logLevel: LogLevel?,
    mockMode: boolean?,
}

export type PlayPathErrorCode =
    -- API-defined
    "VALIDATION_ERROR"
    | "UNAUTHORIZED"
    | "NOT_FOUND"
    | "RATE_LIMITED"
    | "INTERNAL_ERROR"
    -- SDK-defined
    | "NETWORK_ERROR"
    | "TIMEOUT"
    | "DECODE_ERROR"
    | "ENCODE_ERROR"
    | "SDK_NOT_INITIALIZED"
    | "INVALID_CONFIG"
    | "SESSION_NOT_ACTIVE"
    | "SESSION_ENDING"
    | "SESSION_ENDED"
    | "PLAYER_LEFT"
    | "CONFLICT"
    | "UNKNOWN_ERROR"

export type PlayPathError = {
    code: PlayPathErrorCode,
    message: string,
    statusCode: number?,
    retryable: boolean,
    raw: any?,
    requestId: number?,
}

export type Student = { id: string, displayName: string }
export type SessionConfig = { theme: string?, focusSkills: {string}? }

export type Question = {
    id: string,
    kind: ("multiple_choice" | "numeric" | "free_response" | "unknown")?,
    prompt: string?,
    choices: {{id: string, text: string}}?,
    raw: any?,
}

export type MasteryUpdate = {
    skillCode: string,
    previousMastery: number,
    newMastery: number,
    delta: number,
}

export type AnswerResult = {
    correct: boolean,
    feedback: string?,
    masteryUpdates: {MasteryUpdate}?,
    raw: any?,
}

export type HintResult = {
    hint: string,
    hintIndex: number,
    totalHints: number,
    isLastHint: boolean,
    raw: any?,
}

export type LearningEvent = {
    type: string,
    questionId: string?,
    correct: boolean?,
    idempotencyKey: string?,
    timestamp: number?,
    properties: {[string]: any}?,
}

export type BatchResult = {
    accepted: number,
    rejected: number,
    raw: any?,
}

export type LinkResult = {
    success: boolean,
    student: Student?,
    raw: any?,
}

export type Session = {
    sessionId: string,
    player: Player,
    linked: boolean,
    pairingCode: string?,
    student: Student?,
    config: SessionConfig?,

    getNextQuestion: (self: Session, count: number?) -> any,
    submitAnswer: (self: Session, questionId: string, answer: any, responseTimeMs: number) -> any,
    skipQuestion: (self: Session, questionId: string, reason: string) -> any,
    getHint: (self: Session, questionId: string, hintIndex: number?) -> any,
    trackEvent: (self: Session, event: LearningEvent) -> (),
    flush: (self: Session) -> any,
    verifyPairingCode: (self: Session, code: string) -> any,
    endSession: (self: Session) -> any,
}
```

---

## Crypto Implementation

### Recommendation
Embed a trimmed version of `boatbomber/HashLib` (MIT) focused only on SHA-256 and HMAC-SHA256.

### Required Functions
- `Crypto.sha256Hex(message: string): string`
- `Crypto.hmacSha256Hex(key: string, message: string): string`

### Canonical Requirements
- Hash raw bytes of the JSON body string
- For requests without a body: `bodyJson = ""` and `bodyHash = SHA256("")`
- Output must be hex-encoded lowercase

### HMAC-SHA256 Specification
1. `blockSize = 64`
2. If `keyLen > blockSize`, set `key = SHA256(key)` (raw bytes)
3. Pad `key` to 64 bytes with `0x00`
4. `o_key_pad = key XOR 0x5c` (bytewise)
5. `i_key_pad = key XOR 0x36`
6. `hmac = SHA256(o_key_pad .. SHA256(i_key_pad .. messageBytes))`
7. Return hex encoding of hmac digest bytes

---

## Promise Implementation

### Detection Strategy
Check common instance locations in order:
1. Child module: `script:FindFirstChild("Promise")`
2. ReplicatedStorage: `ReplicatedStorage:FindFirstChild("Promise")`
3. ServerScriptService: `ServerScriptService:FindFirstChild("Promise")`
4. Fallback: embedded minimal implementation

### Validation
After require, verify shape:
- `type(Promise) == "table"`
- `type(Promise.new) == "function"`
- `type(Promise.resolve) == "function"`
- `type(Promise.reject) == "function"`

### Minimal Fallback Spec
Required surface:
- `Promise.new(executor)`
- `Promise.resolve(value)`
- `Promise.reject(reason)`
- `Promise.try(fn)`
- `Promise.delay(seconds)`
- `Promise.all(arrayOfPromises)`
- `:andThen(onResolve, onReject?)`
- `:catch(onReject)`
- `:finally(onFinally)`

---

## HTTP Layer

### Request Signing

```lua
local timestamp = tostring(os.time())
local bodyHash = Crypto.sha256Hex(bodyJson)
local canonical = string.format("%s:%s:%s:%s", timestamp, method, path, bodyHash)
local signature = Crypto.hmacSha256Hex(apiKeySecret, canonical)

headers = {
    ["Content-Type"] = "application/json",
    ["X-Game-Key-Id"] = gameKeyId,
    ["X-Timestamp"] = timestamp,
    ["X-Signature"] = signature,
}
```

### Retry Policy
- Attempts: `maxRetries + 1` total tries
- Retry only if `error.retryable == true`
- Backoff: `base * (2 ^ (attempt - 1))` with 10% jitter
- Special case for 429: respect `Retry-After` header

### Error Mapping

| Status | Code | Retryable |
|--------|------|-----------|
| 400 | VALIDATION_ERROR | No |
| 401 | UNAUTHORIZED | No |
| 404 | NOT_FOUND | No |
| 429 | RATE_LIMITED | Yes |
| >=500 | INTERNAL_ERROR | Yes |
| Network failure | NETWORK_ERROR | Yes |

---

## Session Lifecycle

### States
- `CREATING`: session start in-flight
- `ACTIVE`: normal operations allowed
- `ENDING`: endSession requested
- `ENDED`: terminal

### Transitions
```
CREATING → ACTIVE  (on /sessions/start success)
CREATING → ENDED   (on start failure or player leaves)
ACTIVE → ENDING    (on endSession() called)
ENDING → ENDED     (on /sessions/:id/end completes)
ACTIVE → ENDED     (on 401/404 for session-bound calls)
```

### Guard Rules
Before any session method:
- If `player.Parent == nil`: reject `PLAYER_LEFT`
- If `_state == "ENDED"`: reject `SESSION_ENDED`
- If `_state == "ENDING"`: reject `SESSION_ENDING` (except endSession/flush)

### Idempotency
- `endSession()` called twice: return same promise or already-ended object
- `flush()` called repeatedly: coalesce with `_flushInFlight`
- `verifyPairingCode()` twice: coalesce with `_linkInFlight`

---

## Event Batching

### Configuration
- `eventFlushInterval`: seconds between auto-flushes (default: 5)
- `eventFlushThreshold`: events before threshold flush (default: 10)
- `MAX_QUEUE_SIZE`: hard cap (default: 1000)

### trackEvent() Behavior
1. Validate: require `event.type` string
2. Populate defaults: `idempotencyKey`, `timestamp`
3. Append to queue
4. If queue > MAX_QUEUE_SIZE: drop oldest, log warn
5. If queue >= threshold: trigger non-blocking flush

### Flush Loop
```lua
task.spawn(function()
    while self._state == "ACTIVE" do
        task.wait(interval)
        if self._state ~= "ACTIVE" then break end
        if not isPlayerAlive(self.player) then
            self._state = "ENDED"
            break
        end
        if #self._eventQueue > 0 then
            self:flush()
        end
    end
end)
```

### Failure Recovery
- On retryable error: prepend batch back to queue
- On non-retryable error: discard batch, log warn

---

## Mock Mode

### Endpoint Responses

**POST /api/v1/sessions/start**
- `sessionId = uuid()`
- `linked = (robloxUserId % 2 == 0)` (deterministic)
- If linked: `student = { id, displayName }`, `pairingCode = nil`
- If unlinked: `student = nil`, `pairingCode = "ABC123"`

**POST /api/v1/sessions/:id/end**
- `{ ok = true }`

**POST /api/v1/questions/next**
- Returns mock math questions (multiple choice or numeric)
- Stores expected answer in `raw.expectedAnswer`

**POST /api/v1/questions/:id/answer**
- `correct = (answer == expectedAnswer)`
- `feedback = "Great job!"` or `"Try again."`
- `masteryUpdates = [{skillCode, previousMastery, newMastery, delta}]`

**POST /api/v1/questions/:id/skip**
- `{ skipped = true }`

**POST /api/v1/hints**
- Progressive hints from bank
- `{ hint, hintIndex, totalHints, isLastHint }`

**POST /api/v1/events/batch**
- `{ accepted = #events, rejected = 0 }`

**POST /api/v1/link/verify**
- If code matches: `{ success = true, student = {...} }`
- Else: 400 VALIDATION_ERROR

**GET /api/v1/profile/:robloxUserId**
- `{ robloxUserId, student?, mastery = [...] }`

---

## Edge Cases & Error Handling

### Network/Transport
- pcall failure: `NETWORK_ERROR`, retryable=true
- HttpService disabled: clear error message advising Game Settings

### Response Issues
- JSONEncode fails: `ENCODE_ERROR`, retryable=false
- JSONDecode fails: `DECODE_ERROR`, retryable=false

### Rate Limiting
- 429: retryable=true, respect Retry-After header
- Consider 20% jitter to reduce thundering herd

### Auth/Clock
- 401: retryable=false, log diagnostic about key/timestamp

### Session Invalidation
- 404 on session-bound call: transition to ENDED

### Player Leaves
- Before session start: reject PLAYER_LEFT
- During active session: flush loop stops, ignore in-flight results

---

## Testing Strategy

### A) Unit Tests (pure logic)
1. **Crypto vectors**: SHA256(""), SHA256("abc"), HMAC-SHA256 (RFC 4231)
2. **Signing tests**: verify canonical string and computed signature
3. **Error mapping**: feed synthetic responses, verify codes/retryable

### B) Mock-Mode Integration Tests
- Full flow: createSession → getNextQuestion → submitAnswer → getHint → trackEvent → flush → verifyPairingCode → endSession
- Assert session property updates, flush counts, idempotency

### C) Live Integration Tests (optional)
- Smoke test all endpoints with staging credentials
- Validate signatures (401 = signing mismatch)

### D) Performance
- Generate 500 events, ensure batching doesn't freeze server

---

## Implementation Order

1. **Types + constants + config defaults** (foundation)
2. **Logger** (needed everywhere)
3. **Promise detection + fallback** (required for public API)
4. **Crypto embed** (required for signing)
5. **Errors module** (required for consistent rejections)
6. **HttpClient** (depends on Promise/Crypto/Errors/Logger)
7. **Mock module** (used by HttpClient when mockMode)
8. **Session class core + lifecycle guards** (depends on HttpClient/Promise/Logger)
9. **Endpoint methods** (getNextQuestion, submitAnswer, etc.)
10. **Event batching loop + flush recovery** (depends on Session + HttpClient)
11. **Self-tests** (crypto vectors + mock smoke)

---

## Complete Usage Example

```lua
-- ServerScriptService/PlayPathSetup.lua
local Players = game:GetService("Players")
local PlayPath = require(game.ReplicatedStorage.PlayPath)

-- Initialize once at server start
PlayPath.init({
    gameKeyId = "gk_abc123",
    apiKeySecret = "sk_secret_key_here",
    logLevel = "warn",
})

-- Store active sessions
local sessions = {}

Players.PlayerAdded:Connect(function(player)
    PlayPath.createSession(player)
        :andThen(function(session)
            sessions[player] = session
            
            if not session.linked then
                showPairingUI(player, session.pairingCode)
            end
            
            return session:getNextQuestion()
        end)
        :andThen(function(questions)
            showQuestion(player, questions[1])
        end)
        :catch(function(err)
            warn("Failed to start session:", err.message)
        end)
end)

Players.PlayerRemoving:Connect(function(player)
    local session = sessions[player]
    if session then
        session:endSession()
        sessions[player] = nil
    end
end)

-- Called from game logic when player answers
function handleAnswer(player, questionId, answer, responseTimeMs)
    local session = sessions[player]
    session:submitAnswer(questionId, answer, responseTimeMs)
        :andThen(function(result)
            showFeedback(player, result.correct, result.feedback)
            updateMasteryUI(player, result.masteryUpdates)
        end)
        :catch(function(err)
            warn("Submit failed:", err.message)
        end)
end
```

---

## File Template

See `src/PlayPath.lua` for the complete ModuleScript skeleton with all sections laid out and ready for implementation.
