# PlayPath Roblox v1 REST API (Lua SDK)

This document describes the v1 REST contract targeted by `src/PlayPath.lua`.

If you are also working in the main `../playpath` repo, treat
`../playpath/docs/ROBLOX_SDK_API.md` as the upstream source of truth.

## Environments

| Environment | Base URL |
| --- | --- |
| Production | `https://play.gmac.io` |
| Beta (staging) | `https://beta.play.gmac.io` |

All endpoints below are relative to the selected base URL.

## Endpoint Inventory

| Method | Path | Purpose | SDK Surface |
| --- | --- | --- | --- |
| `GET` | `/api/v1/time` | Server time for drift checks | `PlayPath.getServerTime()` |
| `POST` | `/api/v1/sessions` | Start session | `PlayPath.createSession()` |
| `POST` | `/api/v1/sessions/{sessionId}` | End session | `session:endSession()` |
| `GET` | `/api/v1/sessions/{sessionId}` | Session introspection | `session:getSessionStatus()` |
| `POST` | `/api/v1/questions` | Next question | `session:getNextQuestion()` |
| `POST` | `/api/v1/questions/{questionId}` | Submit answer | `session:submitAnswer()` |
| `POST` | `/api/v1/questions/{questionId}/skip` | Skip question | `session:skipQuestion()` |
| `POST` | `/api/v1/hints` | Hint request | `session:getHint()` |
| `POST` | `/api/v1/events` | Batch telemetry ingest | `session:trackEvent()` + `session:flush()` |
| `POST` | `/api/v1/link` | Verify/redeem pairing code | `session:verifyPairingCode()` |
| `POST` | `/api/v1/unlink` | Unlink provider profile | `session:unlinkProfile()` |
| `GET` | `/api/v1/profile/{profileId}` | Profile lookup | `PlayPath.getProfile()`, `session:getProfile()` |
| `POST` | `/api/v1/standards` | Standards lookup | `PlayPath.getStandards()`, `session:getStandards()` |
| `POST` | `/api/v1/grades` | LMS grade passback | `session:submitGrade()` |
| `GET` | `/api/v1/capabilities` | Feature availability | `PlayPath.getCapabilities()` |

## Authentication (HMAC-SHA256)

All protected endpoints are signed. Public endpoint: `GET /api/v1/time`.

### Required Headers

Header names are case-insensitive, but these canonical names are used:

| Header | Type | Notes |
| --- | --- | --- |
| `x-api-key` | string | Game key ID |
| `x-timestamp` | string | Unix ms, UTC |
| `x-nonce` | string | UUID, unique per request |
| `x-signature` | string | `sha256=<hex>` |

Optional:

| Header | Type | Notes |
| --- | --- | --- |
| `x-request-id` | string | Client-generated correlation id |

### Signature Calculation

Inputs:
- `timestamp`: value of `x-timestamp`
- `nonce`: value of `x-nonce`
- `method`: uppercased method
- `pathname`: URL path only, no query string
- `rawBody`: exact JSON sent on the wire (`""` for no body)

```text
bodySha256Hex = sha256Hex(rawBody)
canonical = "{timestamp}:{nonce}:{METHOD}:{pathname}:{bodySha256Hex}"
hmacHex = hmacSha256Hex(apiKeySecret, canonical)
x-signature = "sha256=" + hmacHex
```

Rules:
- Encode JSON once and sign that exact string.
- Keep path canonical (no domain, no query).

## Core Request/Response Shapes

### Start Session (`POST /api/v1/sessions`)

Request keys:
- `profileId` (string, required)
- `robloxUserId` (number, required)
- `displayName` (string, optional)
- `launchToken` (string, optional)

Response keys:
- `sessionId` (string)
- `linked` (boolean)
- `pairingCode` (string or null when linked)
- `student` (`{ id, displayName }` or null)
- `config` (`{ theme?, focusSkills? }`)
- `profileId` (string)

### Get Next Question (`POST /api/v1/questions`)

Request keys:
- `sessionId` (string, required)
- `studentId` (string, optional)
- `skill` (string, optional)
- `context` (table, optional; SDK sends `game` by default)

Response keys:
- `question` or `questions`
- `personalization` (optional)

SDK-normalized question shape includes:
- `id`, `type`, `kind`, `prompt`
- `content`, `choices`, `hints`
- `skillId`, `difficulty`, `expectedTimeMs`

### Submit Answer (`POST /api/v1/questions/{questionId}`)

Request keys:
- `sessionId` (required)
- `studentId` (optional)
- `answer` (any JSON value)
- `responseTimeMs` (optional number)
- `difficulty` (optional number)
- `idempotencyKey` (required by SDK)

Response keys:
- `correct` (boolean)
- `feedback` (string)
- `masteryUpdates` (array)
- `nextReviewAt` (optional)

### Skip Question (`POST /api/v1/questions/{questionId}/skip`)

Request keys:
- `sessionId` (required)
- `studentId` (optional)
- `reason` (string, default `other`)
- `idempotencyKey` (required by SDK)

### Hint (`POST /api/v1/hints`)

Request keys:
- `sessionId`, `questionId` (required)
- `studentId` (optional)
- `hintIndex` (optional number, default `0`)
- `idempotencyKey`

### Events (`POST /api/v1/events`)

Request keys:
- `sessionId` (required)
- `events` (array)

Each event should include:
- `type` (string)
- `questionId` (optional)
- `data` and/or `properties` (SDK normalizes both)
- `timestamp`
- `idempotencyKey`

### Linking and Profile

- `POST /api/v1/link`: `{ sessionId, pairingCode, idempotencyKey }`
- `POST /api/v1/unlink`: `{ sessionId, profileId, idempotencyKey }`
- `GET /api/v1/profile/{profileId}`: returns `{ linked, student? }`

### Standards (`POST /api/v1/standards`)

Request keys:
- `skillIds` (array of strings)
- `frameworkCode` (optional string, e.g. `TEKS`, `CCSS`)

### Grade (`POST /api/v1/grades`)

Request keys:
- `sessionId`
- `score`, `maxScore`
- `comment` (optional)
- `idempotencyKey`

Response keys:
- `success`, `status`, `reasonCode`, `error?`

### Session Status (`GET /api/v1/sessions/{sessionId}`)

Response keys:
- `sessionId`, `status`, `durationSeconds`, `eventsCount`

### Capabilities (`GET /api/v1/capabilities`)

Response keys:
- `version`
- `endpoints` (string array)
- `features` (map, example: `supportsStandards`, `supportsProfileLookup`)

## v1 Question Content Types

Current documented content types:
- `multiple_choice`
- `number_input`
- `fraction_visual`
- `angle_input`
- `number_line`

Reserved:
- `matching`
- `sorting`

## Error Contract

Typical error JSON:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": {}
  }
}
```

HTTP status mapping in SDK includes:
- `400`, `401`, `403`, `404`, `409`, `413`, `429`, `500+`

`x-request-id` from response headers is propagated into `PlayPathError.requestId`
for support/debug correlation.
