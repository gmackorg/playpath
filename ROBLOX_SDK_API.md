# PlayPath Roblox SDK API Reference

This document provides a quick reference for the PlayPath REST API used by the Roblox SDK. For full integration details, see [ROBLOX_INTEGRATION.md](./ROBLOX_INTEGRATION.md).

## API Endpoints

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| POST | `/api/v1/sessions/start` | Start a new game session |
| POST | `/api/v1/sessions/:id/end` | End an active game session |
| POST | `/api/v1/questions/next` | Fetch next adaptive question(s) |
| POST | `/api/v1/questions/:id/answer` | Submit an answer for evaluation |
| POST | `/api/v1/questions/:id/skip` | Skip a question with reason |
| POST | `/api/v1/hints` | Request a hint for a question |
| POST | `/api/v1/events/batch` | Submit a batch of learning events |
| POST | `/api/v1/link/verify` | Verify a pairing code to link accounts |
| GET | `/api/v1/profile/:robloxUserId` | Retrieve player profile and mastery |

---

## Authentication

All requests from the Roblox SDK must be signed using HMAC-SHA256.

### Required Headers
| Header | Description |
|:-------|:------------|
| `X-Game-Key-Id` | Unique identifier for your game (provided by PlayPath) |
| `X-Timestamp` | Current Unix timestamp (seconds) |
| `X-Signature` | Computed HMAC-SHA256 signature |

### Signature Calculation
The signature is computed over a canonical string:
```text
"{timestamp}:{method}:{path}:{bodyHash}"
```
*   `timestamp`: The same value sent in `X-Timestamp`.
*   `method`: HTTP method in uppercase (e.g., `POST`).
*   `path`: Full path including `/api/v1` (e.g., `/api/v1/sessions/start`).
*   `bodyHash`: Hex-encoded SHA256 hash of the JSON request body. Use `SHA256("")` for requests without a body.

**Example (Lua):**
```lua
local bodyHash = Crypto.sha256Hex(bodyJson or "")
local canonical = string.format("%s:%s:%s:%s", timestamp, method, path, bodyHash)
local signature = Crypto.hmacSha256Hex(API_KEY_SECRET, canonical)
```

---

## Request/Response Examples

### 1. Start Session
**POST** `/api/v1/sessions/start`
```json
// Request
{
  "robloxUserId": 12345678,
  "gameId": "uuid-v4",
  "launchToken": "optional-lti-token"
}

// Response (200 OK)
{
  "sessionId": "uuid-v4",
  "student": { "id": "uuid-v4", "displayName": "Alex" }, // null if unlinked
  "config": { "theme": "space", "focusSkills": ["math.fractions"] },
  "linked": true,
  "pairingCode": "ABC123" // Only if linked is false
}
```

### 2. Submit Answer
**POST** `/api/v1/questions/:id/answer`
```json
// Request
{
  "sessionId": "uuid-v4",
  "answer": 42,
  "responseTimeMs": 3500,
  "idempotencyKey": "uuid-v4"
}

// Response (200 OK)
{
  "correct": true,
  "feedback": "Great job!",
  "masteryUpdates": [
    { "skillCode": "math.fractions", "previousMastery": 0.5, "newMastery": 0.55, "delta": 0.05 }
  ]
}
```

### 3. Submit Events Batch
**POST** `/api/v1/events/batch`
```json
// Request
{
  "sessionId": "uuid-v4",
  "events": [
    {
      "type": "skill_demo",
      "questionId": "uuid-v4",
      "correct": true,
      "idempotencyKey": "uuid-v4"
    }
  ]
}

// Response (200 OK)
{
  "accepted": 1,
  "rejected": 0
}
```

### 4. Get Hint
**POST** `/api/v1/hints`
```json
// Request
{
  "sessionId": "uuid-v4",
  "questionId": "uuid-v4",
  "hintIndex": 0,
  "idempotencyKey": "uuid-v4"
}

// Response (200 OK)
{
  "hint": "Try looking at the denominator.",
  "hintIndex": 0,
  "totalHints": 3,
  "isLastHint": false
}
```

### 5. Verify Pairing Code
**POST** `/api/v1/link/verify`
```json
// Request
{
  "robloxUserId": 12345678,
  "pairingCode": "ABC123"
}

// Response (200 OK)
{
  "success": true,
  "student": { "id": "uuid-v4", "displayName": "Alex" }
}
```

---

## Error Codes

| Code | Status | Description |
|:-----|:-------|:------------|
| `VALIDATION_ERROR` | 400 | Request body is missing required fields or has invalid format |
| `UNAUTHORIZED` | 401 | Invalid signature, timestamp expired, or unknown Game Key ID |
| `NOT_FOUND` | 404 | Resource (session, question, player) not found |
| `RATE_LIMITED` | 429 | Too many requests for this game or player |
| `INTERNAL_ERROR` | 500 | Server-side processing failure |

---

## Rate Limits

| Scope | Limit |
|:------|:------|
| Learning Events | 200 requests per minute per game |
| Question Fetching | 100 requests per minute per game |
| Other API calls | 60 requests per minute per player |
