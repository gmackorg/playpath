# PlayPath Play API Reference

The Play API is the narrative learning engine that powers PlayPath's world-based
educational experiences. Unlike the legacy quiz-mode SDK API (documented in
[ROBLOX_SDK_API.md](./ROBLOX_SDK_API.md)), the Play API delivers complete story
worlds with zones, quests, NPCs, branching dialog, and server-authoritative
challenges.

> **Base URL**: `https://play.gmac.io`

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Authentication](#authentication)
  - [HMAC Authentication (Game Engines)](#hmac-authentication-game-engines)
  - [Play Token Authentication (Web UI)](#play-token-authentication-web-ui)
- [Session Lifecycle](#session-lifecycle)
- [Endpoint Reference](#endpoint-reference)
  - [GET /api/v1/play/blueprints](#get-apiv1playblueprints)
  - [POST /api/v1/play/start](#post-apiv1playstart)
  - [POST /api/v1/play/:sessionId/challenge/start](#post-apiv1playsessionidchallengestart)
  - [POST /api/v1/play/:sessionId/challenge/respond](#post-apiv1playsessionidchallengerespond)
  - [POST /api/v1/play/:sessionId/challenge/hint](#post-apiv1playsessionidchallengehint)
  - [POST /api/v1/play/:sessionId/quest/complete](#post-apiv1playsessionidquestcomplete)
  - [POST /api/v1/play/:sessionId/dialog/advance](#post-apiv1playsessioniddialogadvance)
  - [POST /api/v1/play/:sessionId/npc/interact](#post-apiv1playsessionidnpcinteract)
  - [POST /api/v1/play/:sessionId/telemetry](#post-apiv1playsessionidtelemetry)
  - [POST /api/v1/play/:sessionId/complete](#post-apiv1playsessionidcomplete)
- [Error Response Format](#error-response-format)
- [Rate Limits](#rate-limits)

---

## Architecture Overview

The Play API uses a **hybrid authority model**:

- **Client explores**: The game client renders the world, moves the player
  between zones, triggers NPC interactions, and presents challenges locally.
  The full world payload (zones, entities, NPC dialog, challenge content) is
  delivered at session start.

- **Server validates**: Challenge grading, mastery updates, quest completion
  validation, and hint delivery are all server-authoritative. The client
  submits answers and the server returns correctness, feedback, and mastery
  deltas.

```
┌──────────────────┐                     ┌───────────────────────┐
│   Game Client    │                     │    PlayPath Server    │
│  (Roblox/Unity/  │                     │                       │
│   Godot/Web)     │                     │  - Challenge grading  │
│                  │  ── REST/HMAC ──>   │  - Mastery tracking   │
│  - World render  │  <── JSON ────────  │  - Quest validation   │
│  - Player input  │                     │  - Dialog state       │
│  - Zone nav      │                     │  - Telemetry ingest   │
│  - UI/UX         │                     │  - Session summary    │
└──────────────────┘                     └───────────────────────┘
```

All endpoints accept and return JSON (`Content-Type: application/json`).

---

## Authentication

The Play API supports two authentication schemes. Every endpoint requires one
of these unless noted otherwise.

### HMAC Authentication (Game Engines)

**Recommended for Roblox, Unity, Godot, and other game engine integrations.**

HMAC authentication uses a game key pair (key ID + secret) issued from the
PlayPath dashboard. The secret never leaves your server.

#### Required Headers

| Header | Type | Description |
| --- | --- | --- |
| `X-API-Key` | string | Your game key ID (e.g. `pp_live_abc123`) |
| `X-Timestamp` | string | Unix milliseconds, UTC (e.g. `1710432000000`) |
| `X-Nonce` | string | UUID v4, unique per request |
| `X-Signature` | string | `sha256=<hex>` HMAC signature |

Optional:

| Header | Type | Description |
| --- | --- | --- |
| `X-Request-Id` | string | Client-generated correlation ID for debugging |

#### Signature Calculation

```
1. bodyHash    = SHA256_HEX(rawBodyString)
                 (use empty string "" for GET requests or empty bodies)

2. canonical   = "{timestamp}:{nonce}:{METHOD}:{pathname}:{bodyHash}"
                 METHOD is uppercase (GET, POST)
                 pathname is path only, no domain or query string

3. signature   = HMAC_SHA256_HEX(apiKeySecret, canonical)

4. header      = "sha256=" + signature
```

**Example** (pseudocode):

```
apiKeySecret = "sk_test_secret123"
timestamp    = "1710432000000"
nonce        = "550e8400-e29b-41d4-a716-446655440000"
method       = "POST"
pathname     = "/api/v1/play/start"
body         = '{"blueprintId":"bp_abc","profileId":"prof_123"}'

bodyHash     = sha256hex(body)
             = "a1b2c3d4e5f6..."

canonical    = "1710432000000:550e8400-e29b-41d4-a716-446655440000:POST:/api/v1/play/start:a1b2c3d4e5f6..."

signature    = hmacSha256hex(apiKeySecret, canonical)
             = "9f8e7d6c5b4a..."

X-Signature  = "sha256=9f8e7d6c5b4a..."
```

#### Validation Rules

- Timestamp must be within **5 minutes** of server time.
- Each nonce is single-use; replayed nonces are rejected.
- Signature comparison uses constant-time equality to prevent timing attacks.

### Play Token Authentication (Web UI)

**Used by the web play interface.** Play tokens are single-use, short-lived
tokens generated when a student clicks "Play" in the teacher/parent dashboard.

Send the token in the request body of `/play/start`:

```json
{ "token": "pt_a1b2c3d4e5f6..." }
```

Play tokens:
- Expire after a configurable TTL (typically 10 minutes).
- Are consumed atomically on first use (no double-start).
- Carry the blueprint and student context internally.

Play token auth is only valid for `POST /play/start`. All subsequent session
endpoints use the `sessionId` returned by `/play/start` and must authenticate
via HMAC (for game engines) or inherit the web session context.

---

## Session Lifecycle

A complete Play API session follows this flow:

```
 1. List Blueprints (optional)
    GET /play/blueprints
    ─────────────────────────────────────────────────────────
    Returns available blueprints for the authenticated profile.
    Game engines use this to show a level/world picker.

 2. Start Session
    POST /play/start
    ─────────────────────────────────────────────────────────
    Consumes a play token OR accepts blueprintId+profileId (HMAC).
    Returns the full world payload: character, shell, theme,
    zones, entities, challenges (minus answers), and quests.

 3. Explore World
    The client renders zones, lets the player move around,
    interact with NPCs, and discover challenges.

    POST /play/:id/npc/interact      → start NPC interaction
    POST /play/:id/dialog/advance    → advance dialog tree

 4. Challenge Loop (repeat per challenge)
    POST /play/:id/challenge/start   → record challenge begin
    POST /play/:id/challenge/hint    → request hint (optional)
    POST /play/:id/challenge/respond → submit answer, get grade

 5. Quest Completion
    POST /play/:id/quest/complete    → validate quest objectives
    Server checks all objectives met, unlocks dependent quests.

 6. Telemetry (throughout session)
    POST /play/:id/telemetry         → batch event ingest
    Send zone changes, interactions, idle time, custom events.

 7. End Session
    POST /play/:id/complete          → finalize and get summary
    Returns accuracy, mastery changes, time breakdown, highlights.
```

---

## Endpoint Reference

### GET /api/v1/play/blueprints

List available blueprints for the authenticated profile.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `PlayPath.getBlueprints(profileId)` |

#### Query Parameters

| Param | Type | Required | Description |
| --- | --- | --- | --- |
| `profileId` | string | Yes | The profile ID to list blueprints for |
| `cursor` | string | No | Pagination cursor from previous response |

#### Response Body

```json
{
  "blueprints": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "subject": "math",
      "gradeLevel": 4,
      "challengeCount": 8,
      "estimatedMinutes": 15,
      "status": "approved",
      "storyTitle": "The Enchanted Library of Numeralia",
      "shellCode": "quest_linear",
      "createdAt": "2026-03-10T14:30:00.000Z"
    },
    {
      "id": "a23bc45d-67ef-8901-b234-5c6d7e8f9012",
      "subject": "ela",
      "gradeLevel": 3,
      "challengeCount": 6,
      "estimatedMinutes": 12,
      "status": "approved",
      "storyTitle": "Voyage of the Word Weavers",
      "shellCode": "hub_spoke",
      "createdAt": "2026-03-09T10:15:00.000Z"
    }
  ],
  "profileId": "prof_abc123",
  "linked": true,
  "nextCursor": null
}
```

#### Response Fields

| Field | Type | Description |
| --- | --- | --- |
| `blueprints` | `BlueprintListItem[]` | Array of available blueprints |
| `blueprints[].id` | string | Blueprint UUID |
| `blueprints[].subject` | string | Subject area (`"math"`, `"ela"`) |
| `blueprints[].gradeLevel` | number | Grade level (1-12) |
| `blueprints[].challengeCount` | number | Number of challenges in blueprint |
| `blueprints[].estimatedMinutes` | number or null | Estimated play time |
| `blueprints[].status` | string | Blueprint status (`"approved"`, `"active"`, etc.) |
| `blueprints[].storyTitle` | string | Story arc title |
| `blueprints[].shellCode` | string | Game shell type (e.g. `"quest_linear"`, `"hub_spoke"`) |
| `blueprints[].createdAt` | string | ISO 8601 timestamp |
| `profileId` | string | The queried profile ID |
| `linked` | boolean | Whether the profile is linked to a student |
| `nextCursor` | string or null | Cursor for next page, null if no more results |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `UNAUTHORIZED` | 401 | Invalid or missing HMAC headers |
| `VALIDATION_ERROR` | 400 | Missing profileId parameter |

---

### POST /api/v1/play/start

Start a new play session. Returns the complete world payload needed to render
the game.

| Property | Value |
| --- | --- |
| **Auth** | Play Token OR HMAC |
| **SDK Method** | `PlayPath.startPlay(blueprintId, profileId)` |

This endpoint accepts two distinct request shapes depending on the auth method.

#### Request Body (Play Token)

```json
{
  "token": "pt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | string | Yes | Single-use play token (max 128 chars) |

#### Request Body (HMAC)

```json
{
  "blueprintId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "profileId": "prof_abc123"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `blueprintId` | string | Yes | UUID of the blueprint to play |
| `profileId` | string | Yes | Profile ID of the player |

#### Response Body

```json
{
  "sessionId": "sess_7d8e9f0a-1b2c-3d4e-5f6a-7b8c9d0e1f2a",
  "character": {
    "id": "char_abc123",
    "name": "Luna",
    "setting": "A young explorer in the Enchanted Library",
    "desires": "To unlock the secrets of the ancient number scrolls",
    "traits": {
      "curious": true,
      "brave": true
    },
    "companion": {
      "name": "Digit",
      "type": "fox",
      "description": "A clever silver fox who loves puzzles"
    }
  },
  "shell": {
    "id": "shell_001",
    "code": "quest_linear",
    "name": "Linear Quest",
    "loopType": "sequential",
    "rendererHint": null
  },
  "theme": {
    "id": "theme_enchanted",
    "code": "enchanted_library",
    "name": "Enchanted Library",
    "palette": {
      "primary": "#4A90D9",
      "secondary": "#2ECC71",
      "accent": "#F39C12",
      "background": "#1A1A2E"
    },
    "vocabulary": {
      "challenge": "puzzle",
      "zone": "chapter",
      "quest": "adventure",
      "npc": "guide"
    }
  },
  "world": {
    "zones": [
      {
        "id": "zone_entrance",
        "name": "The Grand Foyer",
        "description": "Towering bookshelves stretch to the ceiling...",
        "entities": [
          {
            "id": "npc_librarian",
            "type": "npc",
            "name": "Sage Arithma",
            "position": { "x": 5, "y": 3, "zone": "zone_entrance" },
            "dialog": [
              {
                "speaker": "Sage Arithma",
                "text": "Welcome, young scholar! The library awaits...",
                "choices": [
                  { "label": "Tell me more!", "nextIndex": 1 },
                  { "label": "I'm ready to explore.", "nextIndex": 2 }
                ]
              }
            ]
          }
        ]
      }
    ]
  },
  "challenges": [
    {
      "id": "ch_fraction_01",
      "sequence": 1,
      "mechanicCode": "fraction_visual",
      "inputShape": "multipleChoice",
      "difficulty": 3,
      "narrativeMoment": "The enchanted bookshelf reveals a fraction puzzle",
      "storyIntegration": "Solving this unlocks the passage to the next chapter",
      "content": {
        "prompt": "Luna finds a torn page showing 3/4 of a circle shaded. Which fraction matches?",
        "options": [
          { "id": "a", "label": "1/2" },
          { "id": "b", "label": "3/4" },
          { "id": "c", "label": "2/3" },
          { "id": "d", "label": "4/5" }
        ],
        "explanation": "Three out of four equal parts are shaded, so the fraction is 3/4.",
        "successText": "The page glows and reassembles itself!",
        "failureText": "The page flickers... try again.",
        "hints": [
          "Count how many parts are shaded out of the total.",
          "The circle is divided into 4 equal parts."
        ]
      },
      "skillAtomCode": "math.fractions.identify",
      "skillAtomTitle": "Identify Fractions"
    }
  ],
  "quests": [
    {
      "id": "quest_chapter1",
      "title": "The First Chapter",
      "description": "Complete the fraction puzzles to unlock the next wing.",
      "objectives": [
        {
          "id": "obj_solve_3",
          "description": "Solve 3 fraction challenges",
          "requiredCount": 3
        }
      ],
      "prerequisites": [],
      "rewards": {
        "text": "The door to the Mathematics Wing swings open!"
      }
    }
  ],
  "storyArc": {
    "title": "The Enchanted Library of Numeralia",
    "introduction": "Deep within the city of Numeralia lies a library where numbers come alive...",
    "conclusion": "With every puzzle solved, Luna restored the library's magic..."
  }
}
```

#### Response Fields

| Field | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Unique session ID for all subsequent API calls |
| `character` | `PlayCharacter` | The player's character |
| `character.id` | string | Character UUID |
| `character.name` | string | Character display name |
| `character.setting` | string | Character backstory/setting description |
| `character.desires` | string | Character motivation |
| `character.traits` | object | Key-value character traits |
| `character.companion` | object | Companion creature `{name, type, description}` |
| `shell` | `PlayShell` | Game shell metadata |
| `shell.code` | string | Shell type code (e.g. `"quest_linear"`, `"hub_spoke"`) |
| `shell.loopType` | string | Gameplay loop structure |
| `shell.rendererHint` | string or null | Optional hint for client renderer |
| `theme` | `PlayTheme` | Visual and vocabulary theme |
| `theme.palette` | object | Color palette `{primary, secondary, accent, background}` |
| `theme.vocabulary` | object | Themed term overrides `{challenge, zone, quest, npc}` |
| `world` | `WorldDefinition` | Full world definition with zones and entities |
| `challenges` | `PlayChallenge[]` | All challenges (correct answers excluded) |
| `challenges[].id` | string | Challenge UUID |
| `challenges[].sequence` | number | Display order (1-based) |
| `challenges[].mechanicCode` | string | Challenge mechanic type |
| `challenges[].inputShape` | string | Input type: `"multipleChoice"`, `"freeResponse"`, `"numeric"`, `"dragDrop"`, `"sequence"`, `"matching"` |
| `challenges[].difficulty` | number | Difficulty rating |
| `challenges[].narrativeMoment` | string | Story context for presenting this challenge |
| `challenges[].storyIntegration` | string | How solving connects to the narrative |
| `challenges[].content` | object | Challenge content (prompt, options, hints) — **no correct answer** |
| `challenges[].skillAtomCode` | string | Skill atom identifier |
| `challenges[].skillAtomTitle` | string | Human-readable skill name |
| `quests` | `BlueprintQuest[]` | Quest definitions with objectives and prerequisites |
| `storyArc` | object | Story arc `{title, introduction, conclusion}` |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `TOKEN_INVALID` | 401 | Token does not exist |
| `TOKEN_EXPIRED` | 401 | Token TTL has elapsed |
| `TOKEN_USED` | 409 | Token was already consumed |
| `VALIDATION_ERROR` | 400 | Missing required fields or invalid format |
| `UNAUTHORIZED` | 401 | HMAC signature invalid |
| `SESSION_NOT_FOUND` | 404 | Blueprint not found |

---

### POST /api/v1/play/:sessionId/challenge/start

Record the start of a challenge attempt. Call this when the player begins a
challenge so the server can track response time.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:challengeStart(challengeId)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "challengeId": "ch_fraction_01"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challengeId` | string (UUID) | Yes | ID of the challenge being started |

#### Response Body

```json
{
  "started": true,
  "serverTimestamp": 1710432015000
}
```

| Field | Type | Description |
| --- | --- | --- |
| `started` | boolean | Whether the challenge was successfully started |
| `serverTimestamp` | number | Server timestamp (ms) for response time calculation |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `CHALLENGE_NOT_FOUND` | 404 | Challenge ID not in this blueprint |
| `CHALLENGE_ALREADY_COMPLETED` | 409 | Challenge was already answered |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/challenge/respond

Submit an answer to a challenge. The server grades the response, updates
mastery, and returns feedback.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:challengeRespond(challengeId, response, responseTimeMs, hintUsed)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "challengeId": "ch_fraction_01",
  "response": "b",
  "responseTimeMs": 4200,
  "hintUsed": false,
  "idempotencyKey": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challengeId` | string (UUID) | Yes | Challenge being answered |
| `response` | any | Yes | Player's answer (string for multiple choice ID, number for numeric, etc.) |
| `responseTimeMs` | number | Yes | Time in milliseconds from challenge start to submission (non-negative integer) |
| `hintUsed` | boolean | No | Whether the player used a hint (default `false`) |
| `idempotencyKey` | string (UUID) | No | Client-generated UUID for deduplication |

#### Response Body

```json
{
  "correct": true,
  "feedback": "Excellent work! 3/4 is exactly right.",
  "explanation": "Three out of four equal parts are shaded, making the fraction 3/4.",
  "masteryDelta": 0.08,
  "masteryLevel": 0.62
}
```

| Field | Type | Description |
| --- | --- | --- |
| `correct` | boolean | Whether the answer was correct |
| `feedback` | string | Narrative feedback text for display |
| `explanation` | string | Educational explanation of the correct answer |
| `masteryDelta` | number | Change in mastery for this skill atom (can be negative on wrong answers) |
| `masteryLevel` | number | New mastery level for this skill atom (0.0 to 1.0) |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `CHALLENGE_NOT_FOUND` | 404 | Challenge ID not in this blueprint |
| `CHALLENGE_ALREADY_COMPLETED` | 409 | Challenge already answered |
| `VALIDATION_ERROR` | 400 | Invalid request body |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/challenge/hint

Request a hint for a challenge. Hints are served sequentially; the server
tracks which hints have been shown.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:challengeHint(challengeId, hintIndex?)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "challengeId": "ch_fraction_01",
  "hintIndex": 0
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challengeId` | string (UUID) | Yes | Challenge to get hint for |
| `hintIndex` | number | No | Specific hint index (0-based). Omit for next sequential hint. |

#### Response Body

```json
{
  "hint": "Count how many parts are shaded out of the total.",
  "hintIndex": 0,
  "totalHints": 2,
  "isLastHint": false
}
```

| Field | Type | Description |
| --- | --- | --- |
| `hint` | string | The hint text |
| `hintIndex` | number | Index of this hint (0-based) |
| `totalHints` | number | Total number of hints available for this challenge |
| `isLastHint` | boolean | Whether this is the final hint |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `CHALLENGE_NOT_FOUND` | 404 | Challenge ID not in this blueprint |
| `HINTS_EXHAUSTED` | 409 | All hints already shown |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/quest/complete

Request server validation of quest completion. The server checks that all
quest objectives are met and unlocks dependent quests.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:questComplete(questId)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "questId": "quest_chapter1"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `questId` | string | Yes | Quest ID to complete |

#### Response Body (Success)

```json
{
  "valid": true,
  "rewardText": "The door to the Mathematics Wing swings open!",
  "unlockedQuests": ["quest_chapter2"]
}
```

#### Response Body (Failure)

```json
{
  "valid": false,
  "rewardText": "",
  "unlockedQuests": [],
  "reason": "Not all objectives completed",
  "missingObjectives": ["obj_solve_3"]
}
```

| Field | Type | Description |
| --- | --- | --- |
| `valid` | boolean | Whether the quest is validly complete |
| `rewardText` | string | Narrative reward/celebration text |
| `unlockedQuests` | string[] | Quest IDs now available after this completion |
| `reason` | string or undefined | Reason for rejection (only when `valid` is false) |
| `missingObjectives` | string[] or undefined | IDs of incomplete objectives (only when `valid` is false) |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `QUEST_NOT_FOUND` | 404 | Quest ID not in this blueprint |
| `QUEST_PREREQUISITES_NOT_MET` | 400 | Prerequisite quests not completed |
| `QUEST_OBJECTIVES_INCOMPLETE` | 400 | Not all objectives completed |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/dialog/advance

Advance an NPC dialog tree. If the current dialog line has choices, pass the
selected `choiceIndex`. The server tracks dialog position per NPC per session.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:dialogAdvance(npcId, choiceIndex?)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "npcId": "npc_librarian",
  "choiceIndex": 0
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `npcId` | string | Yes | Entity ID of the NPC |
| `choiceIndex` | number | No | Index of the selected choice (0-based). Omit if no choices on current line. |

#### Response Body

```json
{
  "nextLine": {
    "speaker": "Sage Arithma",
    "text": "Wonderful! The first chapter holds fraction puzzles that will test your wits.",
    "choices": null
  },
  "complete": false
}
```

When dialog is finished:

```json
{
  "nextLine": null,
  "complete": true
}
```

| Field | Type | Description |
| --- | --- | --- |
| `nextLine` | `DialogLine` or null | Next dialog line, or null if conversation ended |
| `nextLine.speaker` | string | Name of the speaking character |
| `nextLine.text` | string | Dialog text |
| `nextLine.choices` | `{label, nextIndex}[]` or null | Available choices, if any |
| `complete` | boolean | Whether this NPC's dialog is now finished |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `VALIDATION_ERROR` | 400 | Missing npcId or invalid choiceIndex |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/npc/interact

Initiate an interaction with an NPC entity. The server returns what kind of
interaction this NPC offers (dialog, challenge, quest giving, etc.) and the
relevant starting data.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:npcInteract(entityId)` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "entityId": "npc_librarian"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `entityId` | string | Yes | Entity ID of the NPC to interact with |

#### Response Body

The response shape varies by interaction type.

**Dialog interaction:**

```json
{
  "interactionType": "dialog",
  "dialogLine": {
    "speaker": "Sage Arithma",
    "text": "Welcome, young scholar!",
    "choices": [
      { "label": "Tell me more!", "nextIndex": 1 }
    ]
  }
}
```

**Challenge interaction:**

```json
{
  "interactionType": "challenge",
  "challengeId": "ch_fraction_01"
}
```

**Quest giver interaction:**

```json
{
  "interactionType": "quest_giver",
  "questId": "quest_chapter1"
}
```

**Info/merchant interaction:**

```json
{
  "interactionType": "info",
  "text": "The ancient scrolls speak of numbers that can be split into equal parts..."
}
```

| Field | Type | Description |
| --- | --- | --- |
| `interactionType` | string | One of `"dialog"`, `"challenge"`, `"quest_giver"`, `"merchant"`, `"info"` |
| `dialogLine` | `DialogLine` or undefined | First dialog line (when `interactionType` is `"dialog"`) |
| `challengeId` | string or undefined | Challenge to present (when `interactionType` is `"challenge"`) |
| `questId` | string or undefined | Quest to offer (when `interactionType` is `"quest_giver"`) |
| `text` | string or undefined | Descriptive text (when `interactionType` is `"info"` or `"merchant"`) |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `VALIDATION_ERROR` | 400 | Missing entityId |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/telemetry

Submit a batch of telemetry events. Events are used for analytics, session
replay, and learning insights.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:trackEvent(event)` (auto-batched), `playSession:flush()` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

```json
{
  "events": [
    {
      "type": "zone_enter",
      "timestamp": 1710432010000,
      "data": {
        "zoneId": "zone_entrance",
        "zoneName": "The Grand Foyer"
      },
      "idempotencyKey": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    },
    {
      "type": "npc_interact",
      "timestamp": 1710432025000,
      "data": {
        "entityId": "npc_librarian",
        "npcName": "Sage Arithma"
      },
      "idempotencyKey": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    },
    {
      "type": "challenge_start",
      "timestamp": 1710432040000,
      "data": {
        "challengeId": "ch_fraction_01",
        "mechanicCode": "fraction_visual"
      },
      "idempotencyKey": "c3d4e5f6-a7b8-9012-cdef-123456789012"
    }
  ]
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `events` | `PlayTelemetryEvent[]` | Yes | Array of 1-100 events |
| `events[].type` | string | Yes | Event type (see [Telemetry Event Types](#telemetry-event-types)) |
| `events[].timestamp` | number | Yes | Client timestamp in ms since epoch (non-negative integer) |
| `events[].data` | object | Yes | Arbitrary event payload (defaults to `{}`) |
| `events[].idempotencyKey` | string (UUID) | Yes | Unique UUID for deduplication |

#### Telemetry Event Types

| Type | Description |
| --- | --- |
| `zone_enter` | Player entered a zone |
| `zone_exit` | Player left a zone |
| `npc_interact` | Player interacted with an NPC |
| `challenge_view` | Challenge UI was displayed |
| `challenge_start` | Player began a challenge |
| `challenge_respond` | Player submitted a challenge answer |
| `challenge_complete` | Challenge was completed (correct or not) |
| `hint_request` | Player requested a hint |
| `quest_accept` | Player accepted a quest |
| `quest_complete` | Player completed a quest |
| `dialog_start` | NPC dialog was initiated |
| `dialog_choice` | Player made a dialog choice |
| `dialog_end` | NPC dialog conversation ended |
| `item_collect` | Player collected an item |
| `player_idle` | Player was idle for a notable duration |
| `session_pause` | Session was paused |
| `session_resume` | Session was resumed |
| `custom` | Custom event (use `data` for details) |

#### Response Body

```json
{
  "accepted": 3,
  "rejected": 0
}
```

With rejections:

```json
{
  "accepted": 2,
  "rejected": 1,
  "rejectedKeys": ["c3d4e5f6-a7b8-9012-cdef-123456789012"]
}
```

| Field | Type | Description |
| --- | --- | --- |
| `accepted` | number | Number of events accepted |
| `rejected` | number | Number of events rejected (duplicates or invalid) |
| `rejectedKeys` | string[] or undefined | Idempotency keys of rejected events |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `VALIDATION_ERROR` | 400 | Invalid event format or empty array |
| `RATE_LIMITED` | 429 | Too many telemetry requests |
| `UNAUTHORIZED` | 401 | Auth failed |

---

### POST /api/v1/play/:sessionId/complete

End a play session and retrieve the session summary. The server finalizes all
tracking data and computes mastery changes, accuracy, time breakdowns, and
highlights.

| Property | Value |
| --- | --- |
| **Auth** | HMAC |
| **SDK Method** | `playSession:complete()` |

#### Path Parameters

| Param | Type | Description |
| --- | --- | --- |
| `sessionId` | string | Session ID from `/play/start` |

#### Request Body

No body required. Send an empty JSON object `{}` or omit the body.

#### Response Body

```json
{
  "summary": {
    "challengesCompleted": 7,
    "challengesCorrect": 5,
    "totalChallenges": 8,
    "accuracy": 0.714,
    "questsCompleted": 2,
    "totalQuests": 3,
    "timeSpentSeconds": 842,
    "skillsWorked": [
      {
        "skillAtomCode": "math.fractions.identify",
        "skillAtomTitle": "Identify Fractions",
        "masteryBefore": 0.45,
        "masteryAfter": 0.68,
        "challengesAttempted": 4,
        "challengesCorrect": 3
      },
      {
        "skillAtomCode": "math.fractions.compare",
        "skillAtomTitle": "Compare Fractions",
        "masteryBefore": 0.30,
        "masteryAfter": 0.42,
        "challengesAttempted": 3,
        "challengesCorrect": 2
      }
    ],
    "zoneBreakdown": [
      {
        "zoneId": "zone_entrance",
        "zoneName": "The Grand Foyer",
        "timeSpentSeconds": 180,
        "challengesCompleted": 2
      },
      {
        "zoneId": "zone_math_wing",
        "zoneName": "The Mathematics Wing",
        "timeSpentSeconds": 662,
        "challengesCompleted": 5
      }
    ],
    "highlights": [
      {
        "type": "mastery_gain",
        "text": "Huge improvement in Identify Fractions! Mastery jumped from 45% to 68%.",
        "entityId": "math.fractions.identify"
      },
      {
        "type": "streak",
        "text": "Got 3 fraction challenges correct in a row!"
      },
      {
        "type": "quest_complete",
        "text": "Completed 'The First Chapter' quest!",
        "entityId": "quest_chapter1"
      }
    ]
  }
}
```

#### Response Fields

| Field | Type | Description |
| --- | --- | --- |
| `summary.challengesCompleted` | number | Total challenges attempted |
| `summary.challengesCorrect` | number | Challenges answered correctly |
| `summary.totalChallenges` | number | Total challenges in the blueprint |
| `summary.accuracy` | number | Fraction correct (0.0 to 1.0) |
| `summary.questsCompleted` | number | Quests completed |
| `summary.totalQuests` | number | Total quests in the blueprint |
| `summary.timeSpentSeconds` | number | Total session duration in seconds |
| `summary.skillsWorked` | `SkillSummary[]` | Per-skill mastery breakdown |
| `summary.skillsWorked[].skillAtomCode` | string | Skill atom identifier |
| `summary.skillsWorked[].skillAtomTitle` | string | Human-readable skill name |
| `summary.skillsWorked[].masteryBefore` | number | Mastery at session start (0.0 to 1.0) |
| `summary.skillsWorked[].masteryAfter` | number | Mastery at session end (0.0 to 1.0) |
| `summary.skillsWorked[].challengesAttempted` | number | Challenges attempted for this skill |
| `summary.skillsWorked[].challengesCorrect` | number | Challenges correct for this skill |
| `summary.zoneBreakdown` | `ZoneTimeSummary[]` | Time and challenge counts per zone |
| `summary.zoneBreakdown[].zoneId` | string | Zone identifier |
| `summary.zoneBreakdown[].zoneName` | string | Human-readable zone name |
| `summary.zoneBreakdown[].timeSpentSeconds` | number | Seconds spent in this zone |
| `summary.zoneBreakdown[].challengesCompleted` | number | Challenges completed in this zone |
| `summary.highlights` | `SessionHighlight[]` | Notable moments for display |
| `summary.highlights[].type` | string | One of `"mastery_gain"`, `"streak"`, `"quest_complete"`, `"first_try"` |
| `summary.highlights[].text` | string | Human-readable celebration text |
| `summary.highlights[].entityId` | string or undefined | Related entity identifier |

#### Error Codes

| Code | HTTP | When |
| --- | --- | --- |
| `SESSION_NOT_FOUND` | 404 | Invalid session ID |
| `UNAUTHORIZED` | 401 | Auth failed |

---

## Error Response Format

All Play API errors follow a consistent shape:

```json
{
  "error": {
    "code": "CHALLENGE_NOT_FOUND",
    "message": "Challenge ID 'ch_invalid' not found in this blueprint",
    "details": {}
  }
}
```

| Field | Type | Description |
| --- | --- | --- |
| `error.code` | string | Machine-readable error code (see table below) |
| `error.message` | string | Human-readable description |
| `error.details` | any or undefined | Additional structured data (validation errors, etc.) |

The response also includes an `X-Request-Id` header for support correlation.

### Error Code Reference

| Code | HTTP Status | Description |
| --- | --- | --- |
| `TOKEN_INVALID` | 401 | Play token does not exist in the database |
| `TOKEN_EXPIRED` | 401 | Play token's `expiresAt` is in the past |
| `TOKEN_USED` | 409 | Play token has already been consumed |
| `TOKEN_MISSING` | 401 | No token provided in request |
| `SESSION_NOT_FOUND` | 404 | Session ID not found |
| `CHALLENGE_NOT_FOUND` | 404 | Challenge ID not in this blueprint |
| `CHALLENGE_ALREADY_COMPLETED` | 409 | Challenge was already answered |
| `QUEST_NOT_FOUND` | 404 | Quest ID not in this blueprint |
| `QUEST_PREREQUISITES_NOT_MET` | 400 | Prerequisite quests not yet completed |
| `QUEST_OBJECTIVES_INCOMPLETE` | 400 | Not all quest objectives satisfied |
| `HINTS_EXHAUSTED` | 409 | All hints already served for this challenge |
| `VALIDATION_ERROR` | 400 | Request body failed schema validation |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `UNAUTHORIZED` | 401 | Neither valid play token nor valid HMAC signature |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `SERVICE_UNAVAILABLE` | 503 | Play API disabled via feature flag |

---

## Rate Limits

Rate limits match the same tier structure as the legacy SDK API.

| Tier | Limit | Window | Applies To |
| --- | --- | --- | --- |
| Standard | 60 requests | 1 minute | Per API key |
| Burst | 10 requests | 1 second | Per API key |
| Telemetry | 30 requests | 1 minute | Per session |
| Start | 5 requests | 1 minute | Per API key |

When rate limited, the server returns HTTP 429 with error code `RATE_LIMITED`
and includes these headers:

| Header | Description |
| --- | --- |
| `Retry-After` | Seconds to wait before retrying |
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

### Best Practices

- Batch telemetry events (up to 100 per request) instead of sending individually.
- Use the SDK's built-in auto-flush (threshold and interval based).
- Cache the world payload from `/play/start` locally; it does not change during the session.
- Implement exponential backoff for retryable errors (`RATE_LIMITED`, `INTERNAL_ERROR`).
