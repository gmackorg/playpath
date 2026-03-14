# PlayPath Event Model

This document describes the event system that connects game engine actions to
Play API calls and telemetry tracking.

## Table of Contents

- [Game Engine Events](#game-engine-events)
- [Event to API Mapping](#event-to-api-mapping)
- [Telemetry Event Types](#telemetry-event-types)
- [Event Flow Diagrams](#event-flow-diagrams)
- [Recommended Minimum Events](#recommended-minimum-events)
- [Batch Semantics](#batch-semantics)
- [Idempotency](#idempotency)
- [Custom Events](#custom-events)

---

## Game Engine Events

The PlayPath web game engine uses a typed `EventBus` that emits 8 core events.
These represent every meaningful player action in the world. Game engine
integrations (Roblox, Unity, Godot) should emit the equivalent events through
the SDK.

### Event Definitions

#### `entity_interact`

Fired when a player interacts with any entity (NPC, object, trigger).

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"entity_interact"` | Event discriminant |
| `entityId` | string | ID of the entity interacted with |
| `playerId` | string | ID of the player entity |

#### `challenge_start`

Fired when a challenge is presented to the player.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"challenge_start"` | Event discriminant |
| `entityId` | string | Entity that triggered the challenge |
| `challengeId` | string | Challenge UUID |

#### `challenge_end`

Fired when a challenge attempt is completed (correct or incorrect).

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"challenge_end"` | Event discriminant |
| `entityId` | string | Entity that triggered the challenge |
| `challengeId` | string | Challenge UUID |
| `correct` | boolean | Whether the answer was correct |

#### `quest_progress`

Fired when a quest objective is completed.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"quest_progress"` | Event discriminant |
| `entityId` | string | Entity related to the objective |
| `questId` | string | Quest UUID |
| `objectiveId` | string | Completed objective ID |

#### `quest_complete`

Fired when all objectives for a quest are met.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"quest_complete"` | Event discriminant |
| `entityId` | string | Entity related to the quest |
| `questId` | string | Quest UUID |

#### `narrative_advance`

Fired when a narrative beat or dialog progresses.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"narrative_advance"` | Event discriminant |
| `entityId` | string | Entity whose narrative advanced |

#### `world_complete`

Fired when all quests and challenges in the world are finished.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"world_complete"` | Event discriminant |

#### `zone_change`

Fired when the player moves between zones.

| Field | Type | Description |
| --- | --- | --- |
| `type` | `"zone_change"` | Event discriminant |
| `playerId` | string | ID of the player entity |
| `fromZone` | string | Zone the player is leaving |
| `toZone` | string | Zone the player is entering |

---

## Event to API Mapping

This table shows how game engine events map to telemetry types and Play API
calls. Some events trigger a server-authoritative API call. All events should
also be tracked as telemetry for analytics.

```
Game Engine Event       Telemetry Type       API Call                              SDK Method
─────────────────────── ──────────────────── ───────────────────────────────────── ──────────────────────────────────
entity_interact         npc_interact         POST /play/:id/npc/interact           playSession:npcInteract()
challenge_start         challenge_start      POST /play/:id/challenge/start        playSession:challengeStart()
challenge_end           challenge_respond    POST /play/:id/challenge/respond      playSession:challengeRespond()
quest_progress          quest_accept         trackEvent("quest_accept")            playSession:trackEvent()
quest_complete          quest_complete       POST /play/:id/quest/complete         playSession:questComplete()
zone_change             zone_enter           trackEvent("zone_enter")              playSession:trackEvent()
narrative_advance       custom               trackEvent("custom")                  playSession:trackEvent()
world_complete          (session end)        POST /play/:id/complete               playSession:complete()
```

**Key distinctions:**

- **Server-authoritative events** (`challenge_start`, `challenge_end`,
  `quest_complete`, `world_complete`) trigger a dedicated API call that returns
  validated state from the server (grades, mastery updates, quest unlocks).

- **Analytics-only events** (`entity_interact`, `quest_progress`, `zone_change`,
  `narrative_advance`) are tracked as telemetry events for session replay and
  learning analytics. They may also trigger an API call (e.g. `npc/interact`)
  when the server needs to return data (dialog lines, interaction type).

---

## Telemetry Event Types

The Play API accepts 18 telemetry event types. These are sent in batches via
`POST /play/:id/telemetry`.

| Type | Description | Recommended `data` Fields |
| --- | --- | --- |
| `zone_enter` | Player entered a zone | `zoneId`, `zoneName` |
| `zone_exit` | Player left a zone | `zoneId`, `zoneName`, `timeSpentMs` |
| `npc_interact` | Player interacted with an NPC | `entityId`, `npcName`, `interactionType` |
| `challenge_view` | Challenge UI was displayed to the player | `challengeId`, `mechanicCode` |
| `challenge_start` | Player began answering a challenge | `challengeId`, `mechanicCode`, `difficulty` |
| `challenge_respond` | Player submitted a challenge answer | `challengeId`, `correct`, `responseTimeMs`, `hintUsed` |
| `challenge_complete` | Challenge attempt finalized | `challengeId`, `correct`, `masteryDelta` |
| `hint_request` | Player requested a hint | `challengeId`, `hintIndex` |
| `quest_accept` | Player accepted/started a quest | `questId`, `questTitle` |
| `quest_complete` | Player completed a quest | `questId`, `questTitle` |
| `dialog_start` | NPC dialog conversation began | `entityId`, `npcName` |
| `dialog_choice` | Player selected a dialog choice | `entityId`, `choiceIndex`, `choiceLabel` |
| `dialog_end` | NPC dialog conversation ended | `entityId`, `npcName`, `linesRead` |
| `item_collect` | Player collected an item/pickup | `itemId`, `itemName` |
| `player_idle` | Player was idle for a notable duration | `idleDurationMs`, `zoneId` |
| `session_pause` | Session was paused (tab hidden, app backgrounded) | `reason` |
| `session_resume` | Session was resumed | `pauseDurationMs` |
| `custom` | Custom event for game-specific tracking | *(any fields)* |

---

## Event Flow Diagrams

### Challenge Flow

```
Game Client                            PlayPath Server
    │                                       │
    │  trackEvent("challenge_view")         │
    │──────────────────────────────────────>│  (telemetry only)
    │                                       │
    │  POST /challenge/start               │
    │  { challengeId }                     │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│
    │  { started, serverTimestamp }         │  Records start time
    │                                       │
    │  (player works on challenge)         │
    │                                       │
    │  POST /challenge/hint (optional)     │
    │  { challengeId, hintIndex }          │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│
    │  { hint, hintIndex, isLastHint }     │  Serves next hint
    │                                       │
    │  POST /challenge/respond             │
    │  { challengeId, response,            │
    │    responseTimeMs, hintUsed }        │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│  Grades answer,
    │  { correct, feedback,                │  updates mastery
    │    masteryDelta, masteryLevel }       │
    │                                       │
    │  trackEvent("challenge_complete")    │
    │──────────────────────────────────────>│  (telemetry only)
    │                                       │
```

### NPC Interaction Flow

```
Game Client                            PlayPath Server
    │                                       │
    │  POST /npc/interact                  │
    │  { entityId }                        │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│
    │  { interactionType: "dialog",        │  Returns interaction type
    │    dialogLine: {...} }               │  + first dialog line
    │                                       │
    │  trackEvent("dialog_start")          │
    │──────────────────────────────────────>│  (telemetry)
    │                                       │
    │  POST /dialog/advance                │
    │  { npcId, choiceIndex: 0 }           │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│
    │  { nextLine: {...}, complete: false } │  Advances dialog state
    │                                       │
    │  trackEvent("dialog_choice")         │
    │──────────────────────────────────────>│  (telemetry)
    │                                       │
    │  POST /dialog/advance                │
    │  { npcId }                           │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│
    │  { nextLine: null, complete: true }  │  Dialog finished
    │                                       │
    │  trackEvent("dialog_end")            │
    │──────────────────────────────────────>│  (telemetry)
    │                                       │
```

### Quest Completion Flow

```
Game Client                            PlayPath Server
    │                                       │
    │  trackEvent("quest_accept")          │
    │──────────────────────────────────────>│  (telemetry)
    │                                       │
    │  ... player completes objectives ... │
    │  (challenges, NPC interactions, etc) │
    │                                       │
    │  POST /quest/complete                │
    │  { questId }                         │
    │──────────────────────────────────────>│
    │<──────────────────────────────────────│  Validates objectives,
    │  { valid: true, rewardText,          │  unlocks next quests
    │    unlockedQuests: [...] }           │
    │                                       │
    │  trackEvent("quest_complete")        │
    │──────────────────────────────────────>│  (telemetry)
    │                                       │
```

### Full Session Flow

```
Game Client                            PlayPath Server
    │                                       │
    │  GET /play/blueprints                │
    │──────────────────────────────────────>│  List available worlds
    │<──────────────────────────────────────│
    │                                       │
    │  POST /play/start                    │
    │──────────────────────────────────────>│  Create session,
    │<──────────────────────────────────────│  return world payload
    │                                       │
    │  trackEvent("zone_enter")            │
    │──────────────────────────────────────>│
    │                                       │
    │  ┌─────────────────────────────┐     │
    │  │ NPC interactions            │     │
    │  │ Challenge loops             │     │  Server-authoritative
    │  │ Quest completions           │     │  grading + validation
    │  │ Zone changes                │     │
    │  │ Telemetry batches           │     │
    │  └─────────────────────────────┘     │
    │                                       │
    │  POST /play/:id/complete             │
    │──────────────────────────────────────>│  Finalize session,
    │<──────────────────────────────────────│  return summary
    │  { summary: { accuracy, mastery,     │
    │    highlights, ... } }               │
    │                                       │
```

---

## Recommended Minimum Events

At minimum, track these events for meaningful analytics and session replay:

| Event | Why It Matters |
| --- | --- |
| `zone_enter` | Session replay, time-per-zone analytics |
| `challenge_start` | Response time measurement baseline |
| `challenge_respond` | Core learning data (already required by API call) |
| `quest_complete` | Progress tracking (already required by API call) |
| `session_pause` / `session_resume` | Accurate time-on-task calculation |

These events are automatically tracked when you use the corresponding API
endpoints. The SDK handles this transparently.

**Strongly recommended additions:**

| Event | Why It Matters |
| --- | --- |
| `npc_interact` | Engagement tracking, story progression |
| `hint_request` | Struggle detection, hint effectiveness analysis |
| `dialog_choice` | Narrative preference analytics |
| `player_idle` | Engagement and attention metrics |

---

## Batch Semantics

Telemetry events are designed to be batched for efficiency.

### How Batching Works

1. The client queues events locally as they occur.
2. Events are flushed to the server when either threshold is met:
   - **Count threshold**: Default 10 events accumulated.
   - **Time interval**: Default 5 seconds since last flush.
3. Events are sent as a single `POST /play/:id/telemetry` request.
4. Maximum 100 events per batch.

### SDK Configuration

```lua
-- Roblox SDK
PlayPath.init({
    gameKeyId = "your-key",
    apiKeySecret = "your-secret",
    eventFlushInterval = 5,      -- seconds between auto-flushes
    eventFlushThreshold = 10,    -- events before auto-flush
})
```

### Manual Flush

Force-flush pending events at any time:

```lua
session:flush():andThen(function(result)
    print("Accepted:", result.accepted, "Rejected:", result.rejected)
end)
```

The SDK also auto-flushes when ending a session via `playSession:complete()`.

### Ordering Guarantees

- Events within a batch are processed in array order.
- Batches are processed in arrival order.
- Client timestamps are preserved for analytics; server adds its own
  receipt timestamp.

---

## Idempotency

Every telemetry event requires a UUID `idempotencyKey`. The server uses this
for deduplication.

### How It Works

1. The client generates a UUID v4 for each event at creation time.
2. The server stores seen idempotency keys per session.
3. Duplicate keys in the same or subsequent batches are silently rejected.
4. The response reports how many events were accepted vs. rejected.

### Example

```json
{
  "events": [
    {
      "type": "zone_enter",
      "timestamp": 1710432010000,
      "data": { "zoneId": "zone_1" },
      "idempotencyKey": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  ]
}
```

If you resend the same batch (e.g. after a network timeout with uncertain
delivery), the server returns:

```json
{
  "accepted": 0,
  "rejected": 1,
  "rejectedKeys": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
}
```

The `challengeRespond` endpoint also supports an optional `idempotencyKey` field
for the same purpose. This prevents double-grading if a response submission is
retried.

### Best Practices

- Generate the idempotency key when the event is created, not when it is sent.
- Store pending events locally so they can be retried with the same keys.
- Do not reuse keys across different events.

---

## Custom Events

Use the `custom` telemetry type for game-specific tracking that does not fit
the predefined event types.

### Sending Custom Events

```lua
-- Roblox SDK
session:trackEvent({
    type = "custom",
    data = {
        action = "minigame_start",
        minigameId = "puzzle_slider",
        difficulty = 3,
    },
})
```

### REST API

```json
{
  "events": [
    {
      "type": "custom",
      "timestamp": 1710432060000,
      "data": {
        "action": "minigame_start",
        "minigameId": "puzzle_slider",
        "difficulty": 3
      },
      "idempotencyKey": "d4e5f6a7-b8c9-0123-defg-h45678901234"
    }
  ]
}
```

### Guidelines

- Use a consistent `action` field in `data` to categorize custom events.
- Keep data payloads small. The `data` field accepts any JSON object, but
  large payloads increase batch size and may hit request size limits.
- Custom events appear in analytics dashboards under the "Custom" category
  and can be filtered by `data.action`.
