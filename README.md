# PlayPath SDK for Roblox

Server-side Lua SDK for integrating [PlayPath](https://playpath.io) adaptive learning into Roblox games.

## Documentation Portal

Start here based on your workflow:

- Fastest first integration: [ModuleScript Quickstart](./docs/guides/module-script-quickstart.md)
- Production team setup: [Rojo + Wally Quickstart](./docs/guides/rojo-wally-quickstart.md)
- Recommended architecture and gameplay loop: [Integration Guide](./docs/guides/integration-guide.md)
- Demo evaluation and Studio walkthrough: [Math + ELA Demo Guide](./docs/guides/demo-guide.md)
- Copyable production wrapper sample: [examples/production/README.md](./examples/production/README.md)
- Launch readiness: [Launch Checklist](./docs/guides/launch-checklist.md)
- Common failures and recovery paths: [Troubleshooting](./docs/guides/troubleshooting.md)
- Raw REST/API contract: [ROBLOX_SDK_API.md](./ROBLOX_SDK_API.md)

Recommended reading order for most studios:
1. pick one installation quickstart
2. read the integration guide
3. run the launch checklist

## Installation

### With Wally (recommended)

Add to your `wally.toml`:

```toml
[dependencies]
PlayPath = "gmackie/playpath@0.1.0"
```

Then run:

```bash
wally install
```

### Manual Installation

Copy `src/PlayPath.lua` into `ReplicatedStorage.PlayPath`.

Optional contract override: copy `src/generated/OpenApiV1.lua` to `ReplicatedStorage.PlayPath/generated/OpenApiV1` to pin endpoint constants to the latest generated OpenAPI contract.

## Project Files

- `default.project.json`: runnable demo/game sync target for Studio and Rojo
- `package.project.json`: SDK-only ModuleScript packaging target
- `demo.project.json`: explicit alias for the demo project layout

## Quick Start

This is the shortest server-side integration path. For production teams, prefer the guides above.

```lua
-- ServerScriptService/PlayPathSetup.lua
local Players = game:GetService("Players")
local PlayPath = require(game.ReplicatedStorage.PlayPath)

PlayPath.init({
    gameKeyId = "your-game-key-id",
    apiKeySecret = "your-api-secret",
})

local sessions = {}

Players.PlayerAdded:Connect(function(player)
    PlayPath.createSession(player)
        :andThen(function(session)
            sessions[player] = session

            if not session.linked then
                -- Show pairing UI with session.pairingCode
            end

            return session:getNextQuestion()
        end)
        :andThen(function(response)
            local question = response.question
            -- Display question to player
        end)
        :catch(function(err)
            warn("PlayPath error:", err.message)
        end)
end)

Players.PlayerRemoving:Connect(function(player)
    local session = sessions[player]
    if session then
        session:endSession()
        sessions[player] = nil
    end
end)
```

## API Reference

### PlayPath.init(config)

Initialize the SDK. Call once at server start.

```lua
PlayPath.init({
    gameKeyId = "your-key",        -- Required
    apiKeySecret = "your-secret",  -- Required
    baseUrl = "https://play.gmac.io", -- Optional, default: production
    maxRetries = 3,                -- Optional
    retryBackoffMs = 1000,         -- Optional
    eventFlushInterval = 5,        -- Optional, seconds
    eventFlushThreshold = 10,      -- Optional, events
    logLevel = "warn",             -- Optional: "none"|"error"|"warn"|"debug"
    mockMode = false,              -- Optional, for testing
})
```

### Launch environment override

Use `baseUrl` to switch between production and beta:

```lua
-- Production (default)
PlayPath.init({
    gameKeyId = "your-key",
    apiKeySecret = "your-secret",
    baseUrl = "https://play.gmac.io",
})

-- Beta / staging
PlayPath.init({
    gameKeyId = "your-key",
    apiKeySecret = "your-secret",
    baseUrl = "https://beta.play.gmac.io",
})
```

### PlayPath.createSession(player, options?)

Create a session for a player. Returns a Promise.

```lua
PlayPath.createSession(player, { launchToken = "optional-lti-token" })
    :andThen(function(session)
        print(session.sessionId)   -- string
        print(session.linked)      -- boolean
        print(session.pairingCode) -- string or nil
        print(session.student)     -- {id, displayName} or nil
        print(session.config)      -- {theme, focusSkills}
    end)
```

### PlayPath.getServerTime()

Fetch server time for clock drift checks (useful when debugging signing issues).

```lua
PlayPath.getServerTime():andThen(function(info)
    print(info.serverTimeMs, info.maxDriftMs)
end)
```

### Session Methods

All methods return Promises except `trackEvent`.

#### session:getNextQuestion(options?)

```lua
-- options is optional; preferred keys are skill and context
session:getNextQuestion():andThen(function(response)
    local question = response.question
    print(question.id, question.prompt, question.choices)
end)
```

### session:getProfile()

Fetch link status and profile metadata for the current session profile from
`/api/v1/profile/{profileId}`.

```lua
session:getProfile()
``` 

### session:getStandards(skillIds, frameworkCode?)

Resolve curriculum standards for one or more skill IDs.

```lua
session:getStandards({ "uuid-1", "uuid-2" }, "TEKS")
```

#### session:submitAnswer(questionId, answer, responseTimeMs, difficulty?)

```lua
session:submitAnswer(questionId, "b", 3500, 3)
    :andThen(function(result)
        print(result.correct)      -- boolean
        print(result.feedback)     -- string
        print(result.masteryUpdates) -- array
    end)
```

#### session:skipQuestion(questionId, reason)

```lua
session:skipQuestion(questionId, "too_hard")
```

#### session:getHint(questionId, hintIndex?)

```lua
session:getHint(questionId, 0):andThen(function(hint)
    print(hint.hint)        -- string
    print(hint.hintIndex)   -- number
    print(hint.totalHints)  -- number
    print(hint.isLastHint)  -- boolean
end)
```

### session:getSessionStatus()

Inspect session lifecycle state and duration counters.

```lua
session:getSessionStatus():andThen(function(status)
    print(status.status, status.durationSeconds, status.eventsCount)
end)
```

#### session:trackEvent(event)

Fire-and-forget event tracking. Events are batched automatically.

```lua
session:trackEvent({
    type = "skill_demo",
    questionId = questionId,
    correct = true,
})
```

#### session:flush()

Manually flush pending events.

```lua
session:flush():andThen(function(result)
    print(result.accepted, result.rejected)
end)
```

#### session:verifyPairingCode(code)

Link an unlinked account.

```lua
session:verifyPairingCode("ABC123"):andThen(function(result)
    if result.success then
        print("Linked to:", result.student.displayName)
    end
end)
```

#### session:submitGrade(score, maxScore, comment?)

Queue an LMS grade passback (if enabled for your environment).

```lua
session:submitGrade(1, 1, "e2e")
    :andThen(function(result)
        print(result.success, result.scoreSubmitted, result.error)
    end)
```

#### session:endSession()

End the session. Flushes pending events first.

```lua
session:endSession():andThen(function()
    print("Session ended")
end)
```

### session:unlinkProfile()

Unlink profile mapping for the active provider identity.

```lua
session:unlinkProfile():andThen(function(resp)
    print(resp.success, resp.unlinked)
end)
```

## Error Handling

All errors are structured:

```lua
session:submitAnswer(...):catch(function(err)
    print(err.code)       -- "RATE_LIMITED", "UNAUTHORIZED", etc.
    print(err.message)    -- Human-readable message
    print(err.statusCode) -- HTTP status or nil
    print(err.retryable)  -- boolean
end)
```

### Error Codes

| Code               | Retryable | Description           |
| ------------------ | --------- | --------------------- |
| `VALIDATION_ERROR` | No        | Invalid request       |
| `UNAUTHORIZED`     | No        | Invalid credentials   |
| `NOT_FOUND`        | No        | Resource not found    |
| `RATE_LIMITED`     | Yes       | Too many requests     |
| `INTERNAL_ERROR`   | Yes       | Server error          |
| `NETWORK_ERROR`    | Yes       | Network failure       |
| `SESSION_ENDED`    | No        | Session already ended |
| `PLAYER_LEFT`      | No        | Player left game      |

### Supported v1 question content types

The demo and SDK parse these question types from `question.type` and `question.content`:
- `multiple_choice`
- `number_input`
- `fraction_visual`
- `angle_input`
- `number_line`
- `matching` (reserved)
- `sorting` (reserved)

Unsupported types are returned in fallback mode with `unsupported` metadata.

### Math and ELA handling examples

```lua
-- Math: number_input and fraction_visual
session:getNextQuestion({ skill = "math.fractions" }):andThen(function(response)
    local question = response.question
    if question.kind == "number_input" then
        -- accept numeric text input, submit as number or string
        session:submitAnswer(question.id, "0.75", 2200, question.difficulty)
    elseif question.kind == "fraction_visual" then
        -- example: fallback to a text answer or selected option id
        session:submitAnswer(question.id, "3/4", 2500, question.difficulty)
    end
end)
```

```lua
-- ELA: multiple_choice and text-style number_input prompts
session:getNextQuestion({ skill = "sor.vocab" }):andThen(function(response)
    local question = response.question
    if question.kind == "multiple_choice" then
        local firstChoice = question.choices and question.choices[1]
        session:submitAnswer(question.id, firstChoice and firstChoice.id or "a", 1800, question.difficulty)
    elseif question.kind == "number_input" then
        -- backend may use number_input for short text/spelling prompts
        session:submitAnswer(question.id, "because", 2100, question.difficulty)
    end
end)
```

## Demo: Math + ELA

See [demo/math-ela/README.md](demo/math-ela/README.md) for a starter game harness that demonstrates:

- session creation
- question loop (`getNextQuestion`, `submitAnswer`, `skipQuestion`, `getHint`)
- pairing flow (`submitPairing`, `getProfile`)
- standards lookups (`getStandards`)
- grade passback (`submitGrade`)
- session state introspection and capability negotiation

For the full external-facing walkthrough, use [docs/guides/demo-guide.md](./docs/guides/demo-guide.md).

## Mock Mode

For testing without API credentials:

```lua
PlayPath.init({
    gameKeyId = "test",
    apiKeySecret = "test",
    mockMode = true,
})
```

## Testing

Run crypto self-tests in Studio:

```lua
local PlayPath = require(game.ReplicatedStorage.PlayPath)
PlayPath._internal.runCryptoTests()
```

## Repo Tooling (Contributors)

This repo includes a `justfile` for one-line local checks.

Prereqs: `just` and `aftman` installed on your machine.

```bash
just install
just verify
just demo-build
just demo-serve
```

If Aftman tool shims fail to refresh due to permissions in `~/.aftman/bin`:

```bash
just fix-aftman-perms
```

## License

MIT
