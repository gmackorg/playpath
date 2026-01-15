# PlayPath SDK for Roblox

Server-side Lua SDK for integrating [PlayPath](https://playpath.io) adaptive learning into Roblox games.

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

## Quick Start

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
    baseUrl = "https://...",       -- Optional, default: production
    maxRetries = 3,                -- Optional
    retryBackoffMs = 1000,         -- Optional
    eventFlushInterval = 5,        -- Optional, seconds
    eventFlushThreshold = 10,      -- Optional, events
    logLevel = "warn",             -- Optional: "none"|"error"|"warn"|"debug"
    mockMode = false,              -- Optional, for testing
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

### Session Methods

All methods return Promises except `trackEvent`.

#### session:getNextQuestion(count?)

```lua
session:getNextQuestion():andThen(function(response)
    local question = response.question
    print(question.id, question.prompt, question.choices)
end)
```

#### session:submitAnswer(questionId, answer, responseTimeMs)

```lua
session:submitAnswer(questionId, "b", 3500)
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

#### session:endSession()

End the session. Flushes pending events first.

```lua
session:endSession():andThen(function()
    print("Session ended")
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

| Code | Retryable | Description |
|------|-----------|-------------|
| `VALIDATION_ERROR` | No | Invalid request |
| `UNAUTHORIZED` | No | Invalid credentials |
| `NOT_FOUND` | No | Resource not found |
| `RATE_LIMITED` | Yes | Too many requests |
| `INTERNAL_ERROR` | Yes | Server error |
| `NETWORK_ERROR` | Yes | Network failure |
| `SESSION_ENDED` | No | Session already ended |
| `PLAYER_LEFT` | No | Player left game |

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

## License

MIT
