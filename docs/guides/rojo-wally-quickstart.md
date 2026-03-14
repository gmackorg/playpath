# Rojo + Wally Quickstart

Use this path if your team already develops Roblox games with source control, Rojo, and package management.

## Install

Add the dependency to `wally.toml`:

```toml
[dependencies]
PlayPath = "gmackie/playpath@0.1.0"
```

Install dependencies:

```bash
wally install
```

Map the SDK into `ReplicatedStorage` through your Rojo project:

```json
{
  "name": "MyGame",
  "tree": {
    "ReplicatedStorage": {
      "Packages": {
        "$path": "Packages"
      },
      "PlayPath": {
        "$path": "Packages/PlayPath/src/PlayPath.lua"
      }
    }
  }
}
```

## Server bootstrap

```lua
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local PlayPath = require(ReplicatedStorage:WaitForChild("PlayPath"))

PlayPath.init({
    gameKeyId = "your-game-key-id",
    apiKeySecret = "your-api-secret",
    baseUrl = "https://play.gmac.io",
    gameId = "my-roblox-game",
    maxRetries = 3,
    retryBackoffMs = 1000,
    eventFlushThreshold = 10,
    eventFlushInterval = 5,
    logLevel = "warn",
})

local sessions = {}

Players.PlayerAdded:Connect(function(player)
    PlayPath.createSession(player):andThen(function(session)
        sessions[player.UserId] = session
    end):catch(function(err)
        warn("createSession failed:", err.code, err.message)
    end)
end)

Players.PlayerRemoving:Connect(function(player)
    local session = sessions[player.UserId]
    sessions[player.UserId] = nil
    if session then
        session:endSession()
    end
end)
```

## Recommended repo layout

- Put PlayPath session orchestration in `ServerScriptService`.
- Keep client UI and renderers separate from answer submission logic.
- Store no secrets in client code or replicated config.
- Wrap the SDK in a game-specific server integration layer so your gameplay code only talks to one local API.

The sample demo in this repo follows that pattern.

## Next reads

- [Integration Guide](./integration-guide.md)
- [Math + ELA Demo Guide](./demo-guide.md)
- [Launch Checklist](./launch-checklist.md)
