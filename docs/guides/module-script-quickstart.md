# ModuleScript Quickstart

Use this path if you want the fastest possible evaluation inside an existing Roblox place.

## What you need

- Roblox Studio
- HTTP enabled for the experience
- a copy of `src/PlayPath.lua`
- PlayPath credentials for beta or production

## Install

1. Create `ReplicatedStorage/PlayPath`.
2. Paste `src/PlayPath.lua` into that ModuleScript.
3. Add a server Script in `ServerScriptService`, for example `PlayPathSetup.server.lua`.

```lua
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local PlayPath = require(ReplicatedStorage:WaitForChild("PlayPath"))

PlayPath.init({
    gameKeyId = "your-game-key-id",
    apiKeySecret = "your-api-secret",
    baseUrl = "https://beta.play.gmac.io", -- swap to production when ready
    gameId = "my-roblox-game",
    logLevel = "warn",
})

local sessions = {}

local function startPlayerSession(player)
    PlayPath.createSession(player):andThen(function(session)
        sessions[player] = session

        if not session.linked then
            print("Pairing code:", session.pairingCode)
        end

        return session:getNextQuestion({
            skill = "math.fractions",
            context = {
                scene = "tutorial",
            },
        })
    end):andThen(function(result)
        print("Question:", result.question and result.question.prompt)
    end):catch(function(err)
        warn("PlayPath error:", err.code, err.message, err.requestId)
    end)
end

Players.PlayerAdded:Connect(startPlayerSession)

Players.PlayerRemoving:Connect(function(player)
    local session = sessions[player]
    sessions[player] = nil
    if session then
        session:endSession()
    end
end)
```

## First questions to answer in your game

- Where will pairing code UX live if the player is unlinked?
- Which game state should trigger `getNextQuestion`?
- How will your client collect answers for `multiple_choice`, `number_input`, and future content types?
- When will you flush/end the session on player exit or match end?

## Minimum production pattern

- Initialize once at server boot.
- Create one session per player.
- Keep all PlayPath calls on the server.
- Use Remotes to send normalized question data to the client.
- Call `session:endSession()` during cleanup.

## Next reads

- [Integration Guide](./integration-guide.md)
- [Launch Checklist](./launch-checklist.md)
- [Troubleshooting](./troubleshooting.md)
