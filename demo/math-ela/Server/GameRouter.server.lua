local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local ReplicatedRoot = ReplicatedStorage:WaitForChild("PlayPathDemo")
local Remotes = require(ReplicatedRoot:WaitForChild("Remotes"))
local manager = require(script:WaitForChild("PlayPathSessionManager"))
local mathFlow = require(script:WaitForChild("MathFlow"))
local elaFlow = require(script:WaitForChild("ELAFlow"))
local MathELOperations = require(ReplicatedRoot:WaitForChild("QuestionTypes"))

local commandEvent = Remotes.CommandEvent
local responseEvent = Remotes.ResponseEvent
local sessionStateEvent = Remotes.SessionStateEvent
local telemetryEvent = Remotes.TelemetryEvent

type DemoCommand = {
	action: string,
	requestId: string?,
	mode: string?,
	payload: { [string]: any }?,
}

local function publish(player: Player, requestId: string?, action: string, ok: boolean, payload: any)
	responseEvent:FireClient(player, {
		requestId = requestId,
		action = action,
		ok = ok,
		payload = payload,
	})
end

local function fail(player: Player, request: DemoCommand, err: any)
	publish(player, request.requestId, request.action or "unknown", false, {
		error = if type(err) == "string"
			then err
			else (if type(err) == "table" and type((err :: any).message) == "string" then (err :: any).message else "Unknown error"),
	})
end

local function publishState(player: Player, state: { [string]: any })
	sessionStateEvent:FireClient(player, state)
end

local FEATURE_ENDPOINT_MAP = {
	supportsProfileLookup = "/api/v1/profile",
	supportsStandards = "/api/v1/standards",
	supportsUnlink = "/api/v1/unlink",
	supportsSessionIntrospection = "/api/v1/sessions",
	supportsCapabilities = "/api/v1/capabilities",
}

local function featureEnabled(player: Player, featureName: string): boolean
	local caps = manager.getSessionCapabilities(player)
	if caps == nil then
		return true
	end

	if type(caps.features) ~= "table" then
		return true
	end
	local explicit = caps.features[featureName]
	if type(explicit) == "boolean" then
		return explicit
	end

	local expectedEndpoint = FEATURE_ENDPOINT_MAP[featureName]
	if expectedEndpoint == nil then
		return true
	end

	if type(caps.endpoints) == "table" then
		for _, endpoint in ipairs(caps.endpoints) do
			if type(endpoint) == "string" and string.lower(endpoint) == string.lower(expectedEndpoint) then
				return true
			end
		end
		return false
	end

	-- If endpoints metadata is unavailable, keep behavior permissive for compatibility.
	return true
end

local function sanitizeMode(mode: any): string
	if mode == "ela" then
		return MathELOperations.MODES.ELA
	end
	return "math"
end

local function getFlowForMode(mode: string)
	if mode == MathELOperations.MODES.ELA then
		return elaFlow
	end
	return mathFlow
end

local function handleStart(player: Player, request: DemoCommand)
	local options = request.payload or {}
	local mode = sanitizeMode(request.mode)
	manager.startSession(player, {
		mode = mode,
		launchToken = options.launchToken,
	}):andThen(function(data: any)
		publishState(player, {
			type = "sessionStarted",
			sessionId = data.session.sessionId,
			linked = data.session.linked,
			pairingCode = data.session.pairingCode,
			profileId = data.session.profileId,
			capabilities = data.entry and data.entry.capabilities,
			mode = mode,
			config = data.session.config,
			student = data.session.student,
		})
		return publish(player, request.requestId, "startSession", true, {
			sessionId = data.session.sessionId,
			linked = data.session.linked,
			pairingCode = data.session.pairingCode,
			profileId = data.session.profileId,
			config = data.session.config,
			student = data.session.student,
		})
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleQuestionRequest(player: Player, request: DemoCommand)
	local requestPayload = request.payload or {}
	local mode = sanitizeMode(request.mode)
	local flow = getFlowForMode(mode)
	local state = manager.getSessionState(player)
	if state == nil then
		fail(player, request, "No active session")
		return
	end

	local builder = flow.buildQuestionRequest({
		focusSkills = state.focusSkills,
		mode = mode,
	}, request.requestId or "default")
	local merged = {
		skill = builder.skill,
		context = builder.context,
	}
	if type(requestPayload.context) == "table" then
		for k, v in pairs(requestPayload.context) do
			merged.context[k] = v
		end
	end

	manager.requestQuestion(player, merged):andThen(function(result: any)
		publish(player, request.requestId, "requestQuestion", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function toNumberMs(value: any): number
	if type(value) == "number" then
		return value
	end
	return 0
end

local function handleSubmitAnswer(player: Player, request: DemoCommand)
	local payload = request.payload or {}
	manager.submitAnswer(player, {
		questionId = tostring(payload.questionId or ""),
		answer = payload.answer,
		responseTimeMs = toNumberMs(payload.responseTimeMs),
		difficulty = payload.difficulty,
	}):andThen(function(result: any)
		publish(player, request.requestId, "submitAnswer", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleSkip(player: Player, request: DemoCommand)
	local payload = request.payload or {}
	manager.skipQuestion(player, {
		questionId = tostring(payload.questionId or ""),
		reason = if type(payload.reason) == "string" then payload.reason else nil,
	}):andThen(function(result: any)
		publish(player, request.requestId, "skipQuestion", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleHint(player: Player, request: DemoCommand)
	local payload = request.payload or {}
	manager.requestHint(player, {
		questionId = tostring(payload.questionId or ""),
		hintIndex = payload.hintIndex,
	}):andThen(function(result: any)
		publish(player, request.requestId, "requestHint", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handlePairing(player: Player, request: DemoCommand)
	local payload = request.payload or {}
	local code = tostring(payload.code or "")
	manager.linkProfile(player, code):andThen(function(result: any)
		publish(player, request.requestId, "submitPairing", true, result)
		publishState(player, {
			type = "pairingResult",
			success = result.success,
			student = result.student,
		})
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleProfile(player: Player, request: DemoCommand)
	if not featureEnabled(player, "supportsProfileLookup") then
		fail(player, request, "Profile lookup unavailable")
		return
	end

	local payload = request.payload or {}
	local profileId = tostring(payload.profileId or "")
	manager.getProfile(profileId):andThen(function(result: any)
		publish(player, request.requestId, "getProfile", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleStandards(player: Player, request: DemoCommand)
	if not featureEnabled(player, "supportsStandards") then
		fail(player, request, "Standards lookup unavailable")
		return
	end

	local payload = request.payload or {}
	manager.getStandards(payload.skillIds or {}, payload.frameworkCode):andThen(function(result: any)
		publish(player, request.requestId, "getStandards", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleCapabilities(player: Player, request: DemoCommand)
	manager.getCapabilities():andThen(function(result: any)
		publish(player, request.requestId, "getCapabilities", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleSessionStatus(player: Player, request: DemoCommand)
	manager.getSessionStatus(player):andThen(function(result: any)
		publish(player, request.requestId, "getSessionStatus", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleSubmitGrade(player: Player, request: DemoCommand)
	local payload = request.payload or {}
	manager.submitGrade(player, payload.score or 0, payload.maxScore or 1, payload.comment):andThen(function(result: any)
		publish(player, request.requestId, "submitGrade", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

local function handleEndSession(player: Player, request: DemoCommand)
	manager.endSession(player):andThen(function(result: any)
		publish(player, request.requestId, "endSession", true, result)
	end, function(err)
		fail(player, request, err)
	end)
end

telemetryEvent.OnServerEvent:Connect(function(player: Player, payload: any)
	if type(payload) ~= "table" then
		return
	end
	manager.trackEvent(player, payload)
end)

commandEvent.OnServerEvent:Connect(function(player, request: DemoCommand)
	if type(request) ~= "table" then
		fail(player, { action = "unknown", requestId = nil }, "Invalid request payload")
		return
	end

	if request.action == "startSession" then
		handleStart(player, request)
	elseif request.action == "requestQuestion" then
		handleQuestionRequest(player, request)
	elseif request.action == "submitAnswer" then
		handleSubmitAnswer(player, request)
	elseif request.action == "skipQuestion" then
		handleSkip(player, request)
	elseif request.action == "requestHint" then
		handleHint(player, request)
	elseif request.action == "submitPairing" then
		handlePairing(player, request)
	elseif request.action == "getProfile" then
		handleProfile(player, request)
	elseif request.action == "getStandards" then
		handleStandards(player, request)
	elseif request.action == "getCapabilities" then
		handleCapabilities(player, request)
	elseif request.action == "getSessionStatus" then
		handleSessionStatus(player, request)
	elseif request.action == "submitGrade" then
		handleSubmitGrade(player, request)
	elseif request.action == "endSession" then
		handleEndSession(player, request)
	else
		fail(player, request, "Unknown action: " .. tostring(request.action))
	end
end)

local function getStringAttribute(name: string, defaultValue: string?): string?
	local value = script:GetAttribute(name)
	if type(value) == "string" and value ~= "" then
		return value
	end
	return defaultValue
end

local function getBooleanAttribute(name: string, defaultValue: boolean): boolean
	local value = script:GetAttribute(name)
	if type(value) == "boolean" then
		return value
	end
	return defaultValue
end

manager.init({
	gameKeyId = getStringAttribute("PlayPathGameKeyId", "demo-game-key"),
	apiKeySecret = getStringAttribute("PlayPathApiKeySecret", "demo-secret"),
	baseUrl = getStringAttribute("PlayPathBaseUrl", nil),
	gameId = getStringAttribute("PlayPathGameId", nil),
	mockMode = getBooleanAttribute("PlayPathMockMode", true),
	logLevel = getStringAttribute("PlayPathLogLevel", "warn"),
})

Players.PlayerRemoving:Connect(function(player)
	manager.endSession(player)
end)

return true
