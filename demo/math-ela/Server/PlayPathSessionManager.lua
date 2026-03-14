local Players = game:GetService("Players")

local M = {}
local FALLBACK_CAPABILITIES = {
	apiVersion = "v1",
	endpoints = {
		"/api/v1/sessions",
		"/api/v1/questions",
		"/api/v1/events",
		"/api/v1/link",
		"/api/v1/unlink",
		"/api/v1/standards",
		"/api/v1/grades",
		"/api/v1/profile",
		"/api/v1/capabilities",
	},
	features = {
		supportsProfileLookup = true,
		supportsStandards = true,
		supportsUnlink = true,
		supportsSessionIntrospection = true,
		supportsCapabilities = true,
	},
}

local PlayPath = nil
local _initialized = false
local _sessions = {} :: { [number]: any }
local _capabilities: any? = nil

local function cloneTable(src: any): { [string]: any }
	if type(src) ~= "table" then
		return {}
	end
	local out: { [string]: any } = {}
	for key, value in pairs(src) do
		out[key] = value
	end
	return out
end

local function toBooleanOrNil(value: any): boolean?
	if type(value) == "boolean" then
		return value
	end
	return nil
end

local function normalizeEndpointSet(endpoints: any): { [string]: boolean }
	local lookup: { [string]: boolean } = {}
	if type(endpoints) ~= "table" then
		return lookup
	end
	for _, endpoint in ipairs(endpoints) do
		if type(endpoint) == "string" then
			lookup[string.lower(endpoint)] = true
		end
	end
	return lookup
end

local function supportsFromEndpointSet(featureName: string, features: { [string]: any }, endpointSet: { [string]: boolean }): boolean
	local explicit = toBooleanOrNil(features[featureName])
	if explicit ~= nil then
		return explicit
	end

	if featureName == "supportsProfileLookup" then
		return endpointSet["/api/v1/profile"] == true
	end
	if featureName == "supportsStandards" then
		return endpointSet["/api/v1/standards"] == true
	end
	if featureName == "supportsUnlink" then
		return endpointSet["/api/v1/unlink"] == true
	end
	if featureName == "supportsSessionIntrospection" then
		return endpointSet["/api/v1/sessions"] == true
	end
	if featureName == "supportsCapabilities" then
		return endpointSet["/api/v1/capabilities"] == true
	end

	return explicit == nil and false
end

local function normalizeCapabilities(cap: any): any
	if type(cap) ~= "table" then
		return FALLBACK_CAPABILITIES
	end

	local normalized = {
		apiVersion = if type(cap.apiVersion) == "string" then cap.apiVersion else FALLBACK_CAPABILITIES.apiVersion,
		endpoints = if type(cap.endpoints) == "table" then cap.endpoints else FALLBACK_CAPABILITIES.endpoints,
		rateLimits = if type(cap.rateLimits) == "table" then cap.rateLimits else nil,
		features = if type(cap.features) == "table" then cloneTable(cap.features) else {},
		raw = cap.raw,
	}

	local endpointSet = normalizeEndpointSet(normalized.endpoints)
	if type(normalized.features) ~= "table" then
		normalized.features = {}
	end
	normalized.features.supportsProfileLookup = supportsFromEndpointSet("supportsProfileLookup", normalized.features, endpointSet)
	normalized.features.supportsStandards = supportsFromEndpointSet("supportsStandards", normalized.features, endpointSet)
	normalized.features.supportsUnlink = supportsFromEndpointSet("supportsUnlink", normalized.features, endpointSet)
	normalized.features.supportsSessionIntrospection = supportsFromEndpointSet(
		"supportsSessionIntrospection",
		normalized.features,
		endpointSet
	)
	normalized.features.supportsCapabilities = supportsFromEndpointSet("supportsCapabilities", normalized.features, endpointSet)

	return normalized
end

local DEFAULT_PLAYPATH_PATH = function(): ModuleScript
	return game:GetService("ReplicatedStorage"):WaitForChild("PlayPath") :: ModuleScript
end

function M.init(config: { [string]: any }?)
	if _initialized then
		return true
	end

	local modulePath = DEFAULT_PLAYPATH_PATH()
	local moduleToLoad = if config and type(config.playPathModule) == "Instance"
		then config.playPathModule
		else modulePath

	PlayPath = require(moduleToLoad :: any)

	local sdkConfig = {
		gameKeyId = if config and type(config.gameKeyId) == "string" then config.gameKeyId else "demo-game-key",
		apiKeySecret = if config and type(config.apiKeySecret) == "string" then config.apiKeySecret else "demo-secret",
		baseUrl = if config and type(config.baseUrl) == "string" then config.baseUrl else nil,
		gameId = if config and type(config.gameId) == "string" then config.gameId else nil,
		mockMode = if config and type(config.mockMode) == "boolean" then config.mockMode else true,
		logLevel = if config and type(config.logLevel) == "string" then config.logLevel else "warn",
	}

	PlayPath.init(sdkConfig)
	_initialized = true
	return true
end

local function ensureInitialized()
	if not _initialized then
		error("PlayPathSessionManager.init() must be called first")
	end
end

local function noSessionError()
	return PlayPath._internal.Promise.reject({
		code = "SESSION_NOT_ACTIVE",
		message = "No active session",
		statusCode = nil,
		retryable = false,
		raw = nil,
		requestId = nil,
	})
end

local function withSessionRecord(player: Player): any?
	return _sessions[player.UserId]
end

local function withCapabilitiesFallback()
	if _capabilities ~= nil and type(_capabilities) == "table" then
		return _capabilities
	end
	return FALLBACK_CAPABILITIES
end

local function cacheCapabilities()
	if _capabilities ~= nil then
		return PlayPath._internal.Promise.resolve(_capabilities)
	end

	return PlayPath.getCapabilities():andThen(function(cap: any)
		_capabilities = normalizeCapabilities(cap)
		return _capabilities
	end):catch(function()
		_capabilities = withCapabilitiesFallback()
		return _capabilities
	end)
end

function M.startSession(player: Player, options: { launchToken: string? }?): any
	ensureInitialized()
	local startOpts = {}
	if options and type(options.launchToken) == "string" then
		startOpts = { launchToken = options.launchToken }
	end

	return PlayPath.createSession(player, startOpts):andThen(function(session: any)
		return cacheCapabilities():andThen(function(caps: any)
			local entry = {
				player = player,
				session = session,
				mode = if options and type((options :: any).mode) == "string" then ((options :: any).mode) else "math",
				startedAt = os.time(),
				questionViews = 0,
				lastQuestionAt = 0,
				focusSkills = if session.config and type(session.config.focusSkills) == "table"
					then session.config.focusSkills
					else {},
				studentId = if session.student and type(session.student.id) == "string" then session.student.id else nil,
				capabilities = caps,
			}
			_sessions[player.UserId] = entry
			return { session = session, entry = entry }
		end)
	end)
end

function M.getSession(player: Player): any?
	return withSessionRecord(player)
end

function M.getSessionState(player: Player): any?
	local entry = withSessionRecord(player)
	if entry == nil then
		return nil
	end
	return entry
end

function M.endSession(player: Player): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end

	_sessions[player.UserId] = nil
	return entry.session:endSession():andThen(function(result: any)
		return result
	end)
end

function M.requestQuestion(player: Player, request: { [string]: any }): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	entry.questionViews += 1
	entry.lastQuestionAt = os.clock()
	return entry.session:getNextQuestion(request)
end

function M.submitAnswer(player: Player, payload: { questionId: string, answer: any, responseTimeMs: number?, difficulty: number? }): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:submitAnswer(payload.questionId, payload.answer, payload.responseTimeMs, payload.difficulty)
end

function M.skipQuestion(player: Player, payload: { questionId: string, reason: string? }): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:skipQuestion(payload.questionId, payload.reason)
end

function M.requestHint(player: Player, payload: { questionId: string, hintIndex: number? }): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:getHint(payload.questionId, payload.hintIndex)
end

function M.linkProfile(player: Player, code: string): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:verifyPairingCode(code)
end

function M.getProfile(profileId: string): any
	ensureInitialized()
	return PlayPath.getProfile(profileId)
end

function M.getStandards(skillIds: { string }, frameworkCode: string?): any
	return PlayPath.getStandards(skillIds, frameworkCode)
end

function M.getCapabilities(): any
	ensureInitialized()
	return cacheCapabilities()
end

function M.getSessionStatus(player: Player): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:getSessionStatus()
end

function M.submitGrade(player: Player, score: number, maxScore: number, comment: string?): any
	ensureInitialized()
	local entry = withSessionRecord(player)
	if entry == nil then
		return noSessionError()
	end
	return entry.session:submitGrade(score, maxScore, comment)
end

function M.trackEvent(player: Player, eventPayload: { [string]: any })
	local entry = withSessionRecord(player)
	if entry == nil then
		return
	end
	entry.session:trackEvent(eventPayload)
end

function M.getSessionCapabilities(player: Player): any?
	local entry = withSessionRecord(player)
	if entry == nil then
		return nil
	end
	return entry.capabilities
end

function M.clearSession(player: Player)
	_sessions[player.UserId] = nil
end

Players.PlayerRemoving:Connect(function(player)
	local entry = withSessionRecord(player)
	if entry ~= nil then
		entry.session:endSession()
	end
	_sessions[player.UserId] = nil
end)

return M
