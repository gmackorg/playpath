--!strict
--[[
    PlayPath Roblox Lua SDK (Server-only ModuleScript)
    
    Drop into ReplicatedStorage, require from ServerScriptService.
    Promise-based API with HMAC-SHA256 signing and event batching.
    
    Usage:
        local PlayPath = require(game.ReplicatedStorage.PlayPath)
        
        PlayPath.init({
            gameKeyId = "your-game-key-id",
            apiKeySecret = "your-secret",
        })
        
        PlayPath.createSession(player):andThen(function(session)
            session:getNextQuestion():andThen(function(question)
                -- handle question
            end)
        end)
]]

local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerScriptService = game:GetService("ServerScriptService")

local PlayPath = {}

local DefaultOpenApiV1 = {
	paths = {
		time = "/api/v1/time",
		sessions = "/api/v1/sessions",
		questions = "/api/v1/questions",
		hints = "/api/v1/hints",
		events = "/api/v1/events",
		link = "/api/v1/link",
		unlink = "/api/v1/unlink",
		grades = "/api/v1/grades",
		standards = "/api/v1/standards",
		capabilities = "/api/v1/capabilities",
		profileBase = "/api/v1/profile",
	},
	buildSessionPath = function(sessionId)
		return "/api/v1/sessions/" .. sessionId
	end,
	buildQuestionPath = function(questionId)
		return "/api/v1/questions/" .. questionId
	end,
	buildQuestionSkipPath = function(questionId)
		return "/api/v1/questions/" .. questionId .. "/skip"
	end,
	buildProfilePath = function(profileId)
		return "/api/v1/profile/" .. profileId
	end,
}

local function resolveOpenApiV1()
	local generatedFolder = script:FindFirstChild("generated")
	if generatedFolder then
		local moduleScript = generatedFolder:FindFirstChild("OpenApiV1")
		if moduleScript and moduleScript:IsA("ModuleScript") then
			local ok, moduleValue = pcall(require, moduleScript)
			if ok and type(moduleValue) == "table" then
				return moduleValue
			end
		end
	end
	return DefaultOpenApiV1
end

local OpenApiV1 = resolveOpenApiV1()

--------------------------------------------------------------------------------
-- 1) Type Definitions
--------------------------------------------------------------------------------

export type LogLevel = "none" | "error" | "warn" | "debug"

export type InitConfig = {
	gameKeyId: string,
	apiKeySecret: string,
	profilePrefix: string?,
	gameId: string?,
	baseUrl: string?,
	maxRetries: number?,
	retryBackoffMs: number?,
	eventFlushInterval: number?,
	eventFlushThreshold: number?,
	logLevel: LogLevel?,
	mockMode: boolean?,
}

export type PlayPathErrorCode =
	-- API-defined
	"VALIDATION_ERROR"
	| "UNAUTHORIZED"
	| "NOT_FOUND"
	| "RATE_LIMITED"
	| "INTERNAL_ERROR"
	-- SDK-defined
	| "NETWORK_ERROR"
	| "TIMEOUT"
	| "DECODE_ERROR"
	| "ENCODE_ERROR"
	| "SDK_NOT_INITIALIZED"
	| "INVALID_CONFIG"
	| "SESSION_NOT_ACTIVE"
	| "SESSION_ENDING"
	| "SESSION_ENDED"
	| "PLAYER_LEFT"
	| "CONFLICT"
	| "UNKNOWN_ERROR"

export type PlayPathError = {
	code: PlayPathErrorCode,
	message: string,
	statusCode: number?,
	retryable: boolean,
	raw: any?,
	requestId: number | string?,
}

export type StudentConfig = {
	theme: string?,
	interests: { string }?,
	focusSkills: { string }?,
	difficultyRange: { number, number }?,
	sessionLimitMinutes: number?,
}

export type Student = {
	id: string,
	displayName: string,
	gradeLevel: number?,
	config: StudentConfig?,
}

export type SessionConfig = {
	theme: string?,
	focusSkills: { string }?,
	interests: { string }?,
	difficultyRange: { number, number }?,
	sessionLimitMinutes: number?,
}

export type CreateSessionOptions = {
	launchToken: string?,
}

export type QuestionKind =
	"multiple_choice"
	| "number_input"
	| "fraction_visual"
	| "angle_input"
	| "number_line"
	| "matching"
	| "sorting"
	| "unknown"

export type QuestionChoice = {
	id: string,
	text: string,
}

export type Question = {
	id: string,
	kind: QuestionKind?,
	skillId: string?,
	difficulty: number?,
	hints: { string }?,
	expectedTimeMs: number?,
	content: any?,
	prompt: string?,
	text: string?,
	choices: { QuestionChoice }?,
	raw: any?,
}

export type GetNextQuestionResponse = {
	personalization: any?,
	questions: { Question }?,
	question: Question?,
	raw: any?,
}

export type MasteryUpdate = {
	skillCode: string,
	previousMastery: number,
	newMastery: number,
	delta: number,
}

export type AnswerResult = {
	correct: boolean,
	feedback: string?,
	masteryUpdates: { MasteryUpdate }?,
	nextReviewAt: any?,
	raw: any?,
}

export type SkipQuestionResponse = {
	skipped: boolean?,
	raw: any?,
}

export type HintResult = {
	hint: string,
	hintIndex: number,
	totalHints: number,
	isLastHint: boolean,
	raw: any?,
}

export type LearningEvent = {
	type: string,
	skillId: string?,
	responseTimeMs: number?,
	difficulty: number?,
	data: { [string]: any }?,
	questionId: string?,
	correct: boolean?,
	question: string?,
	properties: { [string]: any }?,
	idempotencyKey: string?,
	timestamp: number?,
}

export type BatchResult = {
	accepted: number,
	rejected: number,
	raw: any?,
}

export type GradeResult = {
	success: boolean,
	sessionId: string?,
	status: "queued" | "blocked"?,
	reasonCode:
		| "QUEUED"
		| "LMS_DISABLED"
		| "NO_RESOURCE_LINK"
		| "NO_LINEITEM_URL"
		| "SESSION_UNLINKED_STUDENT"
		| "STUDENT_MISSING_LTI_SUB"?,
	scoreSubmitted: boolean?,
	error: string?,
	raw: any?,
}

export type ServerTimeResponse = {
	serverTimeMs: number,
	maxDriftMs: number,
	raw: any?,
}

export type LinkResult = {
	success: boolean,
	student: Student?,
	error: string?,
	raw: any?,
}

export type EndSessionResponse = {
	success: boolean?,
	sessionId: string?,
	alreadyEnded: boolean?,
}

export type Profile = {
	profileId: string,
	linked: boolean,
	student: Student?,
	mastery: { MasteryUpdate }?,
	raw: any?,
}

export type GetProfileResult = {
	linked: boolean,
	student: Student?,
	raw: any?,
}

export type Standard = {
	code: string,
	shortCode: string,
	description: string,
	framework: string,
	jurisdiction: string,
	isPrimary: boolean,
}

export type StandardAlignment = {
	skillId: string,
	standards: { Standard }?,
}

export type StandardsResult = {
	success: boolean,
	data: { StandardAlignment }?,
	requestId: string?,
	timestamp: any?,
	raw: any?,
}

export type SessionStatusResponse = {
	sessionId: string,
	linked: boolean,
	status: "active" | "ended",
	student: Student?,
	startedAt: string?,
	endedAt: string?,
	durationSeconds: number?,
	eventsCount: number?,
	raw: any?,
}

export type UnlinkResult = {
	success: boolean,
	unlinked: boolean,
	raw: any?,
}

export type CapabilitiesResult = {
	apiVersion: string,
	endpoints: { string }?,
	features: { [string]: boolean }?,
	rateLimits: { [string]: any }?,
	raw: any?,
}

export type Session = {
	sessionId: string,
	player: Player,
	linked: boolean,
	pairingCode: string?,
	student: Student?,
	profileId: string,
	config: SessionConfig?,

	getNextQuestion: (self: Session, count: number?, options: QuestionOptions?) -> any,
	submitAnswer: (self: Session, questionId: string, answer: any, responseTimeMs: number?, difficulty: number?) -> any,
	skipQuestion: (self: Session, questionId: string, reason: string?) -> any,
	getHint: (self: Session, questionId: string, hintIndex: number?) -> any,
	trackEvent: (self: Session, event: LearningEvent) -> (),
	flush: (self: Session) -> any,
	getStandards: (self: Session, skillIds: { string }, frameworkCode: string?) -> any,
	verifyPairingCode: (self: Session, code: string) -> any,
	unlinkProfile: (self: Session) -> any,
	getSessionStatus: (self: Session) -> any,
	getProfile: (self: Session) -> any,
	submitGrade: (self: Session, score: number, maxScore: number, comment: string?) -> any,
	endSession: (self: Session) -> any,
}

export type QuestionOptions = {
	skill: string?,
	context: { [string]: any }?,
}

-- Internal types
type HttpMethod = "GET" | "POST"
type SessionState = "CREATING" | "ACTIVE" | "ENDING" | "ENDED"

--------------------------------------------------------------------------------
-- 2) Constants + Utilities
--------------------------------------------------------------------------------

local DEFAULT_BASE_URL = "https://play.gmac.io"
local DEFAULT_MAX_RETRIES = 3
local DEFAULT_RETRY_BACKOFF_MS = 1000
local DEFAULT_FLUSH_INTERVAL = 5
local DEFAULT_FLUSH_THRESHOLD = 10
local MAX_QUEUE_SIZE = 1000

local VALID_EVENT_TYPES: { [string]: boolean } = {
	answer = true,
	hint_used = true,
	skill_demo = true,
	session_start = true,
	session_end = true,
	question_viewed = true,
	question_skipped = true,
	hint_requested = true,
}

local function nowUnixSeconds(): number
	return os.time()
end

local function nowUnixMilliseconds(): number
	-- Prefer DateTime when available (Roblox), fall back to os.time.
	local ok, dt = pcall(function()
		return DateTime.now()
	end)
	if ok and dt ~= nil then
		local anyDate = dt :: any
		local ok2, ms = pcall(function()
			return anyDate.UnixTimestampMilliseconds
		end)
		if ok2 and type(ms) == "number" then
			return ms
		end
		local ok3, legacyMs = pcall(function()
			return anyDate.UnixTimestampMillis
		end)
		if ok3 and type(legacyMs) == "number" then
			return legacyMs
		end
		local ok4, fallbackMs = pcall(function()
			return anyDate.UnixTimestamp * 1000
		end)
		if ok4 and type(fallbackMs) == "number" then
			return fallbackMs
		end
	end
	return os.time() * 1000
end

local function makeEndpointSet(endpoints: any): { [string]: boolean }
	local set: { [string]: boolean } = {}
	if type(endpoints) ~= "table" then
		return set
	end

	for _, endpoint in ipairs(endpoints) do
		if type(endpoint) == "string" then
			set[endpoint] = true
			set[string.lower(endpoint)] = true
		end
	end

	return set
end

local function hasEndpoint(endpointsSet: { [string]: boolean }, endpoint: string): boolean
	if type(endpointsSet) ~= "table" or type(endpoint) ~= "string" then
		return false
	end
	local direct = endpointsSet[endpoint]
	if direct then
		return true
	end
	return endpointsSet[string.lower(endpoint)] == true
end

local function normalizeCapabilitiesResponse(resp: any): any
	if type(resp) ~= "table" then
		return resp
	end

	local out = shallowCopy(resp)
	if type(out.features) ~= "table" then
		out.features = {}
	end

	local features = shallowCopy(out.features)
	local endpointSet = makeEndpointSet(out.endpoints)

	if type(features.supportsUnlink) ~= "boolean" then
		features.supportsUnlink = hasEndpoint(endpointSet, OpenApiV1.paths.unlink)
	end
	if type(features.supportsSessionIntrospection) ~= "boolean" then
		features.supportsSessionIntrospection = hasEndpoint(endpointSet, OpenApiV1.paths.sessions)
	end
	if type(features.supportsCapabilities) ~= "boolean" then
		features.supportsCapabilities = hasEndpoint(endpointSet, OpenApiV1.paths.capabilities)
	end
	if type(features.supportsProfileLookup) ~= "boolean" then
		features.supportsProfileLookup = hasEndpoint(endpointSet, OpenApiV1.paths.profileBase)
	end
	if type(features.supportsStandards) ~= "boolean" then
		features.supportsStandards = hasEndpoint(endpointSet, OpenApiV1.paths.standards)
	end

	out.features = features
	return out
end

local function isPlayerAlive(player: Player): boolean
	return player and player.Parent ~= nil
end

local function uuid(): string
	return HttpService:GenerateGUID(false)
end

local function profileIdForUserId(userId: number, cfg: InitConfig?): string
	local prefix = "roblox"
	if cfg and type(cfg.profilePrefix) == "string" and cfg.profilePrefix ~= "" then
		prefix = cfg.profilePrefix
	end
	return string.format("%s-%d", prefix, userId)
end

local function safeJsonEncode(value: any): (boolean, string)
	local ok, result = pcall(function()
		return HttpService:JSONEncode(value)
	end)
	if ok then
		return true, result
	else
		return false, ""
	end
end

local function safeJsonDecode(json: string): (boolean, any)
	local ok, result = pcall(function()
		return HttpService:JSONDecode(json)
	end)
	return ok, result
end

local function shallowCopy<T>(t: T & {}): T
	local copy = table.clone(t :: any)
	return copy :: any
end

local function getHeaderValue(headers: { [string]: string }?, key: string): string?
	if type(headers) ~= "table" then
		return nil
	end
	for headerKey, value in pairs(headers) do
		if string.lower(headerKey) == string.lower(key) then
			return tostring(value)
		end
	end
	return nil
end

local function normalizeQuestionKind(kind: any): QuestionKind
	if kind == "multiple_choice" then
		return "multiple_choice"
	end
	if kind == "number_input" then
		return "number_input"
	end
	if kind == "fraction_visual" then
		return "fraction_visual"
	end
	if kind == "angle_input" then
		return "angle_input"
	end
	if kind == "number_line" then
		return "number_line"
	end
	if kind == "matching" then
		return "matching"
	end
	if kind == "sorting" then
		return "sorting"
	end
	if kind == "numeric" or kind == "free_response" then
		return "number_input"
	end
	return "unknown"
end

local function normalizeQuestionChoices(rawOptions: any): { QuestionChoice }?
	if type(rawOptions) ~= "table" then
		return nil
	end

	local out: { QuestionChoice } = {}
	for i, opt in ipairs(rawOptions) do
		if type(opt) == "string" then
			table.insert(out, { id = tostring(i), text = opt })
		elseif type(opt) == "table" then
			local id = opt.id
			if type(id) ~= "string" then
				id = tostring(i)
			end
			local text = opt.text
			if type(text) ~= "string" then
				text = opt.label
			end
			if type(text) == "string" then
				table.insert(out, { id = id, text = text })
			end
		end
	end

	if #out == 0 then
		return nil
	end
	return out
end

local function normalizeQuestion(rawQuestion: any): Question
	if type(rawQuestion) ~= "table" then
		return { id = "", kind = "unknown", raw = rawQuestion }
	end

	local id = rawQuestion.id
	local kind = normalizeQuestionKind(rawQuestion.type or rawQuestion.kind)
	local skillId = if type(rawQuestion.skillId) == "string" then rawQuestion.skillId else nil
	local difficulty = if type(rawQuestion.difficulty) == "number" then rawQuestion.difficulty else nil
	local hints = if type(rawQuestion.hints) == "table" then rawQuestion.hints else nil
	local expectedTimeMs = if type(rawQuestion.expectedTimeMs) == "number" then rawQuestion.expectedTimeMs else nil

	-- New API shape uses question.content.prompt/options.
	local prompt = nil
	local choices = nil
	if type(rawQuestion.content) == "table" then
		if type(rawQuestion.content.prompt) == "string" then
			prompt = rawQuestion.content.prompt
		end
		choices = normalizeQuestionChoices(rawQuestion.content.options)
	end

	-- Legacy API shape uses prompt/choices directly.
	if prompt == nil and type(rawQuestion.prompt) == "string" then
		prompt = rawQuestion.prompt
	end
	if prompt == nil and type(rawQuestion.text) == "string" then
		prompt = rawQuestion.text
	end
	if choices == nil and type(rawQuestion.choices) == "table" then
		choices = normalizeQuestionChoices(rawQuestion.choices)
	end

	return {
		id = if type(id) == "string" then id else "",
		kind = kind,
		skillId = skillId,
		difficulty = difficulty,
		hints = hints,
		expectedTimeMs = expectedTimeMs,
		content = rawQuestion.content,
		prompt = prompt,
		text = rawQuestion.text,
		choices = choices,
		raw = rawQuestion,
	}
end

--------------------------------------------------------------------------------
-- 3) Logger
--------------------------------------------------------------------------------

local Logger = {}
Logger.__index = Logger

local LEVEL_NUM: { [string]: number } = {
	none = 0,
	error = 1,
	warn = 2,
	debug = 3,
}

function Logger.new(level: LogLevel)
	local self = setmetatable({
		_level = level,
		_levelNum = LEVEL_NUM[level] or 2,
	}, Logger)
	return self
end

function Logger:_shouldLog(level: string): boolean
	local levelNum = LEVEL_NUM[level] or 0
	return self._levelNum >= levelNum
end

function Logger:error(msg: string, ctx: any?)
	if not self:_shouldLog("error") then
		return
	end
	if ctx ~= nil then
		warn("[PlayPath][ERROR]", msg, ctx)
	else
		warn("[PlayPath][ERROR]", msg)
	end
end

function Logger:warn(msg: string, ctx: any?)
	if not self:_shouldLog("warn") then
		return
	end
	if ctx ~= nil then
		warn("[PlayPath][WARN]", msg, ctx)
	else
		warn("[PlayPath][WARN]", msg)
	end
end

function Logger:debug(msg: string, ctx: any?)
	if not self:_shouldLog("debug") then
		return
	end
	if ctx ~= nil then
		print("[PlayPath][DEBUG]", msg, ctx)
	else
		print("[PlayPath][DEBUG]", msg)
	end
end

--------------------------------------------------------------------------------
-- 4) Promise Detection + Fallback
--------------------------------------------------------------------------------

local function loadExternalPromise(): any?
	local function tryRequire(inst: Instance?): any?
		if inst == nil or not inst:IsA("ModuleScript") then
			return nil
		end
		local ok, mod = pcall(function()
			return require(inst :: ModuleScript)
		end)
		if not ok or type(mod) ~= "table" then
			return nil
		end
		-- Validate Promise shape
		if type(mod.new) ~= "function" then
			return nil
		end
		if type(mod.resolve) ~= "function" then
			return nil
		end
		if type(mod.reject) ~= "function" then
			return nil
		end
		return mod
	end

	-- Check child of this script
	local child = script:FindFirstChild("Promise")
	local fromChild = tryRequire(child)
	if fromChild then
		return fromChild
	end

	-- Check ReplicatedStorage
	local rs = ReplicatedStorage:FindFirstChild("Promise")
	local fromRS = tryRequire(rs)
	if fromRS then
		return fromRS
	end

	-- Check ServerScriptService
	local sss = ServerScriptService:FindFirstChild("Promise")
	local fromSSS = tryRequire(sss)
	if fromSSS then
		return fromSSS
	end

	return nil
end

-- Minimal Promise implementation (fallback)
local function createFallbackPromise()
	local Promise = {}
	Promise.__index = Promise

	type PromiseStatus = "pending" | "resolved" | "rejected"

	function Promise.new(executor: (resolve: (any) -> (), reject: (any) -> ()) -> ())
		local self = setmetatable({
			_status = "pending" :: PromiseStatus,
			_value = nil :: any,
			_handlers = {} :: {
				{
					onResolve: ((any) -> any)?,
					onReject: ((any) -> any)?,
					resolve: (any) -> (),
					reject: (any) -> (),
				}
			},
		}, Promise)

		local reject: (any) -> ()
		local function resolve(value: any)
			if self._status ~= "pending" then
				return
			end

			-- Handle promise chaining
			if type(value) == "table" and type(value.andThen) == "function" then
				value:andThen(resolve, reject)
				return
			end

			self._status = "resolved"
			self._value = value
			self:_executeHandlers()
		end

		reject = function(reason: any)
			if self._status ~= "pending" then
				return
			end
			self._status = "rejected"
			self._value = reason
			self:_executeHandlers()
		end

		task.spawn(function()
			local ok, err = pcall(executor, resolve, reject)
			if not ok then
				reject(err)
			end
		end)

		return self
	end

	function Promise:_executeHandlers()
		for _, handler in ipairs(self._handlers) do
			task.spawn(function()
				if self._status == "resolved" then
					if handler.onResolve then
						local ok, result = pcall(handler.onResolve, self._value)
						if ok then
							handler.resolve(result)
						else
							handler.reject(result)
						end
					else
						handler.resolve(self._value)
					end
				elseif self._status == "rejected" then
					if handler.onReject then
						local ok, result = pcall(handler.onReject, self._value)
						if ok then
							handler.resolve(result)
						else
							handler.reject(result)
						end
					else
						handler.reject(self._value)
					end
				end
			end)
		end
		self._handlers = {}
	end

	function Promise:andThen(onResolve: ((any) -> any)?, onReject: ((any) -> any)?): any
		return Promise.new(function(resolve, reject)
			local handler = {
				onResolve = onResolve,
				onReject = onReject,
				resolve = resolve,
				reject = reject,
			}

			if self._status == "pending" then
				table.insert(self._handlers, handler)
			else
				table.insert(self._handlers, handler)
				self:_executeHandlers()
			end
		end)
	end

	function Promise:catch(onReject: (any) -> any): any
		return self:andThen(nil, onReject)
	end

	function Promise:finally(onFinally: () -> ()): any
		return self:andThen(function(value)
			onFinally()
			return value
		end, function(reason)
			onFinally()
			return Promise.reject(reason)
		end)
	end

	function Promise.resolve(value: any): any
		return Promise.new(function(resolve, _)
			resolve(value)
		end)
	end

	function Promise.reject(reason: any): any
		return Promise.new(function(_, reject)
			reject(reason)
		end)
	end

	function Promise.try(fn: () -> any): any
		return Promise.new(function(resolve, reject)
			local ok, result = pcall(fn)
			if ok then
				resolve(result)
			else
				reject(result)
			end
		end)
	end

	function Promise.delay(seconds: number): any
		return Promise.new(function(resolve, _)
			task.delay(seconds, function()
				resolve(nil)
			end)
		end)
	end

	function Promise.all(promises: { any }): any
		return Promise.new(function(resolve, reject)
			local results = {}
			local remaining = #promises

			if remaining == 0 then
				resolve(results)
				return
			end

			for i, promise in ipairs(promises) do
				promise:andThen(function(value)
					results[i] = value
					remaining = remaining - 1
					if remaining == 0 then
						resolve(results)
					end
				end, function(reason)
					reject(reason)
				end)
			end
		end)
	end

	return Promise
end

-- Load Promise (external or fallback)
local Promise = loadExternalPromise() or createFallbackPromise()

--------------------------------------------------------------------------------
-- 5) Crypto (SHA256 + HMAC-SHA256)
--------------------------------------------------------------------------------

local Crypto = {}

-- SHA256 implementation
-- Based on pure Lua implementations optimized for Roblox/Luau
do
	local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
	local rshift, lshift = bit32.rshift, bit32.lshift
	local rrotate = bit32.rrotate

	-- SHA256 constants
	local K = {
		0x428a2f98,
		0x71374491,
		0xb5c0fbcf,
		0xe9b5dba5,
		0x3956c25b,
		0x59f111f1,
		0x923f82a4,
		0xab1c5ed5,
		0xd807aa98,
		0x12835b01,
		0x243185be,
		0x550c7dc3,
		0x72be5d74,
		0x80deb1fe,
		0x9bdc06a7,
		0xc19bf174,
		0xe49b69c1,
		0xefbe4786,
		0x0fc19dc6,
		0x240ca1cc,
		0x2de92c6f,
		0x4a7484aa,
		0x5cb0a9dc,
		0x76f988da,
		0x983e5152,
		0xa831c66d,
		0xb00327c8,
		0xbf597fc7,
		0xc6e00bf3,
		0xd5a79147,
		0x06ca6351,
		0x14292967,
		0x27b70a85,
		0x2e1b2138,
		0x4d2c6dfc,
		0x53380d13,
		0x650a7354,
		0x766a0abb,
		0x81c2c92e,
		0x92722c85,
		0xa2bfe8a1,
		0xa81a664b,
		0xc24b8b70,
		0xc76c51a3,
		0xd192e819,
		0xd6990624,
		0xf40e3585,
		0x106aa070,
		0x19a4c116,
		0x1e376c08,
		0x2748774c,
		0x34b0bcb5,
		0x391c0cb3,
		0x4ed8aa4a,
		0x5b9cca4f,
		0x682e6ff3,
		0x748f82ee,
		0x78a5636f,
		0x84c87814,
		0x8cc70208,
		0x90befffa,
		0xa4506ceb,
		0xbef9a3f7,
		0xc67178f2,
	}

	-- Initial hash values
	local H0 = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}

	local function preprocessMessage(message: string): { number }
		local len = #message
		local bitLen = len * 8

		-- Convert to bytes
		local bytes = {}
		for i = 1, len do
			bytes[i] = string.byte(message, i)
		end

		-- Append bit '1'
		bytes[len + 1] = 0x80

		-- Pad to 56 mod 64 bytes
		local padLen = (56 - (len + 1) % 64) % 64
		for i = 1, padLen do
			bytes[len + 1 + i] = 0x00
		end

		-- Append original length as 64-bit big-endian
		local finalLen = #bytes
		for i = 7, 0, -1 do
			bytes[finalLen + 8 - i] = band(rshift(bitLen, i * 8), 0xFF)
		end

		return bytes
	end

	local function bytesToWords(bytes: { number }, start: number): { number }
		local words = {}
		for i = 0, 15 do
			local idx = start + i * 4
			words[i + 1] = bor(
				lshift(bytes[idx] or 0, 24),
				lshift(bytes[idx + 1] or 0, 16),
				lshift(bytes[idx + 2] or 0, 8),
				bytes[idx + 3] or 0
			)
		end
		return words
	end

	local function sha256Raw(message: string): { number }
		local bytes = preprocessMessage(message)

		-- Initialize hash values
		local H = {}
		for i = 1, 8 do
			H[i] = H0[i]
		end

		-- Process each 64-byte chunk
		for chunkStart = 1, #bytes, 64 do
			local W = bytesToWords(bytes, chunkStart)

			-- Extend the 16 words into 64 words
			for i = 17, 64 do
				local s0 = bxor(rrotate(W[i - 15], 7), rrotate(W[i - 15], 18), rshift(W[i - 15], 3))
				local s1 = bxor(rrotate(W[i - 2], 17), rrotate(W[i - 2], 19), rshift(W[i - 2], 10))
				W[i] = band(W[i - 16] + s0 + W[i - 7] + s1, 0xFFFFFFFF)
			end

			-- Initialize working variables
			local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

			-- Main loop
			for i = 1, 64 do
				local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
				local ch = bxor(band(e, f), band(bnot(e), g))
				local temp1 = band(h + S1 + ch + K[i] + W[i], 0xFFFFFFFF)
				local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
				local maj = bxor(band(a, b), band(a, c), band(b, c))
				local temp2 = band(S0 + maj, 0xFFFFFFFF)

				h = g
				g = f
				f = e
				e = band(d + temp1, 0xFFFFFFFF)
				d = c
				c = b
				b = a
				a = band(temp1 + temp2, 0xFFFFFFFF)
			end

			-- Add compressed chunk to hash
			H[1] = band(H[1] + a, 0xFFFFFFFF)
			H[2] = band(H[2] + b, 0xFFFFFFFF)
			H[3] = band(H[3] + c, 0xFFFFFFFF)
			H[4] = band(H[4] + d, 0xFFFFFFFF)
			H[5] = band(H[5] + e, 0xFFFFFFFF)
			H[6] = band(H[6] + f, 0xFFFFFFFF)
			H[7] = band(H[7] + g, 0xFFFFFFFF)
			H[8] = band(H[8] + h, 0xFFFFFFFF)
		end

		return H
	end

	local function wordsToHex(words: { number }): string
		local hex = ""
		for _, word in ipairs(words) do
			hex = hex .. string.format("%08x", word)
		end
		return hex
	end

	local function wordsToBytes(words: { number }): string
		local bytes = {}
		for _, word in ipairs(words) do
			table.insert(
				bytes,
				string.char(
					band(rshift(word, 24), 0xFF),
					band(rshift(word, 16), 0xFF),
					band(rshift(word, 8), 0xFF),
					band(word, 0xFF)
				)
			)
		end
		return table.concat(bytes)
	end

	function Crypto.sha256Hex(message: string): string
		return wordsToHex(sha256Raw(message))
	end

	function Crypto.sha256Binary(message: string): string
		return wordsToBytes(sha256Raw(message))
	end

	function Crypto.hmacSha256Hex(key: string, message: string): string
		local blockSize = 64

		-- If key is longer than block size, hash it
		if #key > blockSize then
			key = Crypto.sha256Binary(key)
		end

		-- Pad key to block size
		if #key < blockSize then
			key = key .. string.rep("\0", blockSize - #key)
		end

		-- Create inner and outer padded keys
		local oKeyPad = {}
		local iKeyPad = {}
		for i = 1, blockSize do
			local keyByte = string.byte(key, i)
			oKeyPad[i] = string.char(bxor(keyByte, 0x5c))
			iKeyPad[i] = string.char(bxor(keyByte, 0x36))
		end

		local oKeyPadStr = table.concat(oKeyPad)
		local iKeyPadStr = table.concat(iKeyPad)

		-- HMAC = H(oKeyPad || H(iKeyPad || message))
		local innerHash = Crypto.sha256Binary(iKeyPadStr .. message)
		return Crypto.sha256Hex(oKeyPadStr .. innerHash)
	end
end

--------------------------------------------------------------------------------
-- 6) Errors
--------------------------------------------------------------------------------

local Errors = {}

function Errors.make(
	code: PlayPathErrorCode,
	message: string,
	statusCode: number?,
	retryable: boolean,
	raw: any?,
	requestId: number?
): PlayPathError
	return {
		code = code,
		message = message,
		statusCode = statusCode,
		retryable = retryable,
		raw = raw,
		requestId = requestId,
	}
end

local STATUS_TO_ERROR: { [number]: { code: PlayPathErrorCode, retryable: boolean } } = {
	[400] = { code = "VALIDATION_ERROR", retryable = false },
	[401] = { code = "UNAUTHORIZED", retryable = false },
	[404] = { code = "NOT_FOUND", retryable = false },
	[403] = { code = "UNAUTHORIZED", retryable = false },
	[409] = { code = "CONFLICT", retryable = true },
	[413] = { code = "VALIDATION_ERROR", retryable = false },
	[429] = { code = "RATE_LIMITED", retryable = true },
	[503] = { code = "INTERNAL_ERROR", retryable = true },
}

function Errors.fromHttp(
	statusCode: number,
	bodyText: string,
	headers: { [string]: string }?,
	requestId: number | string?
): PlayPathError
	local requestIdFromHeaders = getHeaderValue(headers, "x-request-id")
	if requestIdFromHeaders ~= nil then
		requestId = requestIdFromHeaders
	end
	-- Try to decode JSON error from body
	local ok, decoded = safeJsonDecode(bodyText)
	if ok and type(decoded) == "table" then
		-- New error shape:
		-- { error: { code: string, message: string, details?: any } }
		local errObj = (decoded :: any).error
		if type(errObj) == "table" then
			local serverCode = (errObj :: any).code
			local serverMsg = (errObj :: any).message
			if type(serverCode) == "string" then
				local retryable = (statusCode == 429) or (statusCode >= 500)
				return Errors.make(
					serverCode :: PlayPathErrorCode,
					if type(serverMsg) == "string" then serverMsg else "Request failed",
					statusCode,
					retryable,
					decoded,
					requestId
				)
			end
		end

		-- Legacy error shape:
		-- { code: string, message: string }
		local legacyCode = (decoded :: any).code
		local legacyMsg = (decoded :: any).message
		if type(legacyCode) == "string" then
			local retryable = (statusCode == 429) or (statusCode >= 500)
			return Errors.make(
				legacyCode :: PlayPathErrorCode,
				if type(legacyMsg) == "string" then legacyMsg else "Request failed",
				statusCode,
				retryable,
				decoded,
				requestId
			)
		end
	end

	-- 5xx errors
	if statusCode >= 500 then
		return Errors.make(
			"INTERNAL_ERROR",
			"Server error",
			statusCode,
			true,
			{ body = bodyText, headers = headers },
			requestId
		)
	end

	-- Map by status code
	local mapped = STATUS_TO_ERROR[statusCode]
	if mapped then
		return Errors.make(
			mapped.code,
			"Request failed",
			statusCode,
			mapped.retryable,
			{ body = bodyText, headers = headers },
			requestId
		)
	end

	return Errors.make(
		"UNKNOWN_ERROR",
		"Request failed with status " .. tostring(statusCode),
		statusCode,
		false,
		{ body = bodyText, headers = headers },
		requestId
	)
end

function Errors.fromTransport(err: any, requestId: number | string?): PlayPathError
	local message = tostring(err)
	-- Check for common Roblox HTTP errors
	if string.find(message:lower(), "http requests are not enabled") then
		message = "HTTP requests are not enabled. Enable in Game Settings > Security."
	end
	return Errors.make("NETWORK_ERROR", message, nil, true, err, requestId)
end

--------------------------------------------------------------------------------
-- 7) Mock Mode
--------------------------------------------------------------------------------

local Mock = {}
Mock._sessions = {} :: { [string]: any }
Mock._questionCounter = 0
Mock._eventHistory = {} :: { [string]: { [string]: boolean } }

local function getMockStudent(profileId: string): any?
	local matched = string.match(profileId, "^roblox%-(%d+)$")
	if type(matched) ~= "string" then
		return {
			id = uuid(),
			displayName = "Student " .. profileId,
			gradeLevel = 4,
			config = {
				theme = "space",
				interests = { "math", "ela" },
				focusSkills = { "math.fractions", "sor.vocabulary" },
				difficultyRange = { 1, 10 },
				sessionLimitMinutes = 30,
			},
		}
	end

	local userId = tonumber(matched) or 0
	if userId % 2 == 1 then
		return nil
	end

	return {
		id = uuid(),
		displayName = "Student " .. profileId,
		gradeLevel = 5,
		config = {
			theme = "space",
			interests = { "math", "ela" },
			focusSkills = { "math.fractions", "sor.vocabulary" },
			difficultyRange = { 1, 10 },
			sessionLimitMinutes = 30,
		},
	}
end

local function makeMockConfig(): any
	return {
		theme = "space",
		interests = { "math", "ela" },
		focusSkills = { "math.fractions", "sor.vocabulary" },
		difficultyRange = { 1, 10 },
		sessionLimitMinutes = 30,
	}
end

local MOCK_HINTS = {
	"Think about what the question is really asking.",
	"Try breaking down the problem into smaller parts.",
	"Remember the fundamental concepts we learned earlier.",
}

local MOCK_QUESTIONS = {
	{
		skillId = "11111111-1111-1111-1111-111111111111",
		kind = "multiple_choice",
		difficulty = 4,
		hints = { "Look at the sizes of the pieces." },
		content = {
			prompt = "Which fraction is larger?",
			options = { "1/2", "3/4", "1/3", "5/6" },
		},
		expectedTimeMs = 30000,
	},
	{
		skillId = "22222222-2222-2222-2222-222222222222",
		kind = "number_input",
		difficulty = 3,
		hints = { "Use multiplication facts." },
		content = {
			prompt = "What is 6 x 7?",
			correctAnswer = 42,
			acceptedFormats = { "42", "forty-two" },
		},
		expectedTimeMs = 20000,
	},
	{
		skillId = "33333333-3333-3333-3333-333333333333",
		kind = "fraction_visual",
		difficulty = 5,
		hints = { "Compare shaded and unshaded parts." },
		content = {
			prompt = "What fraction is shown?",
			visual = { type = "pie", numerator = 1, denominator = 4 },
			options = { "1/4", "2/4", "3/4", "1/2" },
		},
		expectedTimeMs = 35000,
	},
	{
		skillId = "44444444-4444-4444-4444-444444444444",
		kind = "angle_input",
		difficulty = 4,
		hints = { "Estimate from the number line." },
		content = {
			prompt = "Measure this angle",
			visual = { type = "angle", degrees = 45 },
			correctAnswer = 45,
			tolerance = 5,
		},
		expectedTimeMs = 25000,
	},
	{
		skillId = "55555555-5555-5555-5555-555555555555",
		kind = "number_line",
		difficulty = 4,
		hints = { "Place the value on the line." },
		content = {
			prompt = "Place 1/2 on the number line",
			range = { min = 0, max = 1 },
			divisions = 8,
			correctAnswer = 0.5,
			tolerance = 0.05,
		},
		expectedTimeMs = 25000,
	},
}

local MOCK_STANDARDS = {
	{
		skillId = "11111111-1111-1111-1111-111111111111",
		standards = {
			{
				code = "3.NF.A.1",
				shortCode = "3.NF.A.1",
				description = "Add and subtract fractions with like denominators",
				framework = "TEKS",
				jurisdiction = "US-TX",
				isPrimary = true,
			},
		},
	},
	{
		skillId = "22222222-2222-2222-2222-222222222222",
		standards = {
			{
				code = "RL.5.1",
				shortCode = "5.1",
				description = "Read literature and support ideas",
				framework = "CCSS",
				jurisdiction = "US-CA",
				isPrimary = true,
			},
		},
	},
}

local function getQuestionTemplate(skillId: string): any?
	for _, template in ipairs(MOCK_QUESTIONS) do
		if template.skillId == skillId then
			return template
		end
	end
	return nil
end

function Mock.reset()
	Mock._sessions = {}
	Mock._questionCounter = 0
	Mock._eventHistory = {}
end

function Mock.handle(
	method: HttpMethod,
	path: string,
	bodyJson: string,
	_headers: { [string]: string },
	_cfg: InitConfig
): (number, string, { [string]: string })
	local body = {}
	if bodyJson ~= "" then
		local ok, decoded = safeJsonDecode(bodyJson)
		if ok then
			body = decoded
		end
	end

	-- GET /api/v1/time
	if method == "GET" and path == OpenApiV1.paths.time then
		return 200, HttpService:JSONEncode({ serverTimeMs = nowUnixMilliseconds(), maxDriftMs = 300000 }), {}
	end

	-- POST /api/v1/sessions
	if method == "POST" and path == OpenApiV1.paths.sessions then
		local sessionId = uuid()
		local profileId = body.profileId or "roblox-0"
		local student = getMockStudent(profileId)

		local session = {
			sessionId = sessionId,
			profileId = profileId,
			linked = student ~= nil,
			pairingCode = if student == nil then string.upper(string.sub(uuid(), 1, 6)) else nil,
			student = student,
			config = makeMockConfig(),
			currentQuestionIndex = 0,
			masteryBySkill = { ["math.fractions"] = 0.5 },
		}
		Mock._sessions[sessionId] = session

		local response = {
			sessionId = sessionId,
			linked = student ~= nil,
			pairingCode = session.pairingCode,
			student = session.student,
			config = session.config,
			sessionToken = nil,
		}
		return 200, HttpService:JSONEncode(response), {}
	end

	-- POST /api/v1/sessions/{sessionId}
	if method == "POST" and string.match(path, "^" .. OpenApiV1.paths.sessions .. "/[^/]+$") then
		local sessionId = string.match(path, "^" .. OpenApiV1.paths.sessions .. "/([^/]+)$")
		if sessionId and Mock._sessions[sessionId] then
			Mock._sessions[sessionId] = nil
		end
		return 200, HttpService:JSONEncode({ success = true, sessionId = sessionId }), {}
	end

	-- POST /api/v1/questions
	if method == "POST" and path == OpenApiV1.paths.questions then
		Mock._questionCounter = Mock._questionCounter + 1
		local idx = ((Mock._questionCounter - 1) % #MOCK_QUESTIONS) + 1
		local template = MOCK_QUESTIONS[idx]
		if type(body.skill) == "string" then
			local preferredTemplate = getQuestionTemplate(body.skill)
			if preferredTemplate ~= nil then
				template = preferredTemplate
			end
		end

		local question = {
			id = uuid(),
			kind = template.kind,
			skillId = template.skillId,
			difficulty = template.difficulty,
			hints = template.hints,
			content = template.content,
			expectedTimeMs = template.expectedTimeMs,
			raw = { expectedAnswer = template.content.correctAnswer },
		}

		return 200,
			HttpService:JSONEncode({
				question = question,
				personalization = {
					theme = nil,
					themedContent = nil,
				},
			}),
			{}
	end

	-- POST /api/v1/questions/{questionId}
	if method == "POST" and string.match(path, "^" .. OpenApiV1.paths.questions .. "/[^/]+$") then
		local _answer = body.answer
		local correct = (math.random() > 0.3) -- 70% correct for demo
		local skillCode = "math.fractions"
		local delta = if correct then 0.05 else -0.02

		local response = {
			correct = correct,
			feedback = if correct then "Great job!" else "Not quite. Try again!",
			masteryUpdates = {
			{
				skillCode = skillCode,
				previousMastery = 0.5,
				newMastery = 0.5 + delta,
				delta = delta,
			},
			},
			nextReviewAt = DateTime.now():ToIsoDate(),
		}
		return 200, HttpService:JSONEncode(response), {}
	end

	-- POST /api/v1/questions/:id/skip
	if method == "POST" and string.match(path, "^" .. OpenApiV1.paths.questions .. "/[^/]+/skip$") then
		return 200, HttpService:JSONEncode({ success = true }), {}
	end

	-- POST /api/v1/hints
	if method == "POST" and path == OpenApiV1.paths.hints then
		local hintIndex = body.hintIndex or 0
		local totalHints = #MOCK_HINTS
		local actualIndex = math.min(hintIndex, totalHints - 1)

		local response = {
			hint = MOCK_HINTS[actualIndex + 1],
			hintIndex = actualIndex,
			totalHints = totalHints,
			isLastHint = (actualIndex == totalHints - 1),
		}
		return 200, HttpService:JSONEncode(response), {}
	end

	-- POST /api/v1/events
	if method == "POST" and path == OpenApiV1.paths.events then
		local events = body.events or {}
		local sessionId = tostring(body.sessionId or "")
		local seen = Mock._eventHistory[sessionId]
		if seen == nil then
			seen = {}
			Mock._eventHistory[sessionId] = seen
		end

		local accepted = 0
		local rejected = 0
		if type(events) == "table" then
			for _, event in ipairs(events) do
				local key = event and event.idempotencyKey
				if type(key) == "string" and key ~= "" then
					if seen[key] then
						rejected += 1
					else
						seen[key] = true
						accepted += 1
					end
				else
					accepted += 1
				end
			end
		end

		return 200, HttpService:JSONEncode({ accepted = accepted, rejected = rejected }), {}
	end

	-- POST /api/v1/link
	if method == "POST" and path == OpenApiV1.paths.link then
		local pairingCode = body.pairingCode
		if type(pairingCode) == "string" then
			pairingCode = string.upper(pairingCode)
		end

		-- Find session with matching pairing code
		for _sessionId, session in pairs(Mock._sessions) do
			if session.pairingCode == pairingCode and session.profileId == body.profileId then
				session.linked = true
				session.student = getMockStudent(session.profileId)
				session.pairingCode = nil
				return 200, HttpService:JSONEncode({
					success = true,
					student = session.student,
				}), {}
			end
		end

		return 200,
			HttpService:JSONEncode({
				success = false,
				student = nil,
				error = "Invalid pairing code",
			}),
			{}
	end

	-- POST /api/v1/grades
	if method == "POST" and path == OpenApiV1.paths.grades then
		local sessionId = body.sessionId
		return 200,
			HttpService:JSONEncode({
				success = true,
				sessionId = sessionId,
				status = "queued",
				reasonCode = "QUEUED",
				scoreSubmitted = false,
				error = "LMS integration disabled",
			}),
			{}
	end

	-- POST /api/v1/standards
	if method == "POST" and path == OpenApiV1.paths.standards then
		local skillIds = body.skillIds
		local requestedFramework = if type(body.frameworkCode) == "string" then string.lower(body.frameworkCode) else nil
		local response = {}
		if type(skillIds) == "table" then
			for _, requestedSkillId in ipairs(skillIds) do
				if type(requestedSkillId) == "string" then
					for _, entry in ipairs(MOCK_STANDARDS) do
						if entry.skillId == requestedSkillId then
							if requestedFramework == nil then
								table.insert(response, entry)
							else
								local hasMatch = false
								for _, standard in ipairs(entry.standards) do
									if type(standard.framework) == "string" and string.lower(standard.framework) == requestedFramework then
										hasMatch = true
										break
									end
								end
								if hasMatch then
									table.insert(response, entry)
								end
							end
							break
						end
					end
				end
			end
		end

		return 200,
			HttpService:JSONEncode({
				success = true,
				data = response,
				requestId = uuid(),
				timestamp = DateTime.now():ToIsoDate(),
			}),
			{}
	end

	-- GET /api/v1/profile/:robloxUserId
	if method == "GET" and string.match(path, "^" .. OpenApiV1.paths.profileBase .. "/[^/]+$") then
		local profileId = string.match(path, "^" .. OpenApiV1.paths.profileBase .. "/([^/]+)$") or "roblox-0"
		local student = getMockStudent(profileId)
		return 200,
			HttpService:JSONEncode({
				linked = student ~= nil,
				student = student,
			}),
			{}
	end

	-- POST /api/v1/unlink
	if method == "POST" and path == OpenApiV1.paths.unlink then
		local profileId = body.profileId
		local unlinked = false
		for _sessionId, session in pairs(Mock._sessions) do
			if session.profileId == profileId then
				session.linked = false
				session.student = nil
				unlinked = true
			end
		end
		return 200, HttpService:JSONEncode({ success = true, unlinked = unlinked }), {}
	end

	-- GET /api/v1/sessions/{sessionId}
	if method == "GET" and string.match(path, "^" .. OpenApiV1.paths.sessions .. "/[^/]+$") then
		local sessionId = string.match(path, "^" .. OpenApiV1.paths.sessions .. "/([^/]+)$")
		local session = if sessionId then Mock._sessions[sessionId] else nil
		if not sessionId or not session then
			return 404,
				HttpService:JSONEncode({
					error = {
						code = "NOT_FOUND",
						message = "Session not found",
					},
				}),
				{}
		end
		return 200,
			HttpService:JSONEncode({
				sessionId = session.sessionId,
				linked = session.linked,
				status = "active",
				student = session.student,
				startedAt = DateTime.now():ToIsoDate(),
				endedAt = nil,
				durationSeconds = 0,
				eventsCount = 0,
			}),
			{}
	end

	-- GET /api/v1/capabilities
	if method == "GET" and path == OpenApiV1.paths.capabilities then
		return 200,
			HttpService:JSONEncode({
				apiVersion = "v1",
				endpoints = {
					OpenApiV1.paths.sessions,
					OpenApiV1.paths.questions,
					OpenApiV1.paths.events,
					OpenApiV1.paths.link,
					OpenApiV1.paths.unlink,
					OpenApiV1.paths.standards,
					OpenApiV1.paths.profileBase,
					OpenApiV1.paths.capabilities,
				},
				features = {
					supportsStandards = true,
					supportsProfileLookup = true,
					supportsUnlink = true,
					supportsSessionIntrospection = true,
					supportsCapabilities = true,
				},
				rateLimits = {
					sdk_sessions = { limit = 10, windowSeconds = 60 },
				},
			}),
			{}
	end

	-- Unknown endpoint
	return 404,
		HttpService:JSONEncode({
			error = {
				code = "NOT_FOUND",
				message = "Endpoint not found: " .. method .. " " .. path,
			},
		}),
		{}
end

--------------------------------------------------------------------------------
-- 8) HttpClient
--------------------------------------------------------------------------------

local HttpClient = {}
HttpClient.__index = HttpClient

function HttpClient.new(cfg: InitConfig, logger: any)
	local self = setmetatable({
		_cfg = cfg,
		_logger = logger,
		_nextRequestId = 0,
	}, HttpClient)
	return self
end

function HttpClient:_nextId(): number
	self._nextRequestId = self._nextRequestId + 1
	return self._nextRequestId
end

function HttpClient:_signHeaders(
	method: HttpMethod,
	path: string,
	bodyJson: string,
	requestId: number
): { [string]: string }
	-- Canonical contract (see ../playpath/docs/ROBLOX_SDK_API.md):
	-- canonical = "{timestampMs}:{nonce}:{METHOD}:{pathname}:{bodySha256Hex}"
	local timestampMs = tostring(nowUnixMilliseconds())
	local nonce = uuid()
	local bodyHash = Crypto.sha256Hex(bodyJson)
	local canonical = string.format("%s:%s:%s:%s:%s", timestampMs, nonce, method, path, bodyHash)
	local signature = "sha256=" .. Crypto.hmacSha256Hex(self._cfg.apiKeySecret, canonical)

	return {
		["Content-Type"] = "application/json",
		["x-api-key"] = self._cfg.gameKeyId,
		["x-timestamp"] = timestampMs,
		["x-nonce"] = nonce,
		["x-signature"] = signature,
		["x-request-id"] = tostring(requestId),
	}
end

function HttpClient:request(method: HttpMethod, path: string, bodyTable: any?): any
	local requestId = self:_nextId()
	local cfg = self._cfg
	local logger = self._logger

	return Promise.new(function(resolve, reject)
		task.spawn(function()
			-- Encode body
			local bodyJson = ""
			if bodyTable ~= nil then
				local ok, encoded = safeJsonEncode(bodyTable)
				if not ok then
					reject(
						Errors.make("ENCODE_ERROR", "Failed to encode request body", nil, false, bodyTable, requestId)
					)
					return
				end
				bodyJson = encoded
			end

			-- Build headers
			local headers: { [string]: string }
			if method == "GET" and path == OpenApiV1.paths.time then
				headers = {
					["Content-Type"] = "application/json",
					["x-request-id"] = tostring(requestId),
				}
			else
				headers = self:_signHeaders(method, path, bodyJson, requestId)
			end

			-- URL
			local baseUrl = cfg.baseUrl or DEFAULT_BASE_URL
			local url = baseUrl .. path

			-- Retry configuration
			local maxRetries = cfg.maxRetries or DEFAULT_MAX_RETRIES
			local backoffMs = cfg.retryBackoffMs or DEFAULT_RETRY_BACKOFF_MS

			local attempt = 1
			local lastError: PlayPathError? = nil

			local function doRequest()
				logger:debug(string.format("HTTP %s %s (requestId=%d, attempt=%d)", method, path, requestId, attempt))

				-- Mock mode
				if cfg.mockMode then
					local statusCode, respJson, respHeaders = Mock.handle(method, path, bodyJson, headers, cfg)

					if statusCode >= 200 and statusCode < 300 then
						if respJson == "" then
							resolve({})
							return true
						end
						local ok, decoded = safeJsonDecode(respJson)
						if not ok then
							reject(
								Errors.make(
									"DECODE_ERROR",
									"Failed to decode response",
									statusCode,
									false,
									respJson,
									requestId
								)
							)
							return true
						end
						resolve(decoded)
						return true
					else
						lastError = Errors.fromHttp(statusCode, respJson, respHeaders, requestId)
						return false
					end
				end

				-- Real HTTP request
				local ok, resp = pcall(function()
					local params: any = {
						Url = url,
						Method = method,
						Headers = headers,
					}
					if method == "POST" and bodyJson ~= "" then
						params.Body = bodyJson
					end
					return HttpService:RequestAsync(params)
				end)

				if not ok then
					lastError = Errors.fromTransport(resp, requestId)
					return false
				end

				local response = resp :: any
				local statusCode = response.StatusCode
				local respBody = response.Body or ""
				local respHeaders = response.Headers or {}

				logger:debug(string.format("HTTP %s %s -> %d (requestId=%d)", method, path, statusCode, requestId))

				if statusCode >= 200 and statusCode < 300 then
					if respBody == "" then
						resolve({})
						return true
					end
					local decodeOk, decoded = safeJsonDecode(respBody)
					if not decodeOk then
						reject(
							Errors.make(
								"DECODE_ERROR",
								"Failed to decode response",
								statusCode,
								false,
								respBody,
								requestId
							)
						)
						return true
					end
					resolve(decoded)
					return true
				else
					lastError = Errors.fromHttp(statusCode, respBody, respHeaders, requestId)
					return false
				end
			end

			-- Retry loop
			while attempt <= maxRetries + 1 do
				local success = doRequest()
				if success then
					return
				end

				-- Check if we should retry
				if lastError and not lastError.retryable then
					reject(lastError)
					return
				end

				if attempt > maxRetries then
					reject(lastError)
					return
				end

				-- Calculate backoff with jitter
				local retryAfter = 0
				if lastError and lastError.statusCode == 429 and lastError.raw and type(lastError.raw) == "table" then
					local headers = lastError.raw.headers
					local raText = getHeaderValue(headers, "Retry-After")
					if raText ~= nil then
						local ra = tonumber(raText)
						if ra then
							retryAfter = ra
						end
					end
				end

				local exponentialMs = backoffMs * (2 ^ (attempt - 1))
				local baseDelayMs = math.max(exponentialMs, retryAfter * 1000)
				local jitter = 1 + (math.random() * 0.1)
				local delayMs = baseDelayMs * jitter

				logger:warn(
					string.format(
						"Retrying in %.0fms (attempt %d/%d, requestId=%d)",
						delayMs,
						attempt + 1,
						maxRetries + 1,
						requestId
					)
				)

				task.wait(delayMs / 1000)
				attempt = attempt + 1
			end

			reject(lastError)
		end)
	end)
end

--------------------------------------------------------------------------------
-- 9) Session Class
--------------------------------------------------------------------------------

local SessionImpl = {}
SessionImpl.__index = SessionImpl

function SessionImpl.new(player: Player, client: any, logger: any, createResp: any, cfg: InitConfig)
	local self = setmetatable({
		-- Public properties
		sessionId = createResp.sessionId,
		player = player,
		linked = createResp.linked or false,
		pairingCode = createResp.pairingCode,
		student = createResp.student,
		profileId = createResp.profileId or profileIdForUserId(player.UserId, cfg),
		config = createResp.config,

		-- Internal state
		_client = client,
		_logger = logger,
		_cfg = cfg,
		_state = "ACTIVE" :: SessionState,

		-- Session bookkeeping
		_startedAtMs = nowUnixMilliseconds(),
		_eventsCount = 0,

		-- Event batching
		_eventQueue = {} :: { LearningEvent },
		_flushThread = nil :: thread?,
		_flushInFlight = nil :: any?,

		-- Concurrent operation tracking
		_endInFlight = nil :: any?,
		_linkInFlight = nil :: any?,
		_endedAt = nil :: number?,
	}, SessionImpl)

	-- Start flush loop
	self:_startFlushLoop()

	return (self :: any) :: Session
end

function SessionImpl:_startFlushLoop()
	local interval = self._cfg.eventFlushInterval or DEFAULT_FLUSH_INTERVAL

	self._flushThread = task.spawn(function()
		while self._state == "ACTIVE" do
			task.wait(interval)

			-- Check if still active
			if self._state ~= "ACTIVE" then
				break
			end

			-- Check if player left
			if not isPlayerAlive(self.player) then
				self._state = "ENDED"
				break
			end

			-- Flush if there are events
			if #self._eventQueue > 0 then
				self:flush()
			end
		end
	end)
end

function SessionImpl:_ensureActive(): (boolean, PlayPathError?)
	if not isPlayerAlive(self.player) then
		return false, Errors.make("PLAYER_LEFT", "Player left the game", nil, false, nil, nil)
	end
	if self._state == "ENDED" then
		return false, Errors.make("SESSION_ENDED", "Session has ended", nil, false, nil, nil)
	end
	if self._state == "ENDING" then
		return false, Errors.make("SESSION_ENDING", "Session is ending", nil, false, nil, nil)
	end
	return true, nil
end

function SessionImpl:getNextQuestion(countOrOptions: any, options: QuestionOptions?): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	-- The current v1 contract uses POST /api/v1/questions.
	local requestOptions = options
	if type(countOrOptions) == "table" and options == nil then
		requestOptions = countOrOptions
	elseif type(countOrOptions) == "number" then
		self._logger:debug("getNextQuestion called with legacy count argument", { count = countOrOptions })
	elseif countOrOptions ~= nil then
		self._logger:warn("getNextQuestion called with unsupported argument shape", { argType = type(countOrOptions) })
	end

	local context = {
		game = self._cfg.gameId or self.profileId,
	}
	if self.config and self.config.theme then
		context.theme = self.config.theme
	end
	if requestOptions and type(requestOptions.context) == "table" then
		for key, value in pairs(requestOptions.context) do
			context[key] = value
		end
	end

	local body: any = {
		sessionId = self.sessionId,
		studentId = self.student and self.student.id or nil,
		context = context,
	}
	if requestOptions and type(requestOptions.skill) == "string" then
		body.skill = requestOptions.skill
	end

	return self._client:request("POST", OpenApiV1.paths.questions, body):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return { raw = resp }
		end

		local personalization = resp.personalization
		if type(resp.questions) == "table" then
			local questionsOut: { Question } = {}
			for _, q in ipairs(resp.questions) do
				table.insert(questionsOut, normalizeQuestion(q))
			end
			return {
				personalization = personalization,
				questions = questionsOut,
				question = questionsOut[1],
				raw = resp,
			}
		end

		if resp.question ~= nil then
			local q = normalizeQuestion(resp.question)
			return {
				personalization = resp.personalization,
				question = q,
				questions = { q },
				raw = resp,
			}
		end

		return { personalization = resp.personalization, raw = resp }
	end)
end

function SessionImpl:submitAnswer(questionId: string, answer: any, responseTimeMs: number?, difficulty: number?): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	local path = OpenApiV1.buildQuestionPath(questionId)
	local body = {
		sessionId = self.sessionId,
		studentId = self.student and self.student.id or nil,
		answer = answer,
		difficulty = difficulty,
		idempotencyKey = uuid(),
	}
	if type(responseTimeMs) == "number" then
		body.responseTimeMs = responseTimeMs
	end

	return self._client:request("POST", path, body):andThen(function(resp: any)
		if type(resp) == "table" then
			local out = shallowCopy(resp)
			out.raw = resp
			return out
		end
		return { raw = resp }
	end)
end

function SessionImpl:skipQuestion(questionId: string, reason: string?): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	local path = OpenApiV1.buildQuestionSkipPath(questionId)
	local body = {
		sessionId = self.sessionId,
		studentId = self.student and self.student.id or nil,
		reason = reason or "other",
		idempotencyKey = uuid(),
	}

	return self._client:request("POST", path, body)
end

function SessionImpl:getHint(questionId: string, hintIndex: number?): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	local body = {
		sessionId = self.sessionId,
		studentId = self.student and self.student.id or nil,
		questionId = questionId,
		hintIndex = hintIndex or 0,
		idempotencyKey = uuid(),
	}

	return self._client:request("POST", OpenApiV1.paths.hints, body)
end

function SessionImpl:trackEvent(event: LearningEvent)
	-- Silent no-op if not active
	if self._state ~= "ACTIVE" then
		return
	end
	if not isPlayerAlive(self.player) then
		return
	end

	-- Validate event
	if type(event.type) ~= "string" or event.type == "" then
		self._logger:warn("trackEvent called with invalid event type")
		return
	end
	if not VALID_EVENT_TYPES[event.type] then
		self._logger:warn("trackEvent unknown type", { type = event.type })
	end

	-- Clone and populate defaults
	local e: LearningEvent = shallowCopy(event)
	if e.idempotencyKey == nil then
		e.idempotencyKey = uuid()
	end
	if e.data == nil and e.properties ~= nil and type(e.properties) == "table" then
		e.data = e.properties
	end
	if e.properties == nil and e.data ~= nil and type(e.data) == "table" then
		e.properties = e.data
	end
	if e.data == nil then
		e.data = {}
	end
	if e.timestamp == nil then
		e.timestamp = nowUnixMilliseconds()
	end

	-- Add to queue
	table.insert(self._eventQueue, e)
	self._eventsCount += 1

	-- Enforce max queue size (drop oldest)
	while #self._eventQueue > MAX_QUEUE_SIZE do
		table.remove(self._eventQueue, 1)
		self._logger:warn("Event queue exceeded max size, dropping oldest event")
	end

	-- Trigger flush if threshold reached
	local threshold = self._cfg.eventFlushThreshold or DEFAULT_FLUSH_THRESHOLD
	if #self._eventQueue >= threshold then
		-- Non-blocking flush
		task.spawn(function()
			self:flush()
		end)
	end
end

function SessionImpl:flush(): any
	-- Coalesce concurrent flushes
	if self._flushInFlight ~= nil then
		return self._flushInFlight
	end

	-- Nothing to flush
	if #self._eventQueue == 0 then
		return Promise.resolve({ accepted = 0, rejected = 0 })
	end

	-- Snapshot and clear queue
	local batch = self._eventQueue
	self._eventQueue = {}

	local body = {
		sessionId = self.sessionId,
		events = batch,
	}

	local p = self._client
		:request("POST", OpenApiV1.paths.events, body)
		:catch(function(err: PlayPathError)
			-- On retryable error, put events back
			if err.retryable then
				-- Prepend batch back to queue
				local merged = {}
				for _, ev in ipairs(batch) do
					table.insert(merged, ev)
				end
				for _, ev in ipairs(self._eventQueue) do
					table.insert(merged, ev)
				end
				self._eventQueue = merged
				self._logger:warn("Flush failed (retryable), events re-queued", { count = #batch })
			else
				self._logger:warn(
					"Flush failed (non-retryable), events dropped",
					{ count = #batch, error = err.message }
				)
			end
			return Promise.reject(err)
		end)
		:finally(function()
			self._flushInFlight = nil
		end)

	self._flushInFlight = p
	return p
end

function SessionImpl:verifyPairingCode(code: string): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	-- Coalesce concurrent link attempts
	if self._linkInFlight ~= nil then
		return self._linkInFlight
	end

	local body = {
		profileId = self.profileId,
		pairingCode = if type(code) == "string" then string.upper(code) else code,
		sessionId = self.sessionId,
	}

	local p = self._client
		:request("POST", OpenApiV1.paths.link, body)
		:andThen(function(resp: any)
			if resp and resp.success == true then
				self.linked = true
				self.student = resp.student
				self.pairingCode = nil
			end
			return resp
		end)
		:finally(function()
			self._linkInFlight = nil
		end)

	self._linkInFlight = p
	return p
end

function SessionImpl:unlinkProfile(): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	local body = {
		profileId = self.profileId,
	}

	return self._client:request("POST", OpenApiV1.paths.unlink, body):andThen(function(resp: any)
		if type(resp) == "table" and resp.success == true then
			self.linked = false
			self.student = nil
		end
		return resp
	end)
end

function SessionImpl:getSessionStatus(): any
	local path = OpenApiV1.buildSessionPath(self.sessionId)
	return self._client:request("GET", path, nil):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return { raw = resp }
		end
		local out = shallowCopy(resp)
		out.raw = resp
		return out
	end)
end

function SessionImpl:getProfile(): any
	return PlayPath.getProfile(self.profileId)
end

function SessionImpl:getStandards(skillIds: { string }, frameworkCode: string?): any
	local body = {
		skillIds = skillIds,
	}
	if frameworkCode ~= nil then
		body.frameworkCode = frameworkCode
	end

	return self._client:request("POST", OpenApiV1.paths.standards, body):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return { raw = resp }
		end
		local out = shallowCopy(resp)
		out.raw = resp
		return out
	end)
end

function SessionImpl:submitGrade(score: number, maxScore: number, comment: string?): any
	local ok, err = self:_ensureActive()
	if not ok then
		return Promise.reject(err)
	end

	local body = {
		sessionId = self.sessionId,
		score = score,
		maxScore = maxScore,
		comment = comment,
	}

	return self._client:request("POST", OpenApiV1.paths.grades, body)
end

function SessionImpl:endSession(): any
	-- Already ending or ended
	if self._endInFlight ~= nil then
		return self._endInFlight
	end
	if self._state == "ENDED" then
		return Promise.resolve({ ok = true, alreadyEnded = true })
	end

	-- Mark as ending
	self._state = "ENDING"

	-- Best-effort flush, then end session
	local p = Promise.try(function()
		if #self._eventQueue > 0 then
			return self:flush()
		end
		return Promise.resolve(nil)
	end)
		:catch(function(_)
			-- Ignore flush errors during teardown
			return nil
		end)
		:andThen(function()
			local path = OpenApiV1.buildSessionPath(self.sessionId)
			local durationSeconds = math.floor((nowUnixMilliseconds() - (self._startedAtMs :: number)) / 1000)
			return self._client:request("POST", path, {
				summary = {
					duration = durationSeconds,
					eventsCount = self._eventsCount,
				},
			})
		end)
		:finally(function()
			self._state = "ENDED"
			self._endedAt = nowUnixSeconds()
			self._endInFlight = nil
		end)

	self._endInFlight = p
	return p
end

--------------------------------------------------------------------------------
-- 10) PlayPath Public API
--------------------------------------------------------------------------------

local _initialized = false
local _cfg: InitConfig? = nil
local _logger: any = nil
local _client: any = nil

local function validateConfig(cfg: any): (boolean, string?)
	if type(cfg) ~= "table" then
		return false, "Config must be a table"
	end
	if type(cfg.gameKeyId) ~= "string" or cfg.gameKeyId == "" then
		return false, "gameKeyId is required and must be a non-empty string"
	end
	if type(cfg.apiKeySecret) ~= "string" or cfg.apiKeySecret == "" then
		return false, "apiKeySecret is required and must be a non-empty string"
	end
	return true, nil
end

function PlayPath.init(cfg: InitConfig)
	local ok, errMsg = validateConfig(cfg)
	if not ok then
		error("[PlayPath] " .. (errMsg or "Invalid config"))
	end

	-- Resolve config with defaults
	local resolved: InitConfig = {
		gameKeyId = cfg.gameKeyId,
		apiKeySecret = cfg.apiKeySecret,
		gameId = cfg.gameId,
		baseUrl = cfg.baseUrl or DEFAULT_BASE_URL,
		maxRetries = cfg.maxRetries or DEFAULT_MAX_RETRIES,
		retryBackoffMs = cfg.retryBackoffMs or DEFAULT_RETRY_BACKOFF_MS,
		eventFlushInterval = cfg.eventFlushInterval or DEFAULT_FLUSH_INTERVAL,
		eventFlushThreshold = cfg.eventFlushThreshold or DEFAULT_FLUSH_THRESHOLD,
		logLevel = cfg.logLevel or "warn",
		mockMode = cfg.mockMode or false,
	}

	_cfg = resolved
	_logger = Logger.new(resolved.logLevel or "warn")
	_client = HttpClient.new(resolved, _logger)
	_initialized = true

	_logger:debug("PlayPath SDK initialized", { mockMode = resolved.mockMode })
end

function PlayPath.createSession(player: Player, opts: CreateSessionOptions?): any
	if not _initialized or _cfg == nil or _client == nil then
		return Promise.reject(
			Errors.make(
				"SDK_NOT_INITIALIZED",
				"PlayPath.init() must be called before createSession()",
				nil,
				false,
				nil,
				nil
			)
		)
	end

	if not isPlayerAlive(player) then
		return Promise.reject(Errors.make("PLAYER_LEFT", "Player is not in the game", nil, false, nil, nil))
	end

	local body = {
		profileId = profileIdForUserId(player.UserId, _cfg),
		gameId = _cfg.gameId,
		launchToken = if opts then opts.launchToken else nil,
	}

	return _client:request("POST", OpenApiV1.paths.sessions, body):andThen(function(resp: any)
		-- Check if player still in game
		if not isPlayerAlive(player) then
			return Promise.reject(
				Errors.make("PLAYER_LEFT", "Player left during session creation", nil, false, nil, nil)
			)
		end

		local session = SessionImpl.new(player, _client, _logger, resp, _cfg :: InitConfig)
		return session
	end)
end

function PlayPath.getProfile(profileId: string): any
	if not _initialized or _cfg == nil or _client == nil then
		return Promise.reject(
			Errors.make(
				"SDK_NOT_INITIALIZED",
				"PlayPath.init() must be called before getProfile()",
				nil,
				false,
				nil,
				nil
			)
		)
	end

	if type(profileId) ~= "string" or profileId == "" then
		return Promise.reject(Errors.make("INVALID_CONFIG", "Profile ID must be a non-empty string", nil, false, nil, nil))
	end

	local path = OpenApiV1.buildProfilePath(profileId)
	return _client:request("GET", path, nil):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return Promise.reject(Errors.make("DECODE_ERROR", "Malformed /api/v1/profile response", nil, false, resp, nil))
		end
		local out = shallowCopy(resp)
		out.raw = resp
		return out
	end)
end

function PlayPath.getStandards(skillIds: { string }, frameworkCode: string?): any
	if not _initialized or _cfg == nil or _client == nil then
		return Promise.reject(
			Errors.make(
				"SDK_NOT_INITIALIZED",
				"PlayPath.init() must be called before getStandards()",
				nil,
				false,
				nil,
				nil
			)
		)
	end

	if type(skillIds) ~= "table" then
		return Promise.reject(Errors.make("INVALID_CONFIG", "skillIds must be an array", nil, false, nil, nil))
	end

	local body = {
		skillIds = skillIds,
	}
	if frameworkCode ~= nil then
		body.frameworkCode = frameworkCode
	end

	return _client:request("POST", OpenApiV1.paths.standards, body):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return Promise.reject(Errors.make("DECODE_ERROR", "Malformed /api/v1/standards response", nil, false, resp, nil))
		end
		local out = shallowCopy(resp)
		out.raw = resp
		return out
	end)
end

function PlayPath.getServerTime(): any
	if not _initialized or _cfg == nil or _client == nil then
		return Promise.reject(
			Errors.make(
				"SDK_NOT_INITIALIZED",
				"PlayPath.init() must be called before getServerTime()",
				nil,
				false,
				nil,
				nil
			)
		)
	end

	return _client:request("GET", OpenApiV1.paths.time, nil):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return Promise.reject(Errors.make("DECODE_ERROR", "Malformed /api/v1/time response", nil, false, resp, nil))
		end
		local serverTimeMs = resp.serverTimeMs
		local maxDriftMs = resp.maxDriftMs
		if type(serverTimeMs) ~= "number" or type(maxDriftMs) ~= "number" then
			return Promise.reject(Errors.make("DECODE_ERROR", "Malformed /api/v1/time response", nil, false, resp, nil))
		end
		return {
			serverTimeMs = serverTimeMs,
			maxDriftMs = maxDriftMs,
			raw = resp,
		}
	end)
end

function PlayPath.getCapabilities(): any
	if not _initialized or _cfg == nil or _client == nil then
		return Promise.reject(
			Errors.make(
				"SDK_NOT_INITIALIZED",
				"PlayPath.init() must be called before getCapabilities()",
				nil,
				false,
				nil,
				nil
			)
		)
	end

	return _client:request("GET", OpenApiV1.paths.capabilities, nil):andThen(function(resp: any)
		if type(resp) ~= "table" then
			return Promise.reject(
				Errors.make("DECODE_ERROR", "Malformed /api/v1/capabilities response", nil, false, resp, nil)
			)
		end
		local out = normalizeCapabilitiesResponse(resp)
		out.raw = resp
		return out
	end)
end

--------------------------------------------------------------------------------
-- 11) Self-Tests (Internal)
--------------------------------------------------------------------------------

PlayPath._internal = {}

function PlayPath._internal.runCryptoTests(): boolean
	local passed = true
	local function test(name: string, expected: string, actual: string)
		if expected == actual then
			print("[TEST PASS]", name)
		else
			print("[TEST FAIL]", name)
			print("  Expected:", expected)
			print("  Actual:  ", actual)
			passed = false
		end
	end

	-- SHA256 test vectors
	test(
		"SHA256 empty string",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Crypto.sha256Hex("")
	)
	test("SHA256 'abc'", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Crypto.sha256Hex("abc"))
	test(
		"SHA256 'The quick brown fox jumps over the lazy dog'",
		"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		Crypto.sha256Hex("The quick brown fox jumps over the lazy dog")
	)

	-- HMAC-SHA256 test vectors (RFC 4231)
	test(
		"HMAC-SHA256 test 1",
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		Crypto.hmacSha256Hex("Jefe", "what do ya want for nothing?")
	)

	return passed
end

function PlayPath._internal.runMockTests(): boolean
	local passed = true

	-- Initialize in mock mode
	PlayPath.init({
		gameKeyId = "test-key",
		apiKeySecret = "test-secret",
		mockMode = true,
		logLevel = "none",
	})

	print("[TEST] Starting mock mode tests...")

	-- Create a fake player for testing
	local fakePlayer = {
		UserId = 12345678,
		Parent = game,
	} :: any

	local createdSession: any = nil
	local lastQuestion: any = nil

	local function assert(condition: boolean, label: string)
		if condition then
			print("[TEST PASS]", label)
		else
			print("[TEST FAIL]", label)
			passed = false
		end
	end

	local function assertTable(value: any, label: string)
		assert(type(value) == "table", label)
	end

	PlayPath.getServerTime()
		:andThen(function(info)
			assert(type(info.serverTimeMs) == "number" and type(info.maxDriftMs) == "number", "server time")
			return PlayPath.getCapabilities()
		end)
		:andThen(function(capabilities: any)
			assertTable(capabilities, "getCapabilities")
			return PlayPath.createSession(fakePlayer)
		end)
		:andThen(function(session)
			createdSession = session
			assert(type(session.sessionId) == "string", "createSession.sessionId")
			return createdSession:getNextQuestion({ skill = "math.fractions" })
		end)
		:andThen(function(response: any)
			assertTable(response, "getNextQuestion")
			lastQuestion = response.question
			assert(type(lastQuestion) == "table", "getNextQuestion.question")
			assert(type(response.personalization) == "table" or response.personalization == nil, "getNextQuestion.personalization")
			return createdSession:submitAnswer(lastQuestion.id, lastQuestion.content and lastQuestion.content.correctAnswer, 123, 3)
		end)
		:andThen(function(answerResponse: any)
			assertTable(answerResponse, "submitAnswer")
			assert(answerResponse.correct == true or answerResponse.correct == false or answerResponse.nextReviewAt ~= nil, "submitAnswer.shape")
			return createdSession:skipQuestion(lastQuestion.id, "other")
		end)
		:andThen(function(skipResponse: any)
			assertTable(skipResponse, "skipQuestion")
			return createdSession:getHint(lastQuestion.id, 0)
		end)
		:andThen(function(hintResponse: any)
			assertTable(hintResponse, "requestHint")
			assert(type(hintResponse.hint) == "string", "requestHint.hint")
			createdSession:trackEvent({
				type = "question_viewed",
				questionId = lastQuestion and lastQuestion.id or nil,
				data = { source = "mock" },
				properties = { source = "mock" },
				timestamp = nowUnixMilliseconds(),
			})
			return createdSession:flush()
		})
		:andThen(function(flushResponse: any)
			assertTable(flushResponse, "flush")
			assert(type(flushResponse.accepted) == "number" or type(flushResponse.rejected) == "number", "flush.counts")
			return PlayPath.getProfile(createdSession.profileId)
		})
		:andThen(function(profileResponse: any)
			assertTable(profileResponse, "getProfile")
			assert(type(profileResponse.linked) == "boolean", "getProfile.linked")
			return PlayPath.getStandards({ "11111111-1111-1111-1111-111111111111" }, "TEKS")
		})
		:andThen(function(standardsResponse: any)
			assertTable(standardsResponse, "getStandards")
			return createdSession:getSessionStatus()
		end)
		:andThen(function(statusResponse: any)
			assertTable(statusResponse, "getSessionStatus")
			assert(type(statusResponse.sessionId) == "string", "getSessionStatus.sessionId")
			return createdSession:submitGrade(1, 1, "e2e")
		})
		:andThen(function(gradeResponse: any)
			assertTable(gradeResponse, "submitGrade")
			return createdSession:endSession()
		})
		:andThen(function(endResponse: any)
			assertTable(endResponse, "endSession")
			print("[TEST] Mock tests complete")
		end)
		:catch(function(err)
			assert(false, "mock test chain")
			print("[TEST FAIL] Error:", err.message or tostring(err))
		end)
	return passed
end

-- Expose for testing
PlayPath._internal.Crypto = Crypto
PlayPath._internal.Promise = Promise
PlayPath._internal.Mock = Mock

return PlayPath
