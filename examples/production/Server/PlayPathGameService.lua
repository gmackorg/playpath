--!strict
-- Production wrapper sample for studios integrating PlayPath through a single server-owned service.

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local PlayPath = require(ReplicatedStorage:WaitForChild("PlayPath"))

local M = {}

type SessionRecord = {
	session: any,
	lastQuestionId: string?,
	lastQuestionAtMs: number?,
}

local sessionsByUserId: { [number]: SessionRecord } = {}
local capabilitiesCache: any? = nil

local function nowMs(): number
	return os.clock() * 1000
end

function M.init(config: {
	gameKeyId: string,
	apiKeySecret: string,
	baseUrl: string?,
	gameId: string?,
	logLevel: string?,
	mockMode: boolean?,
})
	PlayPath.init({
		gameKeyId = config.gameKeyId,
		apiKeySecret = config.apiKeySecret,
		baseUrl = config.baseUrl,
		gameId = config.gameId,
		logLevel = config.logLevel or "warn",
		mockMode = config.mockMode,
	})

	Players.PlayerRemoving:Connect(function(player)
		M.endSession(player)
	end)
end

function M.getCapabilities(): any
	if capabilitiesCache ~= nil then
		return PlayPath._internal.Promise.resolve(capabilitiesCache)
	end

	return PlayPath.getCapabilities():andThen(function(capabilities: any)
		capabilitiesCache = capabilities
		return capabilities
	end)
end

function M.startSession(player: Player, launchToken: string?): any
	return PlayPath.createSession(player, {
		launchToken = launchToken,
	}):andThen(function(session: any)
		sessionsByUserId[player.UserId] = {
			session = session,
			lastQuestionId = nil,
			lastQuestionAtMs = nil,
		}
		return session
	end)
end

function M.getSession(player: Player): any?
	local record = sessionsByUserId[player.UserId]
	return if record then record.session else nil
end

function M.requestQuestion(player: Player, options: { skill: string?, context: { [string]: any }? }?): any
	local record = sessionsByUserId[player.UserId]
	if record == nil then
		return PlayPath._internal.Promise.reject("No active session")
	end

	return record.session:getNextQuestion(options):andThen(function(result: any)
		local question = result.question
		if type(question) == "table" then
			record.lastQuestionId = question.id
			record.lastQuestionAtMs = nowMs()
		end
		return result
	end)
end

function M.submitAnswer(player: Player, answer: any, questionId: string?, difficulty: number?): any
	local record = sessionsByUserId[player.UserId]
	if record == nil then
		return PlayPath._internal.Promise.reject("No active session")
	end

	local targetQuestionId = questionId or record.lastQuestionId
	if type(targetQuestionId) ~= "string" or targetQuestionId == "" then
		return PlayPath._internal.Promise.reject("No question id available")
	end

	local responseTimeMs = nil
	if type(record.lastQuestionAtMs) == "number" then
		responseTimeMs = math.floor(nowMs() - record.lastQuestionAtMs)
	end

	return record.session:submitAnswer(targetQuestionId, answer, responseTimeMs, difficulty)
end

function M.skipQuestion(player: Player, reason: string?): any
	local record = sessionsByUserId[player.UserId]
	if record == nil or type(record.lastQuestionId) ~= "string" then
		return PlayPath._internal.Promise.reject("No active question")
	end
	return record.session:skipQuestion(record.lastQuestionId, reason or "other")
end

function M.getHint(player: Player, hintIndex: number?): any
	local record = sessionsByUserId[player.UserId]
	if record == nil or type(record.lastQuestionId) ~= "string" then
		return PlayPath._internal.Promise.reject("No active question")
	end
	return record.session:getHint(record.lastQuestionId, hintIndex or 0)
end

function M.trackQuestionViewed(player: Player, question: any)
	local record = sessionsByUserId[player.UserId]
	if record == nil or type(question) ~= "table" then
		return
	end

	record.session:trackEvent({
		type = "question_viewed",
		questionId = question.id,
		data = {
			skillId = question.skillId,
			difficulty = question.difficulty,
			questionType = question.kind,
		},
	})
end

function M.endSession(player: Player): any
	local record = sessionsByUserId[player.UserId]
	if record == nil then
		return PlayPath._internal.Promise.resolve(nil)
	end

	sessionsByUserId[player.UserId] = nil
	record.session:trackEvent({
		type = "session_end",
		data = {
			source = "PlayPathGameService",
		},
	})
	return record.session:endSession()
end

return M
