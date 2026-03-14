local OpenApiV1 = require("playpath.core.openapi_v1")

local Session = {}
Session.__index = Session

local function urlEncode(value)
    return tostring(value):gsub("([^%w%-_%.~])", function(char)
        return string.format("%%%02X", string.byte(char))
    end)
end

local function normalizeChoices(options)
    local normalized = {}
    for index, option in ipairs(options or {}) do
        if type(option) == "table" then
            normalized[#normalized + 1] = {
                id = option.id or tostring(index),
                text = option.text or option.label or option.value or tostring(option.id or index),
                value = option.value,
            }
        else
            normalized[#normalized + 1] = {
                id = tostring(index),
                text = tostring(option),
                value = option,
            }
        end
    end
    return normalized
end

local function normalizeQuestion(response)
    local question = response and response.question or nil
    if type(question) ~= "table" then
        return response
    end

    local content = question.content or {}
    question.prompt = question.prompt or content.prompt or content.question or content.text
    question.answerType = question.answerType or content.answerType
    question.correctAnswer = question.correctAnswer or content.correctAnswer
    question.correctAnswerText = question.correctAnswerText or content.correctAnswerText
    question.explanation = question.explanation or content.explanation
    question.visual = question.visual or content.visual
    question.choices = question.choices or normalizeChoices(content.options or content.choices)
    return response
end

function Session.new(client, payload)
    return setmetatable({
        _client = client,
        sessionId = payload.sessionId,
        sessionToken = payload.sessionToken,
        linked = payload.linked,
        config = payload.config or {},
        student = payload.student,
        _eventQueue = {},
    }, Session)
end

function Session:_request(method, path, body, options)
    options = options or {}
    if self.sessionToken and not options.skipSessionToken then
        options.authorization = "Bearer " .. self.sessionToken
    end
    return self._client.http:request(method, path, body, options)
end

function Session:getWorld(worldId)
    local response = self:_request(
        "GET",
        OpenApiV1.paths.worlds .. "?worldId=" .. urlEncode(worldId),
        nil
    )
    return response.body
end

function Session:getStatus()
    local response = self:_request(
        "GET",
        OpenApiV1.paths.sessions .. "?sessionId=" .. urlEncode(self.sessionId),
        nil
    )
    return response.body
end

function Session:getNextQuestion(payload)
    payload = payload or {}
    payload.sessionId = self.sessionId
    local response = self:_request("POST", OpenApiV1.paths.questions, payload)
    return normalizeQuestion(response.body)
end

function Session:submitAnswer(questionId, payload)
    payload = payload or {}
    payload.sessionId = self.sessionId
    payload.idempotencyKey = payload.idempotencyKey or self._client.config.adapter.generateUUID()
    local response = self:_request(
        "POST",
        OpenApiV1.paths.questions .. "/" .. tostring(questionId),
        payload
    )
    return response.body
end

function Session:getHint(payload)
    payload = payload or {}
    payload.sessionId = self.sessionId
    payload.idempotencyKey = payload.idempotencyKey or self._client.config.adapter.generateUUID()
    local response = self:_request("POST", OpenApiV1.paths.hints, payload)
    return response.body
end

function Session:trackEvent(event)
    local queued = {}
    for key, value in pairs(event or {}) do
        queued[key] = value
    end
    queued.idempotencyKey = queued.idempotencyKey or self._client.config.adapter.generateUUID()
    self._eventQueue[#self._eventQueue + 1] = queued
    return queued
end

function Session:flush()
    if #self._eventQueue == 0 then
        return {
            accepted = 0,
            rejected = 0,
        }
    end

    local payload = {
        sessionId = self.sessionId,
        events = self._eventQueue,
    }
    local response = self:_request("POST", OpenApiV1.paths.events, payload)
    self._eventQueue = {}
    return response.body
end

return Session
