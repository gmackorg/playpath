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

--------------------------------------------------------------------------------
-- 1) Type Definitions
--------------------------------------------------------------------------------

export type LogLevel = "none" | "error" | "warn" | "debug"

export type InitConfig = {
    gameKeyId: string,
    apiKeySecret: string,
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
    requestId: number?,
}

export type Student = {
    id: string,
    displayName: string,
}

export type SessionConfig = {
    theme: string?,
    focusSkills: {string}?,
}

export type CreateSessionOptions = {
    launchToken: string?,
}

export type QuestionKind = "multiple_choice" | "numeric" | "free_response" | "unknown"

export type QuestionChoice = {
    id: string,
    text: string,
}

export type Question = {
    id: string,
    kind: QuestionKind?,
    prompt: string?,
    choices: {QuestionChoice}?,
    raw: any?,
}

export type GetNextQuestionResponse = {
    questions: {Question}?,
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
    masteryUpdates: {MasteryUpdate}?,
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
    questionId: string?,
    correct: boolean?,
    idempotencyKey: string?,
    timestamp: number?,
    properties: {[string]: any}?,
}

export type BatchResult = {
    accepted: number,
    rejected: number,
    raw: any?,
}

export type LinkResult = {
    success: boolean,
    student: Student?,
    raw: any?,
}

export type EndSessionResponse = {
    ok: boolean?,
    alreadyEnded: boolean?,
}

export type Profile = {
    robloxUserId: number,
    student: Student?,
    mastery: {MasteryUpdate}?,
    raw: any?,
}

export type Session = {
    sessionId: string,
    player: Player,
    linked: boolean,
    pairingCode: string?,
    student: Student?,
    config: SessionConfig?,

    getNextQuestion: (self: Session, count: number?) -> any,
    submitAnswer: (self: Session, questionId: string, answer: any, responseTimeMs: number) -> any,
    skipQuestion: (self: Session, questionId: string, reason: string) -> any,
    getHint: (self: Session, questionId: string, hintIndex: number?) -> any,
    trackEvent: (self: Session, event: LearningEvent) -> (),
    flush: (self: Session) -> any,
    verifyPairingCode: (self: Session, code: string) -> any,
    endSession: (self: Session) -> any,
}

-- Internal types
type HttpMethod = "GET" | "POST"
type SessionState = "CREATING" | "ACTIVE" | "ENDING" | "ENDED"

--------------------------------------------------------------------------------
-- 2) Constants + Utilities
--------------------------------------------------------------------------------

local DEFAULT_BASE_URL = "https://api.playpath.io"
local DEFAULT_MAX_RETRIES = 3
local DEFAULT_RETRY_BACKOFF_MS = 1000
local DEFAULT_FLUSH_INTERVAL = 5
local DEFAULT_FLUSH_THRESHOLD = 10
local MAX_QUEUE_SIZE = 1000

local function nowUnixSeconds(): number
    return os.time()
end

local function isPlayerAlive(player: Player): boolean
    return player and player.Parent ~= nil
end

local function uuid(): string
    return HttpService:GenerateGUID(false)
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
    local copy = {}
    for k, v in pairs(t :: any) do
        copy[k] = v
    end
    return copy :: any
end

--------------------------------------------------------------------------------
-- 3) Logger
--------------------------------------------------------------------------------

local Logger = {}
Logger.__index = Logger

local LEVEL_NUM: {[string]: number} = {
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
    if not self:_shouldLog("error") then return end
    if ctx ~= nil then
        warn("[PlayPath][ERROR]", msg, ctx)
    else
        warn("[PlayPath][ERROR]", msg)
    end
end

function Logger:warn(msg: string, ctx: any?)
    if not self:_shouldLog("warn") then return end
    if ctx ~= nil then
        warn("[PlayPath][WARN]", msg, ctx)
    else
        warn("[PlayPath][WARN]", msg)
    end
end

function Logger:debug(msg: string, ctx: any?)
    if not self:_shouldLog("debug") then return end
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
        if type(mod.new) ~= "function" then return nil end
        if type(mod.resolve) ~= "function" then return nil end
        if type(mod.reject) ~= "function" then return nil end
        return mod
    end

    -- Check child of this script
    local child = script:FindFirstChild("Promise")
    local fromChild = tryRequire(child)
    if fromChild then return fromChild end

    -- Check ReplicatedStorage
    local rs = ReplicatedStorage:FindFirstChild("Promise")
    local fromRS = tryRequire(rs)
    if fromRS then return fromRS end

    -- Check ServerScriptService
    local sss = ServerScriptService:FindFirstChild("Promise")
    local fromSSS = tryRequire(sss)
    if fromSSS then return fromSSS end

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
            _handlers = {} :: {{onResolve: ((any) -> any)?, onReject: ((any) -> any)?, resolve: (any) -> (), reject: (any) -> ()}},
        }, Promise)

        local function resolve(value: any)
            if self._status ~= "pending" then return end
            
            -- Handle promise chaining
            if type(value) == "table" and type(value.andThen) == "function" then
                value:andThen(resolve, reject)
                return
            end
            
            self._status = "resolved"
            self._value = value
            self:_executeHandlers()
        end

        local function reject(reason: any)
            if self._status ~= "pending" then return end
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

    function Promise.all(promises: {any}): any
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
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }

    -- Initial hash values
    local H0 = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    }

    local function preprocessMessage(message: string): {number}
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

    local function bytesToWords(bytes: {number}, start: number): {number}
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

    local function sha256Raw(message: string): {number}
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
                local s0 = bxor(rrotate(W[i-15], 7), rrotate(W[i-15], 18), rshift(W[i-15], 3))
                local s1 = bxor(rrotate(W[i-2], 17), rrotate(W[i-2], 19), rshift(W[i-2], 10))
                W[i] = band(W[i-16] + s0 + W[i-7] + s1, 0xFFFFFFFF)
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

    local function wordsToHex(words: {number}): string
        local hex = ""
        for _, word in ipairs(words) do
            hex = hex .. string.format("%08x", word)
        end
        return hex
    end

    local function wordsToBytes(words: {number}): string
        local bytes = {}
        for _, word in ipairs(words) do
            table.insert(bytes, string.char(
                band(rshift(word, 24), 0xFF),
                band(rshift(word, 16), 0xFF),
                band(rshift(word, 8), 0xFF),
                band(word, 0xFF)
            ))
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

local STATUS_TO_ERROR: {[number]: {code: PlayPathErrorCode, retryable: boolean}} = {
    [400] = { code = "VALIDATION_ERROR", retryable = false },
    [401] = { code = "UNAUTHORIZED", retryable = false },
    [404] = { code = "NOT_FOUND", retryable = false },
    [429] = { code = "RATE_LIMITED", retryable = true },
}

function Errors.fromHttp(
    statusCode: number,
    bodyText: string,
    headers: {[string]: string}?,
    requestId: number?
): PlayPathError
    -- Try to decode JSON error from body
    local ok, decoded = safeJsonDecode(bodyText)
    if ok and type(decoded) == "table" then
        local serverCode = decoded.code
        local serverMsg = decoded.message
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

function Errors.fromTransport(err: any, requestId: number?): PlayPathError
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
Mock._sessions = {} :: {[string]: any}
Mock._questionCounter = 0

local MOCK_HINTS = {
    "Think about what the question is really asking.",
    "Try breaking down the problem into smaller parts.",
    "Remember the fundamental concepts we learned earlier.",
}

local MOCK_QUESTIONS = {
    {
        kind = "multiple_choice",
        prompt = "Which fraction is larger?",
        choices = {
            { id = "a", text = "1/2" },
            { id = "b", text = "3/4" },
        },
        expectedAnswer = "b",
    },
    {
        kind = "numeric",
        prompt = "What is 6 x 7?",
        expectedAnswer = 42,
    },
    {
        kind = "multiple_choice",
        prompt = "What is the square root of 64?",
        choices = {
            { id = "a", text = "6" },
            { id = "b", text = "7" },
            { id = "c", text = "8" },
            { id = "d", text = "9" },
        },
        expectedAnswer = "c",
    },
}

function Mock.reset()
    Mock._sessions = {}
    Mock._questionCounter = 0
end

function Mock.handle(
    method: HttpMethod,
    path: string,
    bodyJson: string,
    headers: {[string]: string},
    cfg: InitConfig
): (number, string, {[string]: string})
    local body = {}
    if bodyJson ~= "" then
        local ok, decoded = safeJsonDecode(bodyJson)
        if ok then
            body = decoded
        end
    end

    -- POST /api/v1/sessions/start
    if method == "POST" and path == "/api/v1/sessions/start" then
        local sessionId = uuid()
        local robloxUserId = body.robloxUserId or 0
        local linked = (robloxUserId % 2 == 0)
        
        local session = {
            sessionId = sessionId,
            robloxUserId = robloxUserId,
            linked = linked,
            pairingCode = if linked then nil else string.upper(string.sub(uuid(), 1, 6)),
            student = if linked then { id = uuid(), displayName = "TestStudent" } else nil,
            config = { theme = "space", focusSkills = {"math.fractions"} },
            currentQuestionIndex = 0,
            masteryBySkill = { ["math.fractions"] = 0.5 },
        }
        Mock._sessions[sessionId] = session
        
        local response = {
            sessionId = sessionId,
            linked = linked,
            pairingCode = session.pairingCode,
            student = session.student,
            config = session.config,
        }
        return 200, HttpService:JSONEncode(response), {}
    end

    -- POST /api/v1/sessions/:id/end
    if method == "POST" and string.match(path, "^/api/v1/sessions/[^/]+/end$") then
        local sessionId = body.sessionId
        if sessionId and Mock._sessions[sessionId] then
            Mock._sessions[sessionId] = nil
        end
        return 200, HttpService:JSONEncode({ ok = true }), {}
    end

    -- POST /api/v1/questions/next
    if method == "POST" and path == "/api/v1/questions/next" then
        Mock._questionCounter = Mock._questionCounter + 1
        local idx = ((Mock._questionCounter - 1) % #MOCK_QUESTIONS) + 1
        local template = MOCK_QUESTIONS[idx]
        
        local question = {
            id = uuid(),
            kind = template.kind,
            prompt = template.prompt,
            choices = template.choices,
            raw = { expectedAnswer = template.expectedAnswer },
        }
        
        local count = body.count or 1
        if count > 1 then
            local questions = { question }
            for i = 2, count do
                Mock._questionCounter = Mock._questionCounter + 1
                local idx2 = ((Mock._questionCounter - 1) % #MOCK_QUESTIONS) + 1
                local template2 = MOCK_QUESTIONS[idx2]
                table.insert(questions, {
                    id = uuid(),
                    kind = template2.kind,
                    prompt = template2.prompt,
                    choices = template2.choices,
                    raw = { expectedAnswer = template2.expectedAnswer },
                })
            end
            return 200, HttpService:JSONEncode({ questions = questions }), {}
        end
        
        return 200, HttpService:JSONEncode({ question = question }), {}
    end

    -- POST /api/v1/questions/:id/answer
    if method == "POST" and string.match(path, "^/api/v1/questions/[^/]+/answer$") then
        local answer = body.answer
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
                }
            },
        }
        return 200, HttpService:JSONEncode(response), {}
    end

    -- POST /api/v1/questions/:id/skip
    if method == "POST" and string.match(path, "^/api/v1/questions/[^/]+/skip$") then
        return 200, HttpService:JSONEncode({ skipped = true }), {}
    end

    -- POST /api/v1/hints
    if method == "POST" and path == "/api/v1/hints" then
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

    -- POST /api/v1/events/batch
    if method == "POST" and path == "/api/v1/events/batch" then
        local events = body.events or {}
        return 200, HttpService:JSONEncode({ accepted = #events, rejected = 0 }), {}
    end

    -- POST /api/v1/link/verify
    if method == "POST" and path == "/api/v1/link/verify" then
        local pairingCode = body.pairingCode
        local robloxUserId = body.robloxUserId
        
        -- Find session with matching pairing code
        for sessionId, session in pairs(Mock._sessions) do
            if session.pairingCode == pairingCode and session.robloxUserId == robloxUserId then
                session.linked = true
                session.student = { id = uuid(), displayName = "LinkedStudent" }
                session.pairingCode = nil
                return 200, HttpService:JSONEncode({
                    success = true,
                    student = session.student,
                }), {}
            end
        end
        
        return 400, HttpService:JSONEncode({
            code = "VALIDATION_ERROR",
            message = "Invalid pairing code",
        }), {}
    end

    -- GET /api/v1/profile/:robloxUserId
    if method == "GET" and string.match(path, "^/api/v1/profile/%d+$") then
        local robloxUserId = tonumber(string.match(path, "/(%d+)$")) or 0
        return 200, HttpService:JSONEncode({
            robloxUserId = robloxUserId,
            student = { id = uuid(), displayName = "ProfileStudent" },
            mastery = {
                { skillCode = "math.fractions", previousMastery = 0.5, newMastery = 0.5, delta = 0 },
            },
        }), {}
    end

    -- Unknown endpoint
    return 404, HttpService:JSONEncode({
        code = "NOT_FOUND",
        message = "Endpoint not found: " .. method .. " " .. path,
    }), {}
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

function HttpClient:_signHeaders(method: HttpMethod, path: string, bodyJson: string): {[string]: string}
    local timestamp = tostring(nowUnixSeconds())
    local bodyHash = Crypto.sha256Hex(bodyJson)
    local canonical = string.format("%s:%s:%s:%s", timestamp, method, path, bodyHash)
    local signature = Crypto.hmacSha256Hex(self._cfg.apiKeySecret, canonical)

    return {
        ["Content-Type"] = "application/json",
        ["X-Game-Key-Id"] = self._cfg.gameKeyId,
        ["X-Timestamp"] = timestamp,
        ["X-Signature"] = signature,
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
                    reject(Errors.make("ENCODE_ERROR", "Failed to encode request body", nil, false, bodyTable, requestId))
                    return
                end
                bodyJson = encoded
            end

            -- Build headers
            local headers = self:_signHeaders(method, path, bodyJson)

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
                            reject(Errors.make("DECODE_ERROR", "Failed to decode response", statusCode, false, respJson, requestId))
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
                        reject(Errors.make("DECODE_ERROR", "Failed to decode response", statusCode, false, respBody, requestId))
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
                    if headers and headers["Retry-After"] then
                        local ra = tonumber(headers["Retry-After"])
                        if ra then
                            retryAfter = ra
                        end
                    end
                end

                local exponentialMs = backoffMs * (2 ^ (attempt - 1))
                local baseDelayMs = math.max(exponentialMs, retryAfter * 1000)
                local jitter = 1 + (math.random() * 0.1)
                local delayMs = baseDelayMs * jitter

                logger:warn(string.format("Retrying in %.0fms (attempt %d/%d, requestId=%d)", delayMs, attempt + 1, maxRetries + 1, requestId))

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
        config = createResp.config,

        -- Internal state
        _client = client,
        _logger = logger,
        _cfg = cfg,
        _state = "ACTIVE" :: SessionState,
        
        -- Event batching
        _eventQueue = {} :: {LearningEvent},
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

function SessionImpl:getNextQuestion(count: number?): any
    local ok, err = self:_ensureActive()
    if not ok then
        return Promise.reject(err)
    end

    local body: any = { sessionId = self.sessionId }
    if count ~= nil then
        body.count = count
    end

    return self._client:request("POST", "/api/v1/questions/next", body)
end

function SessionImpl:submitAnswer(questionId: string, answer: any, responseTimeMs: number): any
    local ok, err = self:_ensureActive()
    if not ok then
        return Promise.reject(err)
    end

    local path = "/api/v1/questions/" .. questionId .. "/answer"
    local body = {
        sessionId = self.sessionId,
        answer = answer,
        responseTimeMs = responseTimeMs,
        idempotencyKey = uuid(),
    }

    return self._client:request("POST", path, body)
end

function SessionImpl:skipQuestion(questionId: string, reason: string): any
    local ok, err = self:_ensureActive()
    if not ok then
        return Promise.reject(err)
    end

    local path = "/api/v1/questions/" .. questionId .. "/skip"
    local body = {
        sessionId = self.sessionId,
        reason = reason,
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
        questionId = questionId,
        hintIndex = hintIndex or 0,
        idempotencyKey = uuid(),
    }

    return self._client:request("POST", "/api/v1/hints", body)
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

    -- Clone and populate defaults
    local e: LearningEvent = shallowCopy(event)
    if e.idempotencyKey == nil then
        e.idempotencyKey = uuid()
    end
    if e.timestamp == nil then
        e.timestamp = nowUnixSeconds()
    end

    -- Add to queue
    table.insert(self._eventQueue, e)

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

    local p = self._client:request("POST", "/api/v1/events/batch", body)
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
                self._logger:warn("Flush failed (non-retryable), events dropped", { count = #batch, error = err.message })
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
        robloxUserId = self.player.UserId,
        pairingCode = code,
    }

    local p = self._client:request("POST", "/api/v1/link/verify", body)
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
            local path = "/api/v1/sessions/" .. self.sessionId .. "/end"
            return self._client:request("POST", path, { sessionId = self.sessionId })
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
        return Promise.reject(Errors.make(
            "SDK_NOT_INITIALIZED",
            "PlayPath.init() must be called before createSession()",
            nil,
            false,
            nil,
            nil
        ))
    end

    if not isPlayerAlive(player) then
        return Promise.reject(Errors.make(
            "PLAYER_LEFT",
            "Player is not in the game",
            nil,
            false,
            nil,
            nil
        ))
    end

    local body = {
        robloxUserId = player.UserId,
        gameId = uuid(), -- Unique per session for now; could be stable per experience
        launchToken = if opts then opts.launchToken else nil,
    }

    return _client:request("POST", "/api/v1/sessions/start", body)
        :andThen(function(resp: any)
            -- Check if player still in game
            if not isPlayerAlive(player) then
                return Promise.reject(Errors.make(
                    "PLAYER_LEFT",
                    "Player left during session creation",
                    nil,
                    false,
                    nil,
                    nil
                ))
            end

            local session = SessionImpl.new(player, _client, _logger, resp, _cfg :: InitConfig)
            return session
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
    test(
        "SHA256 'abc'",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Crypto.sha256Hex("abc")
    )
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

    PlayPath.createSession(fakePlayer)
        :andThen(function(session)
            print("[TEST PASS] Session created:", session.sessionId)
            
            -- Test getNextQuestion
            return session:getNextQuestion()
        end)
        :andThen(function(resp)
            print("[TEST PASS] Got question:", resp.question and resp.question.prompt)
            
            -- Done
            print("[TEST] Mock tests complete")
        end)
        :catch(function(err)
            print("[TEST FAIL] Error:", err.message or tostring(err))
            passed = false
        end)

    return passed
end

-- Expose for testing
PlayPath._internal.Crypto = Crypto
PlayPath._internal.Promise = Promise
PlayPath._internal.Mock = Mock

return PlayPath
