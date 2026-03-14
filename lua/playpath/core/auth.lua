local Auth = {}

local function assertNonEmptyString(value, fieldName)
    if type(value) ~= "string" or value == "" then
        error(string.format("%s must be a non-empty string", fieldName), 3)
    end
end

function Auth.validateConfig(config, adapter)
    local authMode = config.authMode or "hmac"
    if authMode ~= "hmac" and authMode ~= "token" then
        error("authMode must be 'hmac' or 'token'", 2)
    end

    if authMode == "token" then
        assertNonEmptyString(config.launchToken, "launchToken")
        return
    end

    assertNonEmptyString(config.gameKeyId, "gameKeyId")
    assertNonEmptyString(config.apiKeySecret, "apiKeySecret")

    if type(adapter.sha256) ~= "function" or type(adapter.hmacSha256) ~= "function" then
        error("hmac auth mode requires adapter crypto functions", 2)
    end
end

function Auth.buildHeaders(config, adapter, method, path, bodyString, options)
    options = options or {}
    local headers = {
        Accept = "application/json",
    }
    if options.skipAuth then
        return headers
    end

    if type(options.authorization) == "string" and options.authorization ~= "" then
        headers.Authorization = options.authorization
        return headers
    end

    local authMode = config.authMode or "hmac"

    if authMode == "token" then
        headers.Authorization = "Bearer " .. config.launchToken
        return headers
    end

    local timestamp = tostring(adapter.getTimeMs())
    local nonce = adapter.generateUUID()
    local bodyHash = adapter.sha256(bodyString or "")
    local canonical = table.concat({
        timestamp,
        nonce,
        string.upper(method),
        path,
        bodyHash,
    }, ":")

    headers["x-api-key"] = config.gameKeyId
    headers["x-timestamp"] = timestamp
    headers["x-nonce"] = nonce
    headers["x-signature"] = "sha256=" .. adapter.hmacSha256(config.apiKeySecret, canonical)

    return headers
end

return Auth
