local Adapter = require("playpath.core.adapter")
local Auth = require("playpath.core.auth")
local HttpClient = require("playpath.core.http")
local OpenApiV1 = require("playpath.core.openapi_v1")
local Session = require("playpath.core.session")

local DEFAULT_BASE_URL = "https://play.gmac.io"

local PlayPath = {}

function PlayPath.init(config)
    if type(config) ~= "table" then
        error("config must be a table", 2)
    end

    Adapter.validate(config.adapter)
    Auth.validateConfig(config, config.adapter)

    local resolved = {
        adapter = config.adapter,
        authMode = config.authMode or "hmac",
        launchToken = config.launchToken,
        gameKeyId = config.gameKeyId,
        apiKeySecret = config.apiKeySecret,
        baseUrl = config.baseUrl or DEFAULT_BASE_URL,
        openapi = config.openapi or OpenApiV1,
    }

    local client = {
        config = resolved,
        http = HttpClient.new(resolved),
        openapi = resolved.openapi,
    }

    function client:createSession(payload)
        local requestBody = {}
        for key, value in pairs(payload or {}) do
            requestBody[key] = value
        end

        local requestOptions = nil
        if resolved.authMode == "token" then
            requestBody.launchToken = resolved.launchToken
            requestOptions = {
                skipAuth = true,
            }
        end

        local response = self.http:request(
            "POST",
            self.openapi.paths.sessions,
            requestBody,
            requestOptions
        )

        return Session.new(self, response.body)
    end

    return client
end

return PlayPath
