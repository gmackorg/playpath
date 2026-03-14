local Auth = require("playpath.core.auth")

local HttpClient = {}
HttpClient.__index = HttpClient

function HttpClient.new(config)
    return setmetatable({
        _config = config,
        _adapter = config.adapter,
    }, HttpClient)
end

function HttpClient:request(method, path, body, options)
    options = options or {}
    local bodyString = nil
    if body ~= nil then
        bodyString = self._adapter.jsonEncode(body)
    end

    local headers = Auth.buildHeaders(self._config, self._adapter, method, path, bodyString or "", options)
    for key, value in pairs(options.headers or {}) do
        headers[key] = value
    end
    if bodyString ~= nil then
        headers["Content-Type"] = "application/json"
    end

    local response, err = self._adapter.httpRequest(method, self._config.baseUrl .. path, headers, bodyString)
    if response == nil then
        error(err or "request failed", 2)
    end

    local decodedBody = response.body
    if type(response.body) == "string" and response.body ~= "" then
        decodedBody = self._adapter.jsonDecode(response.body)
    end

    return {
        status = response.status,
        headers = response.headers or {},
        body = decodedBody,
    }
end

return HttpClient
