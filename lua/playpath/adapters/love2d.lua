local Love2DAdapter = {}

local function loadHttpStack()
    local okHttps, https = pcall(require, "ssl.https")
    if okHttps and https then
        local okLtn12, ltn12 = pcall(require, "ltn12")
        if okLtn12 and ltn12 then
            return https, ltn12
        end
    end

    local okHttp, http = pcall(require, "socket.http")
    local okLtn12, ltn12 = pcall(require, "ltn12")
    if okHttp and okLtn12 then
        return http, ltn12
    end

    return nil, nil
end

local function defaultUuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return (template:gsub("[xy]", function(char)
        local value = love.math.random(0, 15)
        if char == "y" then
            value = (value % 4) + 8
        end
        return string.format("%x", value)
    end))
end

local function shellEscape(value)
    return "'" .. tostring(value):gsub("'", [['"'"']]) .. "'"
end

local function requestWithCurl(method, url, headers, body)
    if type(io.popen) ~= "function" then
        return nil, "Love2D adapter requires LuaSocket/LuaSec or curl"
    end

    local commandParts = {
        "curl",
        "-sS",
        "-X", shellEscape(method),
        "-w", shellEscape("\n__STATUS__:%{http_code}"),
    }

    for key, value in pairs(headers or {}) do
        commandParts[#commandParts + 1] = "-H"
        commandParts[#commandParts + 1] = shellEscape(string.format("%s: %s", key, value))
    end

    local bodyPath = nil
    if body and body ~= "" then
        bodyPath = os.tmpname()
        local file = assert(io.open(bodyPath, "wb"))
        file:write(body)
        file:close()
        commandParts[#commandParts + 1] = "--data-binary"
        commandParts[#commandParts + 1] = shellEscape("@" .. bodyPath)
    end

    commandParts[#commandParts + 1] = shellEscape(url)

    local handle = io.popen(table.concat(commandParts, " "), "r")
    local raw = handle:read("*a") or ""
    handle:close()

    if bodyPath ~= nil then
        os.remove(bodyPath)
    end

    local status = raw:match("\n__STATUS__:(%d+)%s*$") or raw:match("__STATUS__:(%d+)%s*$")
    if status == nil then
        return nil, "curl request failed"
    end

    local responseBody = raw:gsub("\n__STATUS__:%d+%s*$", "")
    return {
        status = tonumber(status) or 0,
        body = responseBody,
        headers = {},
    }
end

function Love2DAdapter.new(options)
    options = options or {}
    local json = assert(options.json, "Love2D adapter requires a json dependency")
    local httpLib, ltn12 = loadHttpStack()

    return {
        httpRequest = function(method, url, headers, body)
            if httpLib == nil or ltn12 == nil then
                return requestWithCurl(method, url, headers, body)
            end

            local chunks = {}
            local requestBody = body or ""
            local responseHeaders = {}

            local ok, _, status = pcall(httpLib.request, {
                method = method,
                url = url,
                headers = headers,
                source = requestBody ~= "" and ltn12.source.string(requestBody) or nil,
                sink = ltn12.sink.table(chunks),
                redirect = false,
                protocol = "tlsv1_2",
                verify = "none",
                options = "all",
                create = responseHeaders,
            })

            if not ok then
                return requestWithCurl(method, url, headers, body)
            end

            return {
                status = tonumber(status) or 0,
                body = table.concat(chunks),
                headers = responseHeaders,
            }
        end,
        jsonEncode = function(value)
            return json.encode(value)
        end,
        jsonDecode = function(value)
            return json.decode(value)
        end,
        generateUUID = options.generateUUID or defaultUuid,
        getTimeMs = function()
            return math.floor(love.timer.getTime() * 1000)
        end,
        setInterval = function(callback, intervalSeconds)
            return {
                callback = callback,
                intervalSeconds = intervalSeconds,
            }
        end,
        log = function(level, message, data)
            if data ~= nil then
                local ok, encoded = pcall(json.encode, data)
                if ok then
                    print(string.format("[playpath][%s] %s %s", level, message, encoded))
                else
                    print(string.format("[playpath][%s] %s %s", level, message, tostring(data)))
                end
                return
            end
            print(string.format("[playpath][%s] %s", level, message))
        end,
    }
end

return Love2DAdapter
