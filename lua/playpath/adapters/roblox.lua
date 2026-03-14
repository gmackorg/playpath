local RobloxAdapter = {}

function RobloxAdapter.new(options)
    options = options or {}
    local HttpService = options.httpService or game:GetService("HttpService")
    local DateTimeService = options.dateTime or DateTime

    return {
        httpRequest = function(method, url, headers, body)
            local response = HttpService:RequestAsync({
                Url = url,
                Method = method,
                Headers = headers,
                Body = body,
            })

            return {
                status = response.StatusCode,
                body = response.Body,
                headers = response.Headers,
            }
        end,
        jsonEncode = function(value)
            return HttpService:JSONEncode(value)
        end,
        jsonDecode = function(value)
            return HttpService:JSONDecode(value)
        end,
        generateUUID = function()
            return HttpService:GenerateGUID(false)
        end,
        getTimeMs = function()
            return DateTimeService.now().UnixTimestampMillis
        end,
        setInterval = function(callback, intervalSeconds)
            local active = true
            task.spawn(function()
                while active do
                    task.wait(intervalSeconds)
                    if active then
                        callback()
                    end
                end
            end)
            return function()
                active = false
            end
        end,
        log = function(level, message, data)
            if data ~= nil then
                print(string.format("[playpath][%s] %s", level, message), data)
                return
            end
            print(string.format("[playpath][%s] %s", level, message))
        end,
        sha256 = options.sha256,
        hmacSha256 = options.hmacSha256,
    }
end

return RobloxAdapter
