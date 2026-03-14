local function assertEqual(actual, expected, message)
    if actual ~= expected then
        error(string.format("%s\nexpected: %s\nactual: %s", message or "values differ", tostring(expected), tostring(actual)), 2)
    end
end

local function assertTruthy(value, message)
    if not value then
        error(message or "expected value to be truthy", 2)
    end
end

local function assertContains(haystack, needle, message)
    if not string.find(haystack, needle, 1, true) then
        error(message or string.format("expected '%s' to contain '%s'", haystack, needle), 2)
    end
end

local function expectError(fn, expectedSubstring)
    local ok, err = pcall(fn)
    if ok then
        error("expected function to fail", 2)
    end

    if expectedSubstring then
        assertContains(tostring(err), expectedSubstring, "unexpected error")
    end
end

local function newSpyAdapter()
    local calls = {}
    local intervals = {}

    local adapter = {
        httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }
            return {
                status = 200,
                body = '{"ok":true}',
                headers = {
                    ["content-type"] = "application/json",
                },
            }
        end,
        jsonEncode = function(value)
            local encodedParts = {}
            for key, encodedValue in pairs(value) do
                encodedParts[#encodedParts + 1] = string.format('"%s":"%s"', key, tostring(encodedValue))
            end
            table.sort(encodedParts)
            return "{" .. table.concat(encodedParts, ",") .. "}"
        end,
        jsonDecode = function(value)
            if value == '{"ok":true}' then
                return { ok = true }
            end
            error("unexpected json payload: " .. tostring(value))
        end,
        generateUUID = function()
            return "uuid-1234"
        end,
        getTimeMs = function()
            return 1700000000123
        end,
        setInterval = function(callback, intervalSeconds)
            intervals[#intervals + 1] = {
                callback = callback,
                intervalSeconds = intervalSeconds,
            }
            return function() end
        end,
        log = function() end,
        sha256 = function(message)
            return "sha(" .. message .. ")"
        end,
        hmacSha256 = function(key, message)
            return "hmac(" .. key .. "," .. message .. ")"
        end,
    }

    return adapter, calls, intervals
end

local function test(description, fn)
    return {
        description = description,
        run = fn,
    }
end

return {
    test("init rejects adapters missing required functions", function()
        local PlayPath = require("playpath")

        expectError(function()
            PlayPath.init({
                authMode = "token",
                launchToken = "launch-token",
                adapter = {
                    httpRequest = function() end,
                },
            })
        end, "adapter")
    end),

    test("token auth mode sends bearer authorization headers", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })

        local response = client.http:request("POST", "/api/v1/sessions", {
            profileId = "student-1",
        })

        assertTruthy(response.body.ok, "decoded response body should be returned")
        assertEqual(#calls, 1, "expected one outgoing request")
        assertEqual(calls[1].method, "POST", "request method mismatch")
        assertEqual(calls[1].url, "https://playpath.test/api/v1/sessions", "request url mismatch")
        assertEqual(calls[1].headers.Authorization, "Bearer launch-token", "missing bearer token")
        assertEqual(calls[1].headers["Content-Type"], "application/json", "json requests should set content type")
        assertEqual(calls[1].body, '{"profileId":"student-1"}', "request body mismatch")
    end),

    test("hmac auth mode requires crypto functions and signs requests", function()
        local PlayPath = require("playpath")

        expectError(function()
            PlayPath.init({
                authMode = "hmac",
                gameKeyId = "game-key",
                apiKeySecret = "secret",
                adapter = {
                    httpRequest = function() end,
                    jsonEncode = function() return "{}" end,
                    jsonDecode = function() return {} end,
                    generateUUID = function() return "uuid-1234" end,
                    getTimeMs = function() return 1700000000123 end,
                    setInterval = function() return function() end end,
                    log = function() end,
                },
            })
        end, "crypto")

        local adapter, calls = newSpyAdapter()
        local client = PlayPath.init({
            authMode = "hmac",
            gameKeyId = "game-key",
            apiKeySecret = "secret",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })

        client.http:request("GET", "/api/v1/time")

        assertEqual(calls[1].headers["x-api-key"], "game-key", "missing api key header")
        assertEqual(calls[1].headers["x-timestamp"], "1700000000123", "missing timestamp header")
        assertEqual(calls[1].headers["x-nonce"], "uuid-1234", "missing nonce header")
        assertEqual(
            calls[1].headers["x-signature"],
            "sha256=hmac(secret,1700000000123:uuid-1234:GET:/api/v1/time:sha())",
            "unexpected signature"
        )
    end),

    test("token mode createSession exchanges launch token for a session token", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }
            return {
                status = 200,
                body = '{"sessionId":"session-1","linked":true,"config":{"theme":"forest"},"sessionToken":"session-token-1"}',
                headers = {
                    ["content-type"] = "application/json",
                },
            }
        end

        adapter.jsonDecode = function(value)
            if value == '{"sessionId":"session-1","linked":true,"config":{"theme":"forest"},"sessionToken":"session-token-1"}' then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = { theme = "forest" },
                    sessionToken = "session-token-1",
                }
            end
            error("unexpected payload: " .. tostring(value))
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })

        local session = client:createSession({
            profileId = "launch-student",
        })

        assertEqual(session.sessionId, "session-1", "session id mismatch")
        assertEqual(session.sessionToken, "session-token-1", "session token mismatch")
        assertEqual(calls[1].headers.Authorization, nil, "launch token should not be sent as bearer during session exchange")
        assertEqual(calls[1].body, '{"launchToken":"launch-token","profileId":"launch-student"}', "session request body mismatch")
    end),

    test("session:getStatus uses the minted session token", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"sessionId":"session-1","active":true,"ended":false}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionToken":"session%-token%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end

            if value == '{"sessionId":"session-1","active":true,"ended":false}' then
                return {
                    sessionId = "session-1",
                    active = true,
                    ended = false,
                }
            end

            error("unexpected payload: " .. tostring(value))
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })

        local session = client:createSession({})
        local status = session:getStatus()

        assertEqual(status.active, true, "status payload should decode")
        assertEqual(calls[2].method, "GET", "status polling should use GET")
        assertEqual(calls[2].url, "https://playpath.test/api/v1/sessions?sessionId=session-1", "status url mismatch")
        assertEqual(calls[2].headers.Authorization, "Bearer session-token-1", "status polling should use the session token")
    end),

    test("session:getWorld uses the minted session token", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"world":{"id":"fallback_world","name":"Forest Path","theme":{"code":"forest","palette":{"primary":"#1","secondary":"#2","accent":"#3"}}},"areas":[{"id":"area_01","name":"Mossy Clearing","gridWidth":2,"gridHeight":2,"tileset":{"id":"tileset-a","tileSize":16},"layers":{"ground":[[1]],"decoration":[[0]],"collision":[[0]]},"transitions":[],"spawnPoint":{"x":1,"y":1}}],"npcs":[],"items":[],"quests":[],"playerSpawn":{"areaId":"area_01","position":{"x":1,"y":1}}}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end
            return {
                world = {
                    id = "fallback_world",
                    name = "Forest Path",
                    theme = {
                        code = "forest",
                        palette = {
                            primary = "#1",
                            secondary = "#2",
                            accent = "#3",
                        },
                    },
                },
                areas = {
                    {
                        id = "area_01",
                        name = "Mossy Clearing",
                        gridWidth = 2,
                        gridHeight = 2,
                        tileset = {
                            id = "tileset-a",
                            tileSize = 16,
                        },
                        layers = {
                            ground = { { 1 } },
                            decoration = { { 0 } },
                            collision = { { 0 } },
                        },
                        transitions = {},
                        spawnPoint = { x = 1, y = 1 },
                    },
                },
                npcs = {},
                items = {},
                quests = {},
                playerSpawn = {
                    areaId = "area_01",
                    position = { x = 1, y = 1 },
                },
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        local world = session:getWorld("fallback_world")

        assertEqual(world.world.name, "Forest Path", "world name mismatch")
        assertEqual(calls[2].headers.Authorization, "Bearer session-token-1", "world request should use session token")
        assertEqual(calls[2].url, "https://playpath.test/api/v1/worlds?worldId=fallback_world", "world request url mismatch")
    end),

    test("session:getNextQuestion normalizes prompt and choices", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"question":{"id":"q-1","skillId":"skill-1","type":"multiple_choice","difficulty":3,"content":{"prompt":"What is 2+2?","options":[{"id":"a","text":"3"},{"id":"b","text":"4"}]}}}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end
            return {
                question = {
                    id = "q-1",
                    skillId = "skill-1",
                    type = "multiple_choice",
                    difficulty = 3,
                    content = {
                        prompt = "What is 2+2?",
                        options = {
                            { id = "a", text = "3" },
                            { id = "b", text = "4" },
                        },
                    },
                },
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        local response = session:getNextQuestion({
            skill = "math.addition.1",
        })

        assertEqual(response.question.prompt, "What is 2+2?", "prompt should be normalized")
        assertEqual(response.question.choices[2].text, "4", "choices should be normalized")
        assertEqual(calls[2].headers.Authorization, "Bearer session-token-1", "question request should use session token")
    end),

    test("session:getNextQuestion normalizes number challenge metadata from content", function()
        local PlayPath = require("playpath")
        local adapter = newSpyAdapter()

        local callCount = 0
        adapter.httpRequest = function()
            callCount = callCount + 1
            if callCount == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"question":{"id":"q-number-1","content":{"question":"How many stars are shown?","answerType":"number","correctAnswer":"12","correctAnswerText":"12","explanation":"There are three rows of four stars.","visual":{"type":"fraction_bar","numerator":3,"denominator":4}}}}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end

            return {
                question = {
                    id = "q-number-1",
                    content = {
                        question = "How many stars are shown?",
                        answerType = "number",
                        correctAnswer = "12",
                        correctAnswerText = "12",
                        explanation = "There are three rows of four stars.",
                        visual = {
                            type = "fraction_bar",
                            numerator = 3,
                            denominator = 4,
                        },
                    },
                },
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        local response = session:getNextQuestion({
            skill = "math.counting",
        })

        assertEqual(response.question.prompt, "How many stars are shown?", "number prompt should be normalized")
        assertEqual(response.question.answerType, "number", "number challenge answer type should be normalized")
        assertEqual(response.question.correctAnswer, "12", "number correct answer should be preserved")
        assertEqual(response.question.correctAnswerText, "12", "number answer label should be preserved")
        assertEqual(response.question.explanation, "There are three rows of four stars.", "number explanation should be preserved")
        assertEqual(response.question.visual.type, "fraction_bar", "visual payload should be preserved")
    end),

    test("session:submitAnswer posts the answer and returns feedback", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"correct":true,"feedback":"Correct!","masteryUpdates":[{"skillCode":"math.addition.1","previousMastery":0.4,"newMastery":0.6,"delta":0.2}]}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end
            return {
                correct = true,
                feedback = "Correct!",
                masteryUpdates = {
                    {
                        skillCode = "math.addition.1",
                        previousMastery = 0.4,
                        newMastery = 0.6,
                        delta = 0.2,
                    },
                },
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        local answer = session:submitAnswer("q-1", {
            answer = "4",
            responseTimeMs = 1800,
        })

        assertEqual(answer.correct, true, "answer correctness mismatch")
        assertEqual(answer.feedback, "Correct!", "answer feedback mismatch")
        assertContains(calls[2].url, "/api/v1/questions/q-1", "answer route mismatch")
        assertContains(calls[2].body, '"sessionId":"session-1"', "answer should include sessionId")
    end),

    test("session:getHint uses the active session token", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"hint":"Try grouping pairs.","hintIndex":0,"totalHints":2,"isLastHint":false}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end
            return {
                hint = "Try grouping pairs.",
                hintIndex = 0,
                totalHints = 2,
                isLastHint = false,
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        local hint = session:getHint({
            questionId = "q-1",
        })

        assertEqual(hint.hint, "Try grouping pairs.", "hint text mismatch")
        assertEqual(calls[2].headers.Authorization, "Bearer session-token-1", "hint request should use session token")
        assertContains(calls[2].body, '"questionId":"q-1"', "hint request body mismatch")
    end),

    test("session:flush posts queued events in one batch", function()
        local PlayPath = require("playpath")
        local adapter, calls = newSpyAdapter()

        adapter.httpRequest = function(method, url, headers, body)
            calls[#calls + 1] = {
                method = method,
                url = url,
                headers = headers,
                body = body,
            }

            if #calls == 1 then
                return {
                    status = 200,
                    body = '{"sessionId":"session-1","linked":true,"config":{},"sessionToken":"session-token-1"}',
                    headers = { ["content-type"] = "application/json" },
                }
            end

            return {
                status = 200,
                body = '{"accepted":2,"rejected":0}',
                headers = { ["content-type"] = "application/json" },
            }
        end

        adapter.jsonDecode = function(value)
            if value:find('"sessionId":"session%-1"', 1, false) then
                return {
                    sessionId = "session-1",
                    linked = true,
                    config = {},
                    sessionToken = "session-token-1",
                }
            end
            return {
                accepted = 2,
                rejected = 0,
            }
        end

        local client = PlayPath.init({
            authMode = "token",
            launchToken = "launch-token",
            baseUrl = "https://playpath.test",
            adapter = adapter,
        })
        local session = client:createSession({
            profileId = "launch-student",
        })
        session:trackEvent({
            type = "question_viewed",
            questionId = "q-1",
        })
        session:trackEvent({
            type = "answer",
            questionId = "q-1",
            correct = true,
        })

        local result = session:flush()

        assertEqual(result.accepted, 2, "flush accepted count mismatch")
        assertContains(calls[2].url, "/api/v1/events", "flush route mismatch")
        assertContains(calls[2].body, '"events"', "flush should send events array")
    end),
}
