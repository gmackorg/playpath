local Adapter = {}

local REQUIRED_FUNCTIONS = {
    "httpRequest",
    "jsonEncode",
    "jsonDecode",
    "generateUUID",
    "getTimeMs",
    "setInterval",
    "log",
}

function Adapter.validate(adapter)
    if type(adapter) ~= "table" then
        error("playpath adapter must be a table", 2)
    end

    for _, field in ipairs(REQUIRED_FUNCTIONS) do
        if type(adapter[field]) ~= "function" then
            error(string.format("playpath adapter is missing required function '%s'", field), 2)
        end
    end
end

return Adapter
