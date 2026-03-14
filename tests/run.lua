package.path = table.concat({
    "./lua/?.lua",
    "./lua/?/init.lua",
    "./tests/?.lua",
    package.path,
}, ";")

local total = 0
local failed = 0

local specs = {
    require("generic_sdk_spec"),
}

for _, suite in ipairs(specs) do
    for _, case in ipairs(suite) do
        total = total + 1
        local ok, err = pcall(case.run)
        if ok then
            io.write("PASS ", case.description, "\n")
        else
            failed = failed + 1
            io.write("FAIL ", case.description, "\n")
            io.write("  ", tostring(err), "\n")
        end
    end
end

if failed > 0 then
    error(string.format("%d/%d tests failed", failed, total))
end

io.write(string.format("PASS all %d tests\n", total))
