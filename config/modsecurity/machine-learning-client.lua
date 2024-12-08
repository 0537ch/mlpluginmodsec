-- Simple test script for ModSecurity Lua integration
function main()
    -- Load ModSecurity module safely
    local status, m = pcall(require, "m")
    if not status then
        return -1
    end

    -- Try to log something simple
    if m and m.log then
        m.log(1, "Lua script executed successfully")
    end

    -- Just return success
    return 1
end
