-- Minimal test script

-- Debug logging function
function debug_log(message)
    if _G['m'] then
        local ok, err = pcall(function()
            _G['m'].log(4, "[DEBUG] " .. tostring(message))
        end)
        if not ok then
            -- If ModSecurity logging fails, try writing to a file
            local f = io.open("/var/log/apache2/modsec_lua_debug.log", "a")
            if f then
                f:write(os.date("%Y-%m-%d %H:%M:%S") .. " ERROR: " .. tostring(err) .. "\n")
                f:close()
            end
        end
    end
end

function main()
    debug_log("Starting main function")
    
    -- Check if we have access to m object
    if _G['m'] == nil then
        debug_log("ModSecurity object not found")
        return nil
    end
    
    debug_log("ModSecurity object found")
    
    -- Try basic logging only
    local ok, err = pcall(function()
        debug_log("Attempting to log message")
        _G['m'].log(4, "Basic test log message")
        debug_log("Log message successful")
    end)
    
    if not ok then
        debug_log("Error occurred: " .. tostring(err))
    end
    
    -- Try to log using ModSecurity
    if _G['m'] then
        _G['m'].log(9, "Lua script executed")
    end
    
    -- Also try to write to file directly
    local f = io.open("/var/log/apache2/modsec_lua_debug.log", "a")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " Lua script executed\n")
        f:close()
    end
    
    debug_log("Finishing main function")
    return nil
end
