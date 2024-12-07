-- Minimal test script

-- Debug logging function
function debug_log(message)
    if _G['m'] then
        local ok, err = pcall(function()
            _G['m'].log(4, "[DEBUG] " .. tostring(message))
        end)
        if not ok then
            -- If ModSecurity logging fails, try writing to a file
            local f = io.open("/tmp/modsec_lua_debug.log", "a")
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
    
    debug_log("Finishing main function")
    return nil
end
