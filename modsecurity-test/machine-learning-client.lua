-- Minimal test script
function main()
    -- Check if we have access to m object
    if _G['m'] == nil then
        return nil
    end
    
    -- Try basic logging only
    local ok, err = pcall(function()
        _G['m'].log(4, "Basic test log message")
    end)
    
    -- Don't try to access any variables yet
    return nil
end
