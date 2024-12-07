-- Test basic request variables
function main()
    -- Basic initialization check
    if not _G['m'] then
        return nil
    end

    -- Try to log something basic first
    _G['m'].log(4, "Lua script started")
    
    -- Try to get just one variable with pcall
    local ok, uri = pcall(function() 
        return _G['m'].getvar("TX.request_uri")
    end)
    
    if ok and uri then
        _G['m'].log(4, "Got URI: " .. tostring(uri))
    else
        _G['m'].log(4, "Failed to get URI")
    end

    return nil
end
