-- Test basic request variables
function main()
    -- Get ModSecurity object safely
    if not _G['m'] then
        return nil
    end

    -- Try to read variables that were set in config
    local uri = _G['m'].getvar("TX.request_uri")
    local method = _G['m'].getvar("TX.method")
    
    -- Log what we got
    if uri and method then
        _G['m'].log(4, "Processing " .. method .. " request to " .. uri)
    end

    return nil
end
