-- Simple ModSecurity Lua plugin
local _M = {}

function _M.main()
    -- Check if ModSecurity object exists
    if not _G.m then
        return nil
    end
    
    -- Try to log a simple message
    local ok, _ = pcall(_G.m.log, 4, "Hello from Lua plugin!")
    
    -- Get and log REQUEST_URI for testing
    local ok_uri, uri = pcall(_G.m.getvar, "REQUEST_URI")
    if ok_uri then
        pcall(_G.m.log, 4, "Requested URI: " .. (uri or "nil"))
    end
    
    return nil
end

return _M
