-- ModSecurity Lua plugin
local _M = {}

function _M.main()
    -- Safely get ModSecurity object
    local m = _G['m']
    if not m then
        return nil
    end
    
    -- Basic logging without string concatenation
    m.log(4, "Lua script started")
    
    -- Safe variable access
    if type(m.getvar) == "function" then
        local ok, uri = pcall(m.getvar, "REQUEST_URI", "none")
        if ok and uri then
            m.log(4, "Got URI")
        end
    end
    
    return nil
end

return _M
