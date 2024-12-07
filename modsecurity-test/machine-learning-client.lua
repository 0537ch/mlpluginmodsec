-- Test basic request variables
function main()
    -- Basic initialization
    local m = _G['m']
    if not m then
        return nil
    end

    -- Test 1: REQUEST_URI
    local ok, uri = pcall(m.getvar, "REQUEST_URI")
    if not ok then
        m.log(4, "Failed to get REQUEST_URI")
        return nil
    end

    -- Test 2: REQUEST_METHOD
    local ok, method = pcall(m.getvar, "REQUEST_METHOD")
    if not ok then
        m.log(4, "Failed to get REQUEST_METHOD")
        return nil
    end

    -- Test 3: REMOTE_ADDR
    local ok, addr = pcall(m.getvar, "REMOTE_ADDR")
    if not ok then
        m.log(4, "Failed to get REMOTE_ADDR")
        return nil
    end

    -- Test 4: REQUEST_HEADERS
    local ok, headers = pcall(m.getvar, "REQUEST_HEADERS")
    if not ok then
        m.log(4, "Failed to get REQUEST_HEADERS")
        return nil
    end

    return nil
end
