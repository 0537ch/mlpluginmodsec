-- Machine Learning Client for ModSecurity
-- Minimal version for debugging segfault

function main()
    -- Basic error handling
    if not m then
        return nil
    end
    
    -- Just log and return
    local status, err = pcall(function()
        m.log(1, "ML client script started")
    end)
    
    if not status then
        return nil
    end
    
    return nil
end
