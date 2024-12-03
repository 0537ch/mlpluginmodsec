-- Machine Learning Client for ModSecurity
-- Simple version for debugging

function main()
    -- Debug logging
    m.log(1, "Starting ML client script")
    
    -- Get request details
    local args = m.getvars("ARGS")
    if not args then
        m.log(1, "No arguments found")
        return nil
    end
    
    m.log(1, "Processing " .. tostring(#args) .. " arguments")
    
    -- Simple pattern matching
    local is_attack = 0
    for _, arg in ipairs(args) do
        local value = arg["value"] or ""
        m.log(1, "Checking argument: " .. tostring(value))
        
        if string.match(value:lower(), "['\"].*or.*['\"]") then
            m.log(1, "Potential SQL injection found")
            is_attack = 1
            break
        end
    end
    
    -- Set result
    m.log(1, "Setting result: " .. tostring(is_attack))
    m.setvar("TX.ML_IS_ATTACK", is_attack)
    m.setvar("TX.ML_ATTACK_PROBABILITY", is_attack)
    
    return nil
end
