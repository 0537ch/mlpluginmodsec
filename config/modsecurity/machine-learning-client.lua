-- ModSecurity Lua script for ML-based attack detection
-- Pure ML approach without pattern matching

function url_decode(str)
    if str == nil then return "" end
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end

function escape_json(str)
    if str == nil then return "" end
    local escaped = str:gsub('\\', '\\\\'):gsub('"', '\\"')
    return escaped
end

function main()
    -- Get request details
    local request_method = m.getvar("REQUEST_METHOD")
    local request_uri = m.getvar("REQUEST_URI")
    local args = m.getvars("ARGS")
    
    -- Log request details
    m.log(2, string.format("[ML-PLUGIN] Processing request - Method: %s, URI: %s", request_method, request_uri))
    
    -- Extract and decode query from URI if present
    local query = ""
    for _, arg in ipairs(args) do
        if arg["name"] == "q" then
            query = url_decode(arg["value"])
            m.log(2, string.format("[ML-PLUGIN] Extracted and decoded query: %s", query))
            break
        end
    end
    
    -- Prepare args JSON with escaped values
    local args_json = string.format('{\\"q\\":\\"%s\\"}', escape_json(query))
    m.log(2, string.format("[ML-PLUGIN] Prepared JSON args: %s", args_json))
    
    -- Get current hour and day
    local hour = os.date("*t").hour
    local day = os.date("*t").wday
    
    -- Construct curl command with proper URL encoding
    local ml_url = "http://127.0.0.1:5000/"
    local curl_cmd = string.format(
        'curl -s -X POST %s -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "method=%s" --data-urlencode "path=%s" --data-urlencode "args=%s" --data-urlencode "hour=%d" --data-urlencode "day=%d"',
        ml_url,
        request_method,
        request_uri,
        args_json,
        hour,
        day
    )
    
    -- Log the curl command
    m.log(2, string.format("[ML-PLUGIN] Sending request: %s", curl_cmd))
    
    -- Execute curl command and get response
    local handle = io.popen(curl_cmd)
    local response = handle:read("*a")
    handle:close()
    
    -- Log raw response
    m.log(2, string.format("[ML-PLUGIN] Raw ML server response: %s", response))
    
    -- Process response - block if response is 1 (detected attack)
    local ml_decision = tonumber(response) or 0
    m.log(2, string.format("[ML-PLUGIN] ML decision: %d", ml_decision))
    
    -- Set variables for ModSecurity
    if ml_decision == 1 then
        m.log(2, "[ML-PLUGIN] Attack detected! Setting block flag...")
        m.setvar("tx.machine-learning-plugin_inbound_ml_status", "-1")
        m.setvar("tx.ml_detected_attack", "1")
        m.setvar("tx.ml_block", "1")
        return "-1"
    else
        m.setvar("tx.machine-learning-plugin_inbound_ml_status", "0")
        m.setvar("tx.ml_detected_attack", "0")
        m.setvar("tx.ml_block", "0")
        return "0"
    end
end

-- Call main function
return main()
