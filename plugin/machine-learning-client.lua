-- ModSecurity Lua script for ML-based attack detection
-- Pure ML approach without pattern matching

function main()
    -- Get request details
    local request_method = m.getvar("REQUEST_METHOD")
    local request_uri = m.getvar("REQUEST_URI")
    local args = m.getvars("ARGS")
    
    -- Log request details
    m.log(2, string.format("[ML-PLUGIN] Processing request - Method: %s, URI: %s", request_method, request_uri))
    
    -- Extract query from URI if present
    local query = ""
    for _, arg in ipairs(args) do
        if arg["name"] == "q" then
            query = arg["value"]
            m.log(2, string.format("[ML-PLUGIN] Extracted query from URI: %s", query))
            break
        end
    end
    
    -- URL encode the query
    local encoded_query = m.urlencode(query)
    m.log(2, string.format("[ML-PLUGIN] Final encoded query: %s", encoded_query))
    
    -- Prepare args JSON
    local args_json = string.format('{\\"q\\":\\"%s\\"}', encoded_query)
    
    -- Get current hour and day
    local hour = os.date("*t").hour
    local day = os.date("*t").wday
    
    -- Construct curl command
    local ml_url = "http://127.0.0.1:5000/"
    local curl_cmd = string.format(
        'curl -s -X POST %s -H "Content-Type: application/x-www-form-urlencoded" -d "method=%s&path=%s&args=%s&hour=%d&day=%d"',
        ml_url,
        request_method,
        m.urlencode(request_uri),
        m.urlencode(args_json),
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
    
    -- Process response
    local ml_decision = tonumber(response) or 0
    m.log(2, string.format("[ML-PLUGIN] ML decision: %d", ml_decision))
    
    -- Set variables for ModSecurity
    if ml_decision == -1 then
        m.log(2, "[ML-PLUGIN] Attack detected! Executing block...")
        m.log(2, "[ML-PLUGIN] Setting up block response")
        m.log(2, "[ML-PLUGIN] Executing disruptive action")
        m.log(2, "[ML-PLUGIN] Forcing immediate block")
        m.setvar("tx.ml_block", "1")
        return "-1"
    else
        m.setvar("tx.ml_block", "0")
        return "0"
    end
end

-- Call main function
return main()
