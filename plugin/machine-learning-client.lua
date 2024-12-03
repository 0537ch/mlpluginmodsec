-- This is a driver code to point to different ML servers and models
-- and seek ml_inbound_status using such models
-- this ml driver is invoked by machine-learning-plugin-after.conf

function init()
    -- Initialize any resources needed
    if not pcall(require, "m") then
        return nil, "Failed to load ModSecurity module"
    end
    if not pcall(require, "ltn12") then
        return nil, "Failed to load ltn12"
    end
    if not pcall(require, "socket.http") then
        return nil, "Failed to load socket.http"
    end
    return true
end

local function safe_table_to_json(tbl, max_size)
    if not tbl or #tbl == 0 then return "{}" end
    
    local result = {}
    local count = 0
    for k,v in pairs(tbl) do
        if count >= max_size then break end
        
        local name = v["name"] or ""
        local value = v["value"] or ""
        -- Escape quotes safely
        value = value:gsub('"', '\\"')
        table.insert(result, string.format('"%s":"%s"', name, value))
        count = count + 1
    end
    
    if #result == 0 then return "{}"
    else return "{" .. table.concat(result, ",") .. "}" end
end

function main()
    -- Initialize
    local ok, err = init()
    if not ok then
        m.log(1, "Initialization failed: " .. tostring(err))
        return 0
    end
    
    -- Get ModSecurity variables safely
    local function get_var_safe(var_name, default)
        local val = m.getvar(var_name)
        return val ~= nil and val or default
    end
    
    -- Configuration
    local ml_server_url = get_var_safe("TX.machine-learning-plugin_ml_server_url")
    if not ml_server_url then
        m.log(1, "ML server URL not configured")
        return 0
    end
    
    -- Get request data with limits
    local method = get_var_safe("REQUEST_METHOD", "GET")
    local path = get_var_safe("REQUEST_FILENAME", "/")
    local hour = get_var_safe("TIME_HOUR", "00")
    local day = get_var_safe("TIME_DAY", "0")
    
    -- Process tables with size limits
    local MAX_ITEMS = 100
    local args_str = safe_table_to_json(m.getvars("ARGS"), MAX_ITEMS)
    local files_str = safe_table_to_json(m.getvars("FILES"), MAX_ITEMS)
    local filesizes_str = safe_table_to_json(m.getvars("FILES_SIZES"), MAX_ITEMS)
    
    -- Construct request body safely
    local body = string.format(
        "method=%s&path=%s&args=%s&files=%s&sizes=%s&hour=%s&day=%s",
        method, path, args_str, files_str, filesizes_str, hour, day
    )
    
    -- Setup request with timeout
    local respbody = {}
    local http = require("socket.http")
    http.TIMEOUT = 5.0  -- 5 second timeout
    
    local headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Content-Length"] = #body
    }
    
    -- Make request with error handling
    local ok, code, response_headers, status
    ok, code, response_headers, status = pcall(function()
        return http.request{
            url = ml_server_url,
            method = 'POST',
            source = ltn12.source.string(body),
            headers = headers,
            sink = ltn12.sink.table(respbody),
            create = function()
                local req_sock = require("socket").tcp()
                req_sock:settimeout(5.0)
                return req_sock
            end
        }
    end)
    
    -- Process response
    local inbound_ml_result = 0
    local response = table.concat(respbody)
    
    if not ok then
        m.log(1, string.format("HTTP request failed: %s", tostring(code)))
    elseif code == nil then
        m.log(1, "Connection failed or timed out")
    elseif code == 401 then
        m.log(1, string.format("ML anomaly detected: %s", response))
    elseif code == 200 then
        inbound_ml_result = 1
    else
        m.log(1, string.format("Unexpected response code: %d", code))
    end
    
    -- Cleanup
    respbody = nil
    collectgarbage("collect")
    
    -- Set results
    pcall(m.setvar, "TX.machine-learning-plugin_inbound_ml_anomaly_score", response or "")
    pcall(m.setvar, "TX.machine-learning-plugin_inbound_ml_status", inbound_ml_result)
    
    return inbound_ml_result
end
