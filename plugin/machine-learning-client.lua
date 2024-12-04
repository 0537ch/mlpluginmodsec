-- Machine Learning Client for ModSecurity
-- Memory-safe implementation with proper cleanup

local http = require "socket.http"
local ltn12 = require "ltn12"
local cjson = require "cjson"

-- Configuration
local ML_SERVER_URL = "http://localhost:5000"
local TIMEOUT = 1  -- seconds
local MAX_REQUEST_SIZE = 1024 * 1024  -- 1MB max request size
local MAX_ARGS = 100  -- Maximum number of arguments to process
local DEBUG = true  -- Enable detailed logging

-- Utility functions for memory-safe operations
local function log_debug(msg)
    if DEBUG then
        m.log(1, "[ML-Plugin Debug] " .. tostring(msg))
    end
end

local function safe_string(str, max_len)
    if not str then return "" end
    return string.sub(tostring(str), 1, max_len or 1024)
end

local function safe_table_size(t)
    local count = 0
    if type(t) ~= "table" then return 0 end
    for _ in pairs(t) do
        count = count + 1
        if count > MAX_ARGS then break end
    end
    return count
end

-- Extract SQL patterns from request
local function extract_sql_patterns(tx)
    local patterns = {}
    
    -- Check ARGS
    local args = m.getvars("ARGS", "")
    if args then
        for _, arg in ipairs(args) do
            if arg.value and string.len(arg.value) > 0 then
                log_debug("Checking ARGS: " .. safe_string(arg.name) .. "=" .. safe_string(arg.value))
                table.insert(patterns, arg.value)
            end
        end
    end
    
    -- Check REQUEST_URI
    local uri = m.getvar("REQUEST_URI")
    if uri then
        log_debug("Checking URI: " .. safe_string(uri))
        table.insert(patterns, uri)
    end
    
    -- Check REQUEST_BODY
    local body = m.getvar("REQUEST_BODY")
    if body then
        log_debug("Checking REQUEST_BODY")
        table.insert(patterns, body)
    end
    
    return patterns
end

-- Make prediction request to ML server
local function predict_sqli(pattern)
    local response = {}
    local request_body = cjson.encode({query = pattern})
    
    log_debug("Sending prediction request for: " .. safe_string(pattern))
    
    local res, code, headers = http.request{
        url = ML_SERVER_URL .. "/predict",
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = string.len(request_body)
        },
        source = ltn12.source.string(request_body),
        sink = ltn12.sink.table(response),
        timeout = TIMEOUT
    }
    
    if code == 200 then
        local response_data = cjson.decode(table.concat(response))
        log_debug("Prediction response: " .. cjson.encode(response_data))
        return response_data.is_sqli, response_data.probability
    end
    
    log_debug("Prediction failed with code: " .. tostring(code))
    return nil, nil
end

-- Main entry point
function main()
    local patterns = extract_sql_patterns()
    local detected = false
    local max_probability = 0
    
    for _, pattern in ipairs(patterns) do
        local is_sqli, probability = predict_sqli(pattern)
        if is_sqli then
            detected = true
            max_probability = math.max(max_probability, probability or 0)
            log_debug("SQL Injection detected with probability: " .. tostring(probability))
            m.log(1, "[ML-Plugin] SQL Injection detected in pattern: " .. safe_string(pattern))
        end
    end
    
    if detected then
        m.setvar("tx.sql_injection_score", max_probability * 100)
        return "detected"
    end
    
    return nil
end
