-- Machine Learning Client for ModSecurity
-- Memory-safe implementation with proper cleanup

-- Lua 5.3 compatibility layer
local unpack = table.unpack or unpack
local loadstring = loadstring or load

-- Safe require with version check
local function safe_require(module_name)
    local success, module = pcall(require, module_name)
    if not success then
        m.log(1, string.format("[ML-Plugin Error] Failed to load module %s: %s", module_name, tostring(module)))
        return nil
    end
    return module
end

-- Load required modules with error handling
local http = safe_require "socket.http"
local ltn12 = safe_require "ltn12"
local cjson = safe_require "cjson"

if not (http and ltn12 and cjson) then
    m.log(1, "[ML-Plugin Error] Required modules not available")
    return
end

-- Configuration with version-specific adjustments
local ML_SERVER_URL = "http://localhost:5000"
local TIMEOUT = 1  -- seconds
local MAX_REQUEST_SIZE = 512 * 1024  -- 512KB
local MAX_ARGS = 50
local MAX_STRING_LENGTH = 4096
local DEBUG = true

-- Utility functions for memory-safe operations
local function log_debug(msg, level)
    level = level or 1  -- Default to info level
    if DEBUG then
        local debug_levels = {
            [1] = "INFO",
            [2] = "WARNING",
            [3] = "ERROR"
        }
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")
        local level_str = debug_levels[level] or "INFO"
        m.log(level, string.format("[ML-Plugin %s] [%s] %s", level_str, timestamp, tostring(msg)))
    end
end

-- Memory monitoring
local function get_memory_usage()
    local file = io.open("/proc/self/status", "r")
    if not file then return "unknown" end
    local content = file:read("*all")
    file:close()
    
    local vm_peak = content:match("VmPeak:%s*(%d+)")
    local vm_size = content:match("VmSize:%s*(%d+)")
    return string.format("VmPeak: %sKB, VmSize: %sKB", vm_peak or "unknown", vm_size or "unknown")
end

-- Enhanced error handling for HTTP requests
local function make_http_request(url, method, headers, body)
    log_debug("Starting HTTP request to: " .. url)
    log_debug("Memory usage before request: " .. get_memory_usage())
    
    local response = {}
    local start_time = os.time()
    
    local success, res, code = protected_call(function()
        return http.request{
            url = url,
            method = method,
            headers = headers,
            source = body and ltn12.source.string(body) or nil,
            sink = ltn12.sink.table(response),
            timeout = TIMEOUT
        }
    end)
    
    local end_time = os.time()
    log_debug(string.format("Request completed in %d seconds", end_time - start_time))
    log_debug("Memory usage after request: " .. get_memory_usage())
    
    if not success then
        log_debug("HTTP request failed: " .. tostring(res), 3)
        return nil, nil
    end
    
    if code ~= 200 then
        log_debug(string.format("HTTP request returned non-200 status: %d", code), 2)
        return nil, nil
    end
    
    return table.concat(response), code
end

-- Memory protection for Lua 5.3
local function protected_call(f, ...)
    if not f then return nil end
    local args = {...}
    local success, result = pcall(function()
        return f(unpack(args))
    end)
    if not success then
        m.log(1, "[ML-Plugin Error] " .. tostring(result))
        return nil
    end
    return result
end

-- Enhanced safe string function
local function safe_string(str, max_len)
    if not str then return "" end
    if type(str) ~= "string" then
        str = tostring(str)
    end
    max_len = max_len or MAX_STRING_LENGTH
    local result = string.sub(str, 1, max_len)
    return result
end

-- Enhanced safe table size function
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

-- Make prediction request to ML server with enhanced logging
local function predict_sqli(pattern)
    if not pattern or type(pattern) ~= "string" then
        log_debug("Invalid pattern provided", 2)
        return nil, nil
    end
    
    if string.len(pattern) > MAX_REQUEST_SIZE then
        log_debug(string.format("Pattern too large: %d bytes", string.len(pattern)), 2)
        return nil, nil
    end
    
    log_debug("Processing pattern: " .. safe_string(pattern, 100) .. "...")
    log_debug("Memory usage at start: " .. get_memory_usage())
    
    local request_body = protected_call(cjson.encode, {query = safe_string(pattern)})
    if not request_body then
        log_debug("Failed to encode request body", 3)
        return nil, nil
    end
    
    local response_body, code = make_http_request(
        ML_SERVER_URL .. "/predict",
        "POST",
        {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = string.len(request_body)
        },
        request_body
    )
    
    if not response_body then
        return nil, nil
    end
    
    local response_data = protected_call(cjson.decode, response_body)
    if not response_data then
        log_debug("Failed to decode response", 3)
        return nil, nil
    end
    
    log_debug(string.format("Prediction result: is_sqli=%s, probability=%s",
        tostring(response_data.is_sqli),
        tostring(response_data.probability)))
    
    return response_data.is_sqli, response_data.probability
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
