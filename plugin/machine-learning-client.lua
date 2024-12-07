-- Machine Learning Client for ModSecurity
-- Memory-safe implementation with proper cleanup

-- Defensive initialization
local function init_modsecurity()
    -- Avoid global table access that might cause segfault
    local m = nil
    local success, err = pcall(function()
        if _G and type(_G.m) == "table" then
            m = _G.m
        end
    end)
    
    if not success or not m then
        return nil
    end
    
    -- Minimal required methods
    local required = {
        "log",
        "getvar"
    }
    
    -- Check methods existence without calling them
    for _, method in ipairs(required) do
        if type(m[method]) ~= "function" then
            return nil
        end
    end
    
    return m
end

-- Initialize safely
local m = init_modsecurity()
if not m then
    return nil
end

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

-- Configuration
local ML_SERVER_URL = "http://localhost:5000"
local TIMEOUT = 1  -- seconds
local MAX_REQUEST_SIZE = 512 * 1024  -- 512KB
local MAX_ARGS = 50
local MAX_STRING_LENGTH = 1024
local MAX_PATTERNS = 50  -- Maximum number of patterns to collect
local MAX_PATTERN_LENGTH = 1024  -- Maximum length of each pattern
local DEBUG = true

-- Basic utility functions
local function safe_string(str, max_len)
    if not str then return "" end
    if type(str) ~= "string" then
        str = tostring(str)
    end
    max_len = max_len or MAX_STRING_LENGTH
    return string.sub(str, 1, max_len)
end

-- Debug logging with protected string operations
local function log_debug(msg, level)
    if not DEBUG then return end
    
    level = level or 1
    local debug_levels = {
        [1] = "INFO",
        [2] = "WARNING",
        [3] = "ERROR"
    }
    
    local ok, timestamp = pcall(os.date, "%Y-%m-%d %H:%M:%S")
    if not ok then timestamp = "unknown_time" end
    
    local level_str = debug_levels[level] or "INFO"
    local log_msg = string.format("[ML-Plugin %s] [%s] %s", 
        level_str,
        timestamp,
        safe_string(tostring(msg))
    )
    
    pcall(m.log, level, log_msg)
end

-- Memory monitoring with error handling
local function get_memory_usage()
    local ok, file = pcall(io.open, "/proc/self/status", "r")
    if not ok or not file then 
        return "memory_unknown"
    end
    
    local content = file:read("*all")
    file:close()
    
    if not content then
        return "memory_read_failed"
    end
    
    local vm_peak = content:match("VmPeak:%s*(%d+)")
    local vm_size = content:match("VmSize:%s*(%d+)")
    
    return string.format("VmPeak: %sKB, VmSize: %sKB", 
        vm_peak or "unknown", 
        vm_size or "unknown"
    )
end

-- Extract SQL patterns from request with memory protection
local function extract_sql_patterns()
    local patterns = {}
    local pattern_count = 0
    
    -- Function to safely add pattern
    local function add_pattern(pattern)
        if pattern_count >= MAX_PATTERNS then
            log_debug("Maximum pattern limit reached", 2)
            return false
        end
        
        if type(pattern) == "string" and #pattern > 0 then
            local safe_pattern = safe_string(pattern, MAX_PATTERN_LENGTH)
            table.insert(patterns, safe_pattern)
            pattern_count = pattern_count + 1
            return true
        end
        return false
    end
    
    -- Check ARGS with pcall
    local ok, args = pcall(m.getvars, "ARGS", "")
    if ok and args then
        for _, arg in ipairs(args) do
            if arg.value and type(arg.value) == "string" and #arg.value > 0 then
                log_debug("Checking ARGS: " .. safe_string(arg.name) .. "=" .. safe_string(arg.value))
                if not add_pattern(arg.value) then
                    break
                end
            end
        end
    end
    
    -- Check REQUEST_URI with pcall
    local ok_uri, uri = pcall(m.getvar, "REQUEST_URI")
    if ok_uri and uri and pattern_count < MAX_PATTERNS then
        log_debug("Checking URI: " .. safe_string(uri))
        add_pattern(uri)
    end
    
    return patterns
end

-- Simple pattern matching for SQL injection with optimized patterns
local function check_sql_pattern(pattern)
    if not pattern or type(pattern) ~= "string" then
        return false, 0
    end
    
    -- Convert to lowercase for case-insensitive matching
    local ok, lower_pattern = pcall(string.lower, pattern)
    if not ok then
        log_debug("Failed to convert pattern to lowercase", 2)
        return false, 0
    end
    
    -- Optimized SQL injection patterns to prevent catastrophic backtracking
    local patterns = {
        "select%s+[%w%*]+%s+from",  -- More specific SELECT pattern
        "union%s+select%s+",        -- More specific UNION pattern
        "insert%s+into%s+",
        "delete%s+from%s+",
        "drop%s+table%s+",
        "exec%s*%(.-%))",           -- Bounded exec pattern
        "execute%s*%(.-%))",        -- Bounded execute pattern
        "update%s+[%w_]+%s+set",    -- More specific UPDATE pattern
        "'%s*or%s*'1'%s*=%s*'1",   -- Specific OR condition
        "--;?%s*$",                 -- Comment at end of line
        "/%*.*%*/",                -- Inline comment
        "xp_cmdshell%s*%(.-%))"    -- Bounded xp_cmdshell pattern
    }
    
    for _, p in ipairs(patterns) do
        local ok, found = pcall(string.find, lower_pattern, p)
        if ok and found then
            return true, 0.95
        end
    end
    
    return false, 0
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

-- Main entry point with error handling
function main()
    local start_memory = get_memory_usage()
    log_debug("Starting SQL injection check. " .. start_memory)
    
    -- Set timeout for the entire operation
    local start_time = os.time()
    local function check_timeout()
        if os.time() - start_time > TIMEOUT then
            log_debug("Operation timed out", 2)
            return true
        end
        return false
    end
    
    local ok, patterns = pcall(extract_sql_patterns)
    if not ok or not patterns then
        log_debug("Failed to extract patterns", 3)
        return nil
    end
    
    if check_timeout() then return nil end
    
    local detected = false
    local max_probability = 0
    
    for _, pattern in ipairs(patterns) do
        if check_timeout() then return nil end
        
        local ok, is_sqli, probability = pcall(check_sql_pattern, pattern)
        if ok and is_sqli then
            detected = true
            max_probability = math.max(max_probability, probability)
            log_debug("SQL Injection detected with probability: " .. tostring(probability))
            pcall(m.log, 1, "[ML-Plugin] SQL Injection detected in pattern: " .. safe_string(pattern))
        end
    end
    
    if detected then
        pcall(m.setvar, "tx.sql_injection_score", max_probability * 100)
        return "detected"
    end
    
    local end_memory = get_memory_usage()
    log_debug("Finished SQL injection check. " .. end_memory)
    
    return nil
end
