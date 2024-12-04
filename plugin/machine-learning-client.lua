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

-- Utility functions for memory-safe operations
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

local function collect_args_safely()
    local args = {}
    local args_count = 0
    
    -- Get ARGS names safely
    local args_names = m.getvars("ARGS_NAMES")
    if not args_names then return args end
    
    -- Process each argument safely
    for _, name in ipairs(args_names) do
        if args_count >= MAX_ARGS then break end
        
        -- Get value safely
        local success, value = pcall(function()
            return m.getvar("ARGS:" .. safe_string(name.value, 64))
        end)
        
        if success and value then
            args[safe_string(name.value, 64)] = safe_string(value, 1024)
            args_count = args_count + 1
        end
    end
    
    return args
end

local function make_http_request_safely(method, path, args)
    -- Prepare request data with size limits
    local current_time = os.date("*t")
    local safe_args = {}
    
    -- Safely process args
    local args_size = 0
    for k, v in pairs(args) do
        args_size = args_size + #k + #v
        if args_size > MAX_REQUEST_SIZE then break end
        safe_args[k] = v
    end
    
    -- Create safe post data
    local post_data = string.format(
        "method=%s&path=%s&args=%s&hour=%d&day=%d",
        safe_string(method, 32),
        safe_string(path, 2048),
        safe_string(cjson.encode(safe_args):gsub('"', "$#$"), MAX_REQUEST_SIZE),
        current_time.hour,
        current_time.wday
    )
    
    -- Enforce maximum request size
    if #post_data > MAX_REQUEST_SIZE then
        m.log(1, "Request size exceeds maximum allowed")
        return 1
    end
    
    -- Prepare response table with size limit
    local response = {}
    local response_size = 0
    local response_sink = function(chunk)
        if chunk and response_size < MAX_REQUEST_SIZE then
            response_size = response_size + #chunk
            table.insert(response, chunk)
        end
        return true
    end
    
    -- Set timeout
    http.TIMEOUT = TIMEOUT
    
    -- Make request with pcall for safety
    local success, result = pcall(function()
        return http.request{
            url = ML_SERVER_URL,
            method = "POST",
            headers = {
                ["Content-Type"] = "application/x-www-form-urlencoded",
                ["Content-Length"] = #post_data
            },
            source = ltn12.source.string(post_data),
            sink = response_sink
        }
    end)
    
    -- Handle errors safely
    if not success then
        m.log(1, "ML request failed safely: " .. tostring(result))
        return 1
    end
    
    -- Parse response safely
    local response_str = table.concat(response)
    local score = tonumber(response_str) or 1
    
    -- Cleanup
    response = nil
    collectgarbage()
    
    return score
end

function main()
    -- Initialize with pcall for safety
    local success, result = pcall(function()
        -- Get request details safely
        local method = safe_string(m.getvar("REQUEST_METHOD"), 32)
        local path = safe_string(m.getvar("REQUEST_URI"), 2048)
        local args = collect_args_safely()
        
        -- Make prediction request
        local score = make_http_request_safely(method, path, args)
        
        -- Set score safely
        if type(score) == "number" then
            m.setvar("tx.ml_score", score)
        else
            m.setvar("tx.ml_score", 1)
        end
    end)
    
    -- Handle any errors
    if not success then
        m.log(1, "Error in ML client: " .. tostring(result))
        m.setvar("tx.ml_score", 1)  -- Fail open
    end
    
    -- Cleanup
    collectgarbage()
    return nil
end
