-- This is a driver code to point to different ML servers and models
-- and seek ml_inbound_status using such models
-- this ml driver is invoked by machine-learning-plugin-after.conf
-- currently most of this code is from https://github.com/coreruleset/coreruleset/pull/2067/files

function main()
    -- Variable Declarations:
    -- setting the machine learning server URL
    local status, m = pcall(require, "m")
    if not status then
        return -1  -- Return early if ModSecurity module can't be loaded
    end

    -- Get ML server URL with validation
    local ml_server_url = m.getvar("TX.machine-learning-plugin_ml_server_url")
    if not ml_server_url then
        m.log(4, "ML server URL not configured")
        return -1
    end

    -- Load required libraries safely
    local status_http, http = pcall(require, "socket.http")
    local status_ltn12, ltn12 = pcall(require, "ltn12")
    
    if not (status_http and status_ltn12) then
        m.log(4, "Failed to load required libraries")
        return -1
    end

    -- initialising the variable to return the machine learning pass or block status
    local inbound_ml_result = 0
    -- Initialising variables
    local method = m.getvar("REQUEST_METHOD")
    local path = m.getvar("REQUEST_FILENAME")
    local hour = m.getvar("TIME_HOUR")
    local day = m.getvar("TIME_DAY")
    local args = m.getvars("ARGS")
    local files = m.getvars("FILES")
    local filesizes = m.getvars("FILES_SIZES")
    local args_str = "{}"
    local filesstr = "{}"
    local filesizestr = "{}"
    local body = " "
    local respbody = {}
    -- Parsing the tables and logging
    if args ~= nil then
      args_str = "{"
      for k,v in pairs(args) do
        name = v["name"]
        value = v["value"]
        value = value:gsub('"', "$#$")
        args_str = args_str..'"'..name..'":"'..value..'",'
      end
      if #args == 0 then
        args_str = "{}"
      else
        args_str = string.sub(args_str, 1, -2)
        args_str = args_str.."}"
      end
    end
    
    if files ~= nil then
      filesstr = "{"
      for k,v in pairs(files) do
        name = v["name"]
        value = v["value"]
        value = value:gsub('"', "$#$")
        filesstr = filesstr..'"'..name..'":"'..value..'",'
      end
      if #files == 0 then
        filesstr = "{}"
      else
        filesstr = string.sub(filesstr, 1, -2)
        filesstr = filesstr.."}"
      end
    end
  
    if filesizes ~= nil then
      filesizestr = "{"
      for k,v in pairs(filesizes) do
        name = v["name"]
        value = v["value"]
        value = value:gsub('"', "$#$")
        filesizestr = filesizestr..'"'..name..'":"'..value..'",'
      end
      if #filesizes == 0 then
        filesizestr = "{}"
      else
        filesizestr = string.sub(filesizestr, 1, -2)
        filesizestr = filesizestr.."}"
      end
    end
  
    -- Construct http request for the ml server
    --body = "method="..method.."&path="..path.."&args="..args_str.."&files="..filesstr.."&sizes="..filesizestr.."&hour="..hour.."&day="..day
    body = string.format("method=%s&path=%s&args=%s&files=%s&sizes=%s&hour=%s&day=%s", method, path, args_str, filesstr, filesizestr, hour, day)
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded";
      ["Content-Length"] = #body
    }
    local source = ltn12.source.string(body)
    local client, code, headers, status = http.request{
      url=ml_server_url, 
      method='POST',
      source=source,
      headers=headers,
      sink = ltn12.sink.table(respbody)
    }
    respbody = table.concat(respbody)
  
  -- Processing the result
    if client == nil then
      m.log(2, 'The server is unreachable ')
    end
    if code == 401 then
      m.log(1,'Anomaly found by ML')
    end
    if code == 200 then
      inbound_ml_result = 1
    end
    m.setvar("TX.machine-learning-plugin_inbound_ml_anomaly_score", respbody)
    m.setvar("TX.machine-learning-plugin_inbound_ml_status", inbound_ml_result)
    return inbound_ml_result
  end
  