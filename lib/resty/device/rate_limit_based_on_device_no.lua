--[[
Author: xuyd
Date: 2023/10/23
Usage: Provides two types of access restriction rules
1. single_command_hits: Limits the number of times the same interface is accessed by the same deviceNo within a specific time period
2. total_command_hits: Limits the number of times all interfaces are accessed by the same deviceNo within a specific time period
]]

local _M = {}
_M.expired_seconds = 600

local restybase = require("restybase")
local cjson = require("cjson")

local function get_expired_seconds()
  return _M.expired_seconds
end


local function calc_device_visit_hits(device_no, command_redis_key, start_second, end_second)
  local client = restybase.get_redis_client()
  if client == nil then
    return {single_command_visit_hits = 0, total_command_visit_hits = 0 }
  end
  
  local second_count = end_second - start_second + 1
  local prefix_scv = "resty_dal_scv_" .. device_no .. "_" .. command_redis_key .. "_"
  local prefix_tcv = "resty_dal_tcv_" .. device_no .. "_"
  
  client:init_pipeline(second_count*2)
  for i = start_second, end_second do
    client:get(prefix_scv .. i)
  end
  
  for i = start_second, end_second do
    client:get(prefix_tcv .. i)
  end
  
  local responses, errors = client:commit_pipeline()
  restybase.close_redis_client(client)  
  
  if not responses then
    ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    return {single_command_visit_hits = 0, total_command_visit_hits = 0 }
  end
  
  local idx = 0
  local scv_sum = 0
  local tcv_sum = 0
  for i, res in ipairs(responses) do
    local value = 0
    if res ~= ngx.null then
      value = (tonumber(res) or 0)
    end
    
    if idx < second_count then
      scv_sum = scv_sum + value
    else
      tcv_sum = tcv_sum + value
    end
    
    idx = idx + 1
  end  
  
  return {single_command_visit_hits = scv_sum, total_command_visit_hits = tcv_sum }
  
end


local function timer_incr_visit_hits(premature, time_slice, device_no, command_redis_key)
  if premature then
    return
  end
  
  local client = restybase.get_redis_client()
  if client == nil then
    return
  end   
  
  local key1 = "resty_dal_tcv_" .. device_no .. "_" .. time_slice
  local key2 = "resty_dal_scv_" .. device_no .. "_" .. command_redis_key .. "_" .. time_slice
  local expire_time = get_expired_seconds()
  
  client:init_pipeline()
  
  client:incr(key1)
  client:expire(key1, expire_time)
  client:incr(key2)
  client:expire(key2, expire_time)
  
  local responses, errors = client:commit_pipeline()
  restybase.close_redis_client(client)
  
  if not responses then
    ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    return
  end
  
  for i, res in ipairs(responses) do
    if not res then
      ngx.log(ngx.ERR, "Failed to execute command in pipeline at index ", i, ": ", errors[i])
    end
  end
  
end

-- Validate each rule individually; if any rule reaches the threshold, then apply restrictions.
local function do_device_access_limit(current_seconds, device_no, command, command_redis_key, rules)
  
  local feature_values = {}
  local status, duration_key, real_value
  for _, rule in ipairs(rules) do
    local start_seconds = current_seconds - tonumber(rule.duration)
    duration_key = tostring(rule.duration)
    if feature_values[duration_key] == nil then
      feature_values[duration_key] = calc_device_visit_hits(device_no, command_redis_key, start_seconds, current_seconds)
    end
    status = feature_values[duration_key]
    
    if "single_command_hits" == rule.feature then
      real_value = status.single_command_visit_hits
    elseif "total_command_hits" == rule.feature then
      real_value = status.total_command_visit_hits
    else
      real_value = 0
    end
    
    if real_value >= tonumber(rule.threshold) then
      if restybase.check_probability(rule.probability) then
        ngx.log(ngx.ERR, "[LIMIT] device[", device_no , "] command[", command, "] hits ", real_value, " times in ", rule.duration, " seconds, reach threshold[", rule.threshold , "] of rule ", rule.feature)
        return true
      end
    end
  end
  
  return false
  
end


-- Module initialization; params include: expired_seconds (the expiration time of the Redis cache, in seconds)
function _M.init_by_lua_block(params)
  if params == nil or next(params) == nil then
    return
  end
  
  if params.expired_seconds ~= nil then
    local expired_seconds = tonumber(params.expired_seconds)
    if expired_seconds ~= nil and expired_seconds > 0 then
      _M.expired_seconds = expired_seconds
    end
  end
    
end

-- Perform rate limit validation; the params include the parameter: rule, which specifies the name of the rule to be used.
function _M.access_by_lua_block(params)
  if params == nil or next(params) == nil then
    return false
  end
  
  local command = restybase.get_request_command()
  if not command then
    ngx.log(ngx.INFO, "command is empty")
    return false
  end
  
  -- Access is uniformly restricted for requests without x-device-no and without the setting to ignore validation.
  local device_no = ngx.req.get_headers()['x-device-no']
  if device_no ~= nil then
    device_no = string.trim(device_no)
    device_no = string.replaceAll(device_no, "%W", "_")
  end
  
  if string.isNullOrEmpty(device_no) then
    ngx.log(ngx.ERR, "request command[" .. command .. "] has no header: x-device-no")
    return true
  end  
  
  local rules = restybase.get_request_command_rules(command, 'x-limit-rules', params.rule)
  if next(rules) == nil then
    ngx.log(ngx.INFO, "rules is empty for ", params.rule, " and command ", command)
    return false
  end
  
  local command_redis_key = restybase.get_command_redis_key(command)
  local current_seconds = ngx.time()
  
  if do_device_access_limit(current_seconds, device_no, command, command_redis_key, rules) then
    return true
  end
  
  -- For requests that are allowed through, asynchronously perform operations to increase the access count.
  local ok, err = ngx.timer.at(0, timer_incr_visit_hits, current_seconds, device_no, command_redis_key)
  if not ok then
      ngx.log(ngx.ERR, "failed to create timer: ", err)
  end
  
end

return _M