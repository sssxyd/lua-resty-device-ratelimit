--[[
Author: xuyd
Date: 2023/10/23
Initialization operations performed inside init_by_lua_block:

]]
local _M = {
  _VERSION = '0.33'
}

local redis = require("resty.redis")
local http = require("resty.http")
local cjson = require("cjson")

local Configuration = {}
Configuration.redis = {
  scheme = 'redis',
  host = '127.0.0.1',
  database = 0,
  port = 6379,
  pswd = nil,
  time_out_mills = 500,
  pool_size = 100,
  idle_mills = 10000
}
Configuration.api_access_expired_seconds = 600
Configuration.device_id_header_name = nil
Configuration.device_id_check_uri = nil
Configuration.device_id_check_async = true

local function string_isNullOrEmpty(str)
  if str == nil or str == ngx.null or type(str) ~= "string" then
      return true
  end
  return str == ""
end

local function string_indexOf(s, sub)
  local index = string.find(s, sub, 1, true)
  if index then
    return index
  else
    return -1
  end
end

local function string_trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function string_startsWith(s, sub)
  return s:sub(1, #sub) == sub
end


local function boolean_value(obj)
  if obj == nil or obj == ngx.null then
    return false
  end
  
  if type(obj) == "boolean" then
    return obj
  end
  
  if type(obj) == "number" then
    return obj > 0
  end
  
  if type(obj) == "string" then
    local str = string_trim(obj):lower()
    if str == "true" or str == "ok" or str == "yes" or str == "y" or str == "1" then
      return true
    end
  end
  
  if type(obj) == "table" then
    return next(obj) ~= nil
  end
  
  return false
end

local function isValidHttpUrl(url)
    return string.match(url, "^https?://[%w-_%.%?%.:/%+=&]+") ~= nil
end


local function get_redis_client()
  local red = redis:new()
  red:set_timeout(Configuration.redis.time_out_mills)
  local ok, err = red:connect(Configuration.redis.host, Configuration.redis.port)
  if not ok then
    ngx.log(ngx.ERR, "Failed to connect redis server: " .. Configuration.redis.host .. ":" .. Configuration.redis.port)
    return nil
  end
  
  if not string_isNullOrEmpty(Configuration.redis.pswd) then
    local ok, err = red:auth(Configuration.redis.pswd)
    if not ok then
      ngx.log(ngx.ERR, "Failed to authenticate to Redis server: " .. err)
      return nil
    end
  end
  
  if Configuration.redis.database > 0 then
    local res, err = red:select(Configuration.redis.database)
    if not res then
        ngx.log(ngx.ERR, "select database[" .. Configuration.redis.database .. "] failed", err)
        return nil
    end
  end

  return red
end

local function close_redis_client(client)
  if client == nil then
    return
  end
  local ok, err = client:set_keepalive(Configuration.redis.idle_mills, Configuration.redis.pool_size)
  if not ok then
    ngx.log(ngx.ERR, "failed to set keepalive: " .. err)
  end
end

local function get_alphanumeric_underscore_key(str)
  str = str:gsub("[/%-.]", "_")
  if str:find("%W") then
    return ngx.md5(str)
  end
  
  if #str > 32 then
    return ngx.md5(str)
  end
  
  return str
end

--redis :// [: password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]] [&database=database]]
local function parse_redis_uri(uri)
  if string_isNullOrEmpty(uri) then
    return nil
  end
  
  str = string_trim(uri)
  
  local idx = string_indexOf(str, "://")
  if idx < 1 then
    ngx.log(ngx.ERR, 'redis_uri[' .. uri .. '] is invlaid!'
    return nil
  end
  
  local scheme = str:sub(1, idx-1):lower()
  if "redis" ~= scheme then
    ngx.log(ngx.ERR, 'redis_uri[' .. uri .. '] is invlaid, only redis:// scheme is supported!'
    return nil
  end
  
  str = str:sub(idx+3)
  if string_startsWith(str, ":") then
    str = str:sub(2)
  end
  
  local password = nil
  idx = string_indexOf(str, "@")
  if idx > 1 then
    password = string_trim(str:sub(1, idx-1))
    str = str:sub(idx+1)
    if password == "" then
      password = nil
    end
  end
  
  local host = nil
  local port = 6379
  idx = string_indexOf(str, ":")
  if idx > 1 then
    host = string_trim(str:sub(1, idx-1))
    str = str:sub(idx+1)
    idx = string_indexOf(str, "/")
    if idx > 1 then
      port = tonumber(string_trim(str:sub(1, idx-1))) or 6379
      str = str:sub(idx+1)
    else
      port = tonumber(str) or 6379
      str = ""
    end
  else
    idx = string_indexOf(str, "/")
    host = string_trim(str:sub(1, idx-1))
    str = str:sub(idx+1)
  end
  
  local database = 0
  idx = string_indexOf("?")
  if idx > 1 then
    database = tonumber(string_trim(str:sub(1, idx-1))) or 0
    str = string_trim(str:sub(idx+1))
  end  

  local options = {}
  for key, value in str:gmatch("([^&=]+)=([^&=]+)") do
      if key == "timeout" then
          local time, unit = value:match("(%d+)([dhmsu]?s?)")
          time = tonumber(time)
          if time then
              if unit == "d" then
                  time = time * 86400 * 1000
              elseif unit == "h" then
                  time = time * 3600 * 1000 
              elseif unit == "m" then
                  time = time * 60 * 1000
              elseif unit == "ms" then
                  time = time  
              elseif unit == "us" then
                  time = time / 1000 
              elseif unit == "ns" then
                  time = time / 1000000
              end
              options.timeout = time
          end
      elseif key == "database" then
          database = tonumber(key) or 0
      end
  end

  return {
      scheme = scheme,
      host = host,
      port = port,
      password = password,
      database = database,
      options = options
  }
end

local function get_api_key()
  if ngx.ctx.device_ratelimit_api_key ~= nil then
    return ngx.ctx.device_ratelimit_api_key
  end
  
  local uri = ngx.var.uri
  uri = uri:gsub("^/", "")
  uri = uri:gsub("/$", "")
  if #uri == 0 then
    uri = "_"
  end
  ngx.ctx.device_ratelimit_api_key = get_alphanumeric_underscore_key(uri)
  
  return ngx.ctx.device_ratelimit_api_key
end

local function get_device_id()
  if ngx.ctx.device_ratelimit_device_id ~= nil then
    return ngx.ctx.device_ratelimit_device_id
  end
  
  local device_id = nil
  if string_isNullOrEmpty(Configuration.device_id_header_name) then
    return ngx.var.remote_addr
  else
    device_id = ngx.req.get_headers()[Configuration.device_id_header_name]
  end
  
  ngx.ctx.device_ratelimit_device_id = device_id
  
  return ngx.ctx.device_ratelimit_device_id
end

local function get_device_key()
  if ngx.ctx.device_ratelimit_device_key ~= nil then
    return ngx.ctx.device_ratelimit_device_key
  end
  
  local device_id = get_device_id()
  if device_id == nil then
    return nil
  end
  
  ngx.ctx.device_ratelimit_device_key = get_alphanumeric_underscore_key(device_id)
  
  return ngx.ctx.device_ratelimit_device_key
end

local function has_recorded()
  if ngx.ctx.device_ratelimit_recorded and true or false then
    return true
  end
  return false
end

local function set_recorded()
  ngx.ctx.device_ratelimit_recorded = true
end

local function timer_incr_visit_hits(premature, time_slice, device_key, redis_key)
  if premature then
    return
  end
  
  local client = get_redis_client()
  if client == nil then
    return
  end
  
  local key1 = "resty_device_ratelimit_" .. device_key .. "_" .. time_slice
  local key2 = "resty_device_ratelimit_" .. device_key .. "_" .. redis_key .. "_" .. time_slice
  local expire_time = get_expired_seconds()
  
  client:init_pipeline()
  
  client:incr(key1)
  client:expire(key1, Configuration.api_access_expired_seconds)
  client:incr(key2)
  client:expire(key2, Configuration.api_access_expired_seconds)
  
  local responses, errors = client:commit_pipeline()
  close_redis_client(client)
  
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

local function do_record(time_slice)
  if has_recorded() then
    return
  end
  
  set_recorded()
  
  local ok, err = ngx.timer.at(0.1, timer_incr_visit_hits, time_slice, get_device_key(), get_api_key())
  if not ok then
      ngx.log(ngx.ERR, "failed to create timer: ", err)
  end  
end

local function calc_device_visit_hits(device_key, redis_key, start_second, end_second)
  local client = get_redis_client()
  if client == nil then
    return {current_api_access_count = 0, total_apis_access_count = 0 }
  end
  
  local second_count = end_second - start_second + 1
  local prefix_scv = "resty_device_ratelimit_" .. device_key .. "_" .. redis_key .. "_"
  local prefix_tcv = "resty_device_ratelimit_" .. device_key .. "_"
  
  client:init_pipeline(second_count*2)
  for i = start_second, end_second do
    client:get(prefix_scv .. i)
  end
  
  for i = start_second, end_second do
    client:get(prefix_tcv .. i)
  end
  
  local responses, errors = client:commit_pipeline()
  close_redis_client(client)  
  
  if not responses then
    ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    return {current_api_access_count = 0, total_apis_access_count = 0 }
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

  return {current_api_access_count = scv_sum, total_apis_access_count = tcv_sum }
end

local function get_device_visit_hits(start_second, end_second)
  local hit_key = "hit_" .. start_second .. "_" .. end_second
  if ngx.ctx.devie_ratelimit_device_visit_hits == nil then
    ngx.ctx.devie_ratelimit_device_visit_hits = {}
  end
  
  --Cache the API access statistics for a specific time period
  if ngx.ctx.devie_ratelimit_device_visit_hits[hit_key] == nil then
    ngx.ctx.devie_ratelimit_device_visit_hits[hit_key] = calc_device_visit_hits(get_device_key(), get_api_key(), start_second, end_second)
  end
  
  return ngx.ctx.devie_ratelimit_device_visit_hits[hit_key]
  
end

local function set_device_key_valid(device_key, is_valid, expired_seconds) 
  local client = get_redis_client()
  if client == nil then
    return
  end
  
  local key = "resty_device_ratelimit_" .. device_key .. "_valid";
  if expired_seconds == 0 then
    client::del(key)
  else
    client:init_pipeline(2)
    client::set(key, is_valid and 1 or 0)
    client:expire(key, expired_seconds)
    local responses, errors = client:commit_pipeline()
    close_redis_client(client)
    if not responses then
      ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    end
  end
end

local function do_check_device_id(device_id, device_key, remote_addr, request_uri, request_time, request_headers)
  local httpc = http.new()
  httpc:set_timeout(3000)
  local data = {
      device_id = device_id,
      remote_addr = remote_addr,
      request_uri = request_uri,
      request_headers = request_headers
  }

  local res, err = httpc:request_uri(Configuration.device_id_check_uri, {
      method = "POST",
      body = cjson.encode(data),
      headers = {
          ["Content-Type"] = "application/json",
      }
  })

  if not res then
    set_device_key_valid(device_key, true, 60)
    return true
  end
  
  if res.status ~= 200 then
    set_device_key_valid(device_key, true, 60)
    return true
  end
  
  local result, decode_err = cjson.decode(res.body)
  if not result or result.valid == nil then
    set_device_key_valid(device_key, true, 60)
    return true
  end
  
  local valid = (tonumber(result.valid) or 0) > 0
  local expired_seconds = tonumber(result.expired_seconds) or 60
  set_device_key_valid(device_key, valid, expired_seconds) 
  
  return valid
end

local function timer_check_device_id(premature, device_id, device_key, remote_addr, request_uri, request_time, request_headers)
  if premature then
    return
  end
  
  do_check_device_id(device_id, device_key, remote_addr, request_uri, request_time, request_headers)
    
end

local function is_device_id_valid(device_key)
  if Configuration.device_id_check_uri == nil then
    return true
  end
  
  if string_isNullOrEmpty(device_key) then
    return false
  end
  
  if ngx.ctx.device_ratelimit_device_id_valid == nil then
    --Attempt to retrieve the verification status of the deviceId from Redis
    local client = get_redis_client()
    local val = client:get("resty_device_ratelimit_" .. device_key .. "_valid")
    close_redis_client(client)
    
    if val == ngx.null then
      --Initiate verification when encountering an unverified deviceId
      if Configuration.device_id_check_async then
        ngx.ctx.device_ratelimit_device_id_valid = true
        local ok, err = ngx.timer.at(0, timer_check_device_id, get_device_id(), device_key, ngx.var.remote_addr, ngx.time(), ngx.req.get_headers())
        if not ok then
            ngx.log(ngx.ERR, "failed to create timer: ", err)
        end
      else
        ngx.ctx.device_ratelimit_device_id_valid = do_check_device_id(get_device_id(), get_device_key(), ngx.var.remote_addr, ngx.time(), ngx.req.get_headers())
      end
    else
      ngx.ctx.device_ratelimit_device_id_valid = boolean_value(val)
    end
  end
  
  return ngx.ctx.device_ratelimit_device_id_valid
end

local function do_limit(aspect, metric, seconds, threshold)
  
end

-- { redis_uri='', reids_conn_pool_size=50, redis_conn_idle_mills=10000, api_access_expired_seconds=600, device_id_header_name = 'x-device-id', device_id_check_uri = '', device_id_check_async = true} 
function _M.config(config)
  if config ~= nil and next(config) ~= nil then
    local redis = parse_redis_uri(tostring(config.redis_uri) or "")
    if redis ~= nil then
      Configuration.redis.scheme = redis.scheme
      Configuration.redis.host = redis.host
      Configuration.redis.port = redis.port
      Configuration.redis.pswd = redis.password
      Configuration.redis.database = redis.db
      if redis.options and redis.options.timeout then
        Configuration.redis.timeout_mills = redis.options.timeout
      end
    end
    
    if config.redis_conn_pool_size ~= nil then
      Configuration.redis.pool_size = tonumber(config.redis_conn_pool_size) or Configuration.redis.pool_size
    end
    
    if config.redis_conn_idle_mills ~= nil then
      Configuration.redis.idle_mills = tonumber(config.redis_conn_idle_mills) or Configuration.redis.idle_mills
    end
    
    if config.api_access_expired_seconds ~= nil then
      Configuration.api_access_expired_seconds = tonumber(config.api_access_expired_seconds) or Configuration.api_access_expired_seconds
    end
    
    if config.device_id_header_name ~= nil and not string_isNullOrEmpty(tostring(config.device_id_header_name)) then
      Configuration.device_id_header_name = tostring(config.device_id_header_name)
    end
    
    if config.device_id_check_uri ~= nil and isValidHttpUrl(tostring(config.device_id_check_uri)) then
      Configuration.device_id_check_uri = config.device_id_check_uri
    end
    
    if config.device_id_check_async ~= nil then
      Configuration.device_id_check_async = boolean_value(config.device_id_check_async)
    end

  end
end

function _M.check_device_id(sync)
  
  sync = boolean_value(sync)
  
end

function _M.set_device_id_valid(device_id, is_valid, expired_seconds)
  if string_isNullOrEmpty(device_id) or is_valid == nil or expired_seconds == nil then
    return
  end
  
  is_valid = boolean_value(is_valid)
  expired_seconds = tonumber(expired_seconds) or 0
  
  local device_key = get_alphanumeric_underscore_key(device_id)
  set_device_key_valid(device_key, is_valid, expired_seconds)
end

function _M.check_remote_addr(sync)
  
end

function _M.set_remote_addr_valid(remote_addr, is_valid, expired_seconds)
  
end

function _M.limit_device_id_current_api(seconds, times)
  --If the deviceId is invalid, restrict access.
  if not is_device_id_valid(get_device_key()) then
    return true
  end 
  
  local end_second = ngx.time()
  seconds = tonumber(seconds) or 0
  times = tonumber(times) or 0
  --If the latest access seconds or number of accesses is not set, then do not restrict access
  if seconds <=0 or times <= 0 then
    do_record(end_second)
    return false
  end
  
  local hits = get_device_visit_hits(end_second - seconds, end_second)
  
  do_record(end_second)
  
  return hits.current_api_access_count >= times
end

function _M.limit_device_id_total_apis(seconds, times)
  --If the deviceId is invalid, restrict access.
  if not is_device_id_valid(get_device_key()) then
    return true
  end
  
  local end_second = ngx.time()
  seconds = tonumber(seconds) or 0
  times = tonumber(times) or 0
  --If the latest access seconds or number of accesses is not set, then do not restrict access
  if seconds <=0 or times <= 0 then
    do_record(end_second)
    return false
  end
  
  local hits = get_device_visit_hits(end_second - seconds, end_second)
  
  do_record(end_second)
  
  return hits.total_apis_access_count >= times  
end

function _M.limit_global_current_api(seconds, times)
  
end
  
function _M.limit_global_total_apis(seconds, times)
  
end

function _M.record()
  
end


return _M