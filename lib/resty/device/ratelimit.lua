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
Configuration.uri_hit_min_expired_seconds = 60
Configuration.device_id_header_name = nil
Configuration.device_id_check_uri = nil

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

local function string_startsWith(s, sub)
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

local function get_uri_key()
  if ngx.ctx.device_ratelimit_uri_key ~= nil then
    return ngx.ctx.device_ratelimit_uri_key
  end
  
  local uri = ngx.var.uri
  uri = uri:gsub("^/", "")
  uri = uri:gsub("/$", "")
  if #uri == 0 then
    uri = "_"
  end
  ngx.ctx.device_ratelimit_uri_key = get_alphanumeric_underscore_key(uri)
  
  return ngx.ctx.device_ratelimit_uri_key
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
  return ngx.ctx.device_ratelimit_recorded and true or false
end

local function set_recorded()
  ngx.ctx.device_ratelimit_recorded = true
end

local function timer_incr_visit_hits(premature, timestamp_second, device_key, uri_key)
  if premature then
    return
  end
  
  local client = get_redis_client()
  if client == nil then
    return
  end
  
  local ttl1 = get_key_preifx_expired_seconds("resty_device_ratelimit_global_")
  local ttl2 = get_key_preifx_expired_seconds("resty_device_ratelimit_global_" .. uri_key .. "_")
  local key1 = "resty_device_ratelimit_global_" .. timestamp_second
  local key2 = "resty_device_ratelimit_global_" .. uri_key .. "_" .. timestamp_second
  local count = 2
  local ttl3 = 0
  local ttl4 = 0
  local key3 = nil
  local key4 = nil
  if device_key ~= nil then
    ttl3 = get_key_preifx_expired_seconds("resty_device_ratelimit_" .. device_key .. "_")
    ttl4 = get_key_preifx_expired_seconds("resty_device_ratelimit_" .. device_key .. "_" .. uri_key .. "_")
    key3 = "resty_device_ratelimit_" .. device_key .. "_" .. timestamp_second
    key4 = "resty_device_ratelimit_" .. device_key .. "_" .. uri_key .. "_" .. timestamp_second
    count = 4
  end
  
  client:init_pipeline(count)
  client:ttl(key1)
  client:ttl(key2)
  if device_key ~= nil then
    client:ttl(key3)
    client:ttl(key4)
  end
  
  local responses, errors = client:commit_pipeline()
  if not responses then
    close_redis_client(client)  
    ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    return
  end
  
  for i, res in ipairs(responses) do
    local value = 0
    if res ~= ngx.null then
      value = (tonumber(res) or 0)
    end
    
    if i == 1 then
      ttl1 = (value == -1) and -1 or max(value, ttl1)
    elseif i == 2 then
      ttl2 = (value == -1) and -1 or max(value, ttl2)
    elseif i == 3 then
      ttl3 = (value == -1) and -1 or max(value, ttl3)
    elseif i == 4 then
      ttl4 = (value == -1) and -1 or max(value, ttl4)
    end
  end
  
  client:init_pipeline(count*2)
  client:incr(key1)
  client:expire(key1, ttl1)
  client:incr(key2)
  client:expire(key2, ttl2)
  if device_key ~= nil then
    client:incr(key3)
    client:expire(key3, ttl3)
    client:incr(key4)
    client:expire(key4, ttl4)
  end
  
  responses, errors = client:commit_pipeline()
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

local function do_record(timestamp_second)
  if has_recorded() then
    return
  end
  
  set_recorded()
  
  local ok, err = ngx.timer.at(0.1, timer_incr_visit_hits, timestamp_second, get_device_key(), get_uri_key())
  if not ok then
      ngx.log(ngx.ERR, "failed to create timer: ", err)
  end  
end

local function get_key_preifx_expired_seconds(redis_key_prefix)
  if ngx.ctx.devie_ratelimit_cache_expires == nil then
    ngx.ctx.devie_ratelimit_cache_expires = {}
  end
  
  if ngx.ctx.devie_ratelimit_cache_expires[redis_key_prefix] == nil then
    return Configuration.uri_hit_min_expired_seconds
  end
  
  return ngx.ctx.devie_ratelimit_cache_expires[redis_key_prefix]
end

local function get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)
  if ngx.ctx.devie_ratelimit_cache_hits == nil then
    ngx.ctx.devie_ratelimit_cache_hits = {}
  end
  
  if ngx.ctx.devie_ratelimit_cache_expires == nil then
    ngx.ctx.devie_ratelimit_cache_expires = {}
  end
  
  ngx.ctx.devie_ratelimit_cache_expires[cache_key] = seconds
  
  local hits = ngx.ctx.devie_ratelimit_cache_hits[cache_key]
  if hits ~= nil then
    return hits
  end
  
  local client = get_redis_client()
  if client == nil then
    return 0
  end
  
  if seconds == 1 then
    hits = client:get(redis_key_prefix .. timestamp_second)
    close_redis_client(client)
    ngx.ctx.devie_ratelimit_cache_hits[cache_key] = hits
    return hits
  end
  
  client:init_pipeline(seconds*2)
  for i = timestamp_second - seconds + 1, timestamp_second do
    client:get(redis_key_prefix .. i)
  end
  
  local responses, errors = client:commit_pipeline()
  close_redis_client(client)  
  
  if not responses then
    ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    return 0
  end  
  
  hits = 0
  for i, res in ipairs(responses) do
    local value = 0
    if res ~= ngx.null then
      value = (tonumber(res) or 0)
    end
    hits = hits + value
  end   
  
  ngx.ctx.devie_ratelimit_cache_hits[cache_key] = hits
  return hits
end

local function get_device_current_uri_hits(device_key, uri_key, timestamp_second, seconds)
  local cache_key = "current_uri_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = "resty_device_ratelimit_" .. device_key .. "_" .. uri_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix)
end

local function get_device_total_uris_hits(device_key, timestamp_second, seconds)
  local cache_key = "total_uris_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = "resty_device_ratelimit_" .. device_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)  
end

local function get_global_current_uri_hits(uri_key, timestamp_second, seconds)
  local cache_key = "global_uri_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = "resty_device_ratelimit_global_" .. uri_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix)  
end

local function get_global_total_uris_hits(timestamp_second, seconds)
  local cache_key = "global_uris_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = "resty_device_ratelimit_global_"
  return get_or_calc_hits(cache_key, redis_key_prefix)
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
  if string_isNullOrEmpty(device_key) then
    return false
  end
  
  if Configuration.device_id_check_uri == nil then
    return true
  end
  
  if ngx.ctx.device_ratelimit_device_id_valid == nil then
    --Attempt to retrieve the verification status of the deviceId from Redis
    local client = get_redis_client()
    local val = client:get("resty_device_ratelimit_" .. device_key .. "_valid")
    close_redis_client(client)
    
    if val == ngx.null then
      --Initiate verification when encountering an unverified deviceId
      ngx.ctx.device_ratelimit_device_id_valid = true
      local ok, err = ngx.timer.at(0, timer_check_device_id, get_device_id(), device_key, ngx.var.remote_addr, ngx.time(), ngx.req.get_headers())
      if not ok then
          ngx.log(ngx.ERR, "failed to create timer: ", err)
      end
    else
      ngx.ctx.device_ratelimit_device_id_valid = boolean_value(val)
    end
  end
  
  return ngx.ctx.device_ratelimit_device_id_valid
end

-- { redis_uri='', reids_conn_pool_size=50, redis_conn_idle_mills=10000, device_id_header_name = 'x-device-id', device_id_check_uri = ''} 
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
    
    if config.device_id_header_name ~= nil and not string_isNullOrEmpty(tostring(config.device_id_header_name)) then
      Configuration.device_id_header_name = tostring(config.device_id_header_name)
    end
    
    if config.device_id_check_uri ~= nil and isValidHttpUrl(tostring(config.device_id_check_uri)) then
      Configuration.device_id_check_uri = config.device_id_check_uri
    end
    
  end
end

function _M.limit(metrics, seconds, times)
  local timestamp_second = ngx.time()
  seconds = tonumber(seconds) or 0
  times = tonumber(times) or 0
  if seconds <=0 or times <= 0 or string_isNullOrEmpty(metrics) then
    return false
  end
  
  local hits = -1
  metrics = string_trim(metrics):lower()
  if "global_current_uri" == metrics then
    hits = get_global_current_uri_hits(get_uri_key(), timestamp_second, seconds)
  elseif "global_total_uris" == metrics then
    hits = get_global_total_uris_hits(timestamp_second, seconds)
  elseif "device_current_uri" == metrics then
    if not is_device_id_valid(get_device_key()) then
      return true
    end
    hits = get_device_current_uri_hits(get_device_key(), get_uri_key(), timestamp_second, seconds)
  elseif "device_total_uris" == metrics then
    if not is_device_id_valid(get_device_key()) then
      return true
    end
    hits = get_device_total_uris_hits(get_device_key(), timestamp_second, seconds)
  end
  
  if hits < 0 then
    return false
  end
  
  return hits >= times
  
end

function _M.check()
  return do_check_device_id(get_device_id(), get_device_key(), ngx.var.remote_addr, ngx.time(), ngx.req.get_headers())
end

function _M.record()
  do_record(ngx.time())
end

function _M.setValid(device_id, is_valid, expired_seconds)
  if string_isNullOrEmpty(device_id) then
    return
  end
  
  is_valid = boolean_value(is_valid)
  expired_seconds = tonumber(expired_seconds) or 0
  
  set_device_key_valid(get_alphanumeric_underscore_key(device_id), is_valid, expired_seconds)
  
end

return _M