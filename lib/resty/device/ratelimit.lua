--[[
Author: xuyd
Date: 2023/10/23
controlling the rate of requests based on the deviceId
]]
local _M = {
  _VERSION = '0.3.4'
}

local redis = require("resty.redis")
local http = require("resty.http")
local cjson = require("cjson")
local resty_aes = require("resty.aes")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

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
Configuration.device_id_cookie_name = nil
Configuration.default_device_check_url = nil
Configuration.server_device_check_urls = {}

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
  
  local obj_type = type(obj)
  
  if obj_type == "boolean" then
    return obj
  end
  
  if obj_type == "number" then
    return obj > 0
  end
  
  if obj_type == "string" then
    local str = string_trim(obj):lower()
    if str == "true" or str == "ok" or str == "yes" or str == "y" or str == "1" then
      return true
    end
  end
  
  if obj_type == "table" then
    return next(obj) ~= nil
  end
  
  return false
end

local function number_value(obj)
  if obj == nil or obj == ngx.null then
    return 0
  end
  
  local obj_type = type(obj)
  
  if obj_type == "boolean" then
    return obj and 1 or 0
  end
  
  if obj_type == "table" then
    local count = 0
    for _ in pairs(myTable) do
        count = count + 1
    end
    return count
  end
  
  return tonumber(obj)
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
  str = str:gsub("[/%. -]", "_")
  if str:find("[^%a%d_]") or #str > 32 then
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
    ngx.log(ngx.ERR, 'redis_uri[' .. uri .. '] is invlaid!')
    return nil
  end
  
  local scheme = str:sub(1, idx-1):lower()
  if "redis" ~= scheme then
    ngx.log(ngx.ERR, 'redis_uri[' .. uri .. '] is invlaid, only redis:// scheme is supported!')
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
  idx = string_indexOf(str, "?")
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
  
  
  --get deviceId from header/cookie/remote_addr
  local device_id = nil
  
  if not string_isNullOrEmpty(Configuration.device_id_header_name) then
    device_id = ngx.req.get_headers()[Configuration.device_id_header_name]
  end
  
  if string_isNullOrEmpty(device_id) and string_isNullOrEmpty(Configuration.device_id_cookie_name) then
    device_id = ngx.var["cookie_" .. Configuration.device_id_cookie_name]
  end
  
  if Configuration.device_id_header_name == nil and Configuration.device_id_cookie_name == nil then
    device_id = ngx.var.remote_addr
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

local function get_server_key(server_name, server_port)
  if server_name ~= nil and server_port ~= nil then
    return get_alphanumeric_underscore_key(server_name) .. '_' .. server_port
  end
  
  if ngx.ctx.device_ratelimit_server_key ~= nil then
    return ngx.ctx.device_ratelimit_server_key
  end
  
  ngx.ctx.device_ratelimit_server_key = get_alphanumeric_underscore_key(ngx.var.server_name) .. '_' .. ngx.var.server_port
  return ngx.ctx.device_ratelimit_server_key
end

local function get_server_redis_key_prefix(server_key)
  return "resty_" .. server_key .. "_drl_"
end

--Obtain the interface address for the deviceId check configured for a specific server
local function get_check_url(server_name, server_port)
  local url = Configuration.server_device_check_urls[server_name .. ':' .. server_port]
  if string_isNullOrEmpty(url) then
    url = Configuration.default_device_check_url
  end
  return url
end

local function timer_incr_visit_hits(premature, timestamp_second, server_key, device_key, uri_key, metrics_expired_cache)
  if premature then
    return
  end
  
  local client = get_redis_client()
  if client == nil then
    return
  end
  
  local ttl1 = metrics_expired_cache["global_total_uris"] or Configuration.uri_hit_min_expired_seconds
  local ttl2 = metrics_expired_cache["global_current_uri"] or Configuration.uri_hit_min_expired_seconds
  local ttl3 = metrics_expired_cache["device_total_uris"] or Configuration.uri_hit_min_expired_seconds
  local ttl4 = metrics_expired_cache["device_current_uri"] or Configuration.uri_hit_min_expired_seconds
  
  local prefix = get_server_redis_key_prefix(server_key)
  
  local key1 = prefix .. "global_" .. timestamp_second
  local key2 = prefix .. "global_" .. uri_key .. "_" .. timestamp_second
  local count = 2
  local key3 = nil
  local key4 = nil
  if device_key ~= nil then
    key3 = prefix .. device_key .. "_" .. timestamp_second
    key4 = prefix .. device_key .. "_" .. uri_key .. "_" .. timestamp_second
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
    local value = number_value(res)
    
    if i == 1 then
      ttl1 = (value == -1) and -1 or math.max(value, ttl1)
    elseif i == 2 then
      ttl2 = (value == -1) and -1 or math.max(value, ttl2)
    elseif i == 3 then
      ttl3 = (value == -1) and -1 or math.max(value, ttl3)
    elseif i == 4 then
      ttl4 = (value == -1) and -1 or math.max(value, ttl4)
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

local function get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)
  if ngx.ctx.devie_ratelimit_cache_hits == nil then
    ngx.ctx.devie_ratelimit_cache_hits = {}
  end
  
  local hits = ngx.ctx.devie_ratelimit_cache_hits[cache_key]
  if hits ~= nil then
    return hits
  end
  
  local client = get_redis_client()
  if client == nil then
    return 0
  end
  
  if seconds == 1 then
    hits = number_value(client:get(redis_key_prefix .. timestamp_second))
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
    hits = hits + number_value(res)
  end

  ngx.ctx.devie_ratelimit_cache_hits[cache_key] = hits
  return hits
end

local function get_device_current_uri_hits(server_key, device_key, uri_key, timestamp_second, seconds)
  local cache_key = "current_uri_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = get_server_redis_key_prefix(server_key) .. device_key .. "_" .. uri_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)
end

local function get_device_total_uris_hits(server_key, device_key, timestamp_second, seconds)
  local cache_key = "total_uris_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = get_server_redis_key_prefix(server_key) .. device_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)  
end

local function get_global_current_uri_hits(server_key, uri_key, timestamp_second, seconds)
  local cache_key = "global_uri_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = get_server_redis_key_prefix(server_key) .. "global_" .. uri_key .. "_"
  return get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)  
end

local function get_global_total_uris_hits(server_key, timestamp_second, seconds)
  local cache_key = "global_uris_" .. timestamp_second .. "_" .. seconds
  local redis_key_prefix = get_server_redis_key_prefix(server_key) .. "global_"
  return get_or_calc_hits(cache_key, redis_key_prefix, timestamp_second, seconds)
end

local function set_device_key_valid(server_key, device_key, is_valid, expired_seconds) 
  local client = get_redis_client()
  if client == nil then
    return
  end
  
  local key = get_server_redis_key_prefix(server_key) .. device_key .. "_valid";
  if expired_seconds == 0 then
    client:del(key)
  else
    client:init_pipeline(2)
    client:set(key, is_valid and 1 or 0)
    client:expire(key, expired_seconds)
    local responses, errors = client:commit_pipeline()
    close_redis_client(client)
    if not responses then
      ngx.log(ngx.ERR, "Failed to commit Redis pipeline: ", errors)
    end
  end
end

local function do_check_device_id(device_id, device_key, remote_addr, request_uri, request_time, request_headers, server_name, server_port)
  local url = get_check_url(server_name, server_port)
  if string_isNullOrEmpty(url) or not isValidHttpUrl(url) then
    return true
  end
  
  local httpc = http.new()
  httpc:set_timeout(3000)
  local data = {
      device_id = device_id,
      remote_addr = remote_addr,
      request_uri = request_uri,
      request_time = request_time,
      request_headers = request_headers,
      server_name = server_name,
      server_port = server_port
  }

  local res, err = httpc:request_uri(url, {
      method = "POST",
      body = cjson.encode(data),
      headers = {
          ["Content-Type"] = "application/json",
      }
  })

  local server_key = get_server_key(server_name, server_port)

  if not res then
    ngx.log(ngx.ERR, err)
    set_device_key_valid(server_key, device_key, true, 60)
    return true
  end
  
  if res.status ~= 200 then
    set_device_key_valid(server_key, device_key, true, 60)
    return true
  end
  
  local result, decode_err = cjson.decode(res.body)
  if not result or result.valid == nil then
    set_device_key_valid(server_key, device_key, true, 60)
    return true
  end
  
  local valid = boolean_value(result.valid)
  local expired_seconds = tonumber(result.expired_seconds) or 60
  set_device_key_valid(server_key, device_key, valid, expired_seconds) 
  
  return valid
end

local function timer_check_device_id(premature, device_id, device_key, remote_addr, request_uri, request_time, request_headers, server_name, server_port)
  if premature then
    return
  end
  
  do_check_device_id(device_id, device_key, remote_addr, request_uri, request_time, request_headers, server_name, server_port)
    
end

local function is_device_id_valid(device_id, device_key, remote_addr, req_uri, req_time, req_headers, server_name, server_port)
  if string_isNullOrEmpty(device_key) then
    return false
  end
  
  if get_check_url(server_name, server_port) == nil then
    return true
  end
  
  if ngx.ctx.device_ratelimit_device_id_valid == nil then
    --Attempt to retrieve the verification status of the deviceId from Redis
    local client = get_redis_client()
    local val = client:get(get_server_redis_key_prefix(get_server_key(server_name, server_port)) .. device_key .. "_valid")
    close_redis_client(client)
    
    if val == ngx.null then
      --Initiate verification when encountering an unverified deviceId
      ngx.ctx.device_ratelimit_device_id_valid = true
      local ok, err = ngx.timer.at(0, timer_check_device_id, device_id, device_key, remote_addr, req_uri, req_time, req_headers, server_name, server_port)
      if not ok then
          ngx.log(ngx.ERR, "failed to create timer: ", err)
      end
    else
      ngx.ctx.device_ratelimit_device_id_valid = boolean_value(val)
    end
  end
  
  return ngx.ctx.device_ratelimit_device_id_valid
end


-- {
-- redis_uri(required): redis :// [: password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]] [&database=database]]
-- redis_conn_pool_size(optional): default 50, The size of the Redis connection pool
-- redis_conn_idle_mills(optional): default 10000 (ms), The number of milliseconds a connection is idle in the connection pool
-- device_id_header_name(optional): The name of the HTTP Header in the Request that holds the deviceId
-- device_id_cookie_name(optional): The cookie name if you save deviceId in cookie
-- default_device_check_url(optional): The address for checking the legality of the deviceId, if a corresponding server configuration is not found in server_device_check_urls, then use this address
-- server_device_check_urls(optional): Configure the address for checking the legality of the deviceId corresponding to different Server:Port
-- }
function _M.config(config)
  if config ~= nil and next(config) ~= nil then
    local redis = parse_redis_uri(tostring(config.redis_uri) or "")
    if redis ~= nil then
      Configuration.redis.scheme = redis.scheme
      Configuration.redis.host = redis.host
      Configuration.redis.port = redis.port
      Configuration.redis.pswd = redis.password
      Configuration.redis.database = redis.database
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
    
    if config.device_id_cookie_name ~= nil and not string_isNullOrEmpty(tostring(config.device_id_cookie_name)) then
      Configuration.device_id_cookie_name = tostring(config.device_id_cookie_name)
    end
    
    if config.default_device_check_url ~= nil and isValidHttpUrl(tostring(config.default_device_check_url)) then
      Configuration.default_device_check_url = config.default_device_check_url
    end
    
    if config.server_device_check_urls ~= nil and next(config.server_device_check_urls) ~= nil then
      for key, value in pairs(config.server_device_check_urls) do
        if not string_isNullOrEmpty(value) and isValidHttpUrl(value) then
          Configuration.server_device_check_urls[key] = value
        end
      end      
    end
    
  end
end

--metrics(required): device_current_uri/device_total_uris/global_current_uri/global_total_uris
--seconds: The number of seconds from the current time
--times：max visit times
--example
-- limit("device_current_uri", 1, 1) means: Limit the same device to access the current interface no more than once per second
-- limit("device_total_uris", 30, 100) means: Limit the same device to a total of 100 accesses to any interface of this service within any 30-second period
-- limit("global_current_uri", 1, 10) means: Limit this service to only allow 10 accesses per second to the current interface
-- limit("global_total_uris", 1, 1000) means: Limit the current service to support a maximum of 1000 accesses per second
function _M.limit(metrics, seconds, times)
  local timestamp_second = ngx.time()
  seconds = tonumber(seconds) or 0
  times = tonumber(times) or 0
  if seconds <=0 or times <= 0 or string_isNullOrEmpty(metrics) then
    return false
  end
  
  if ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache == nil then
    ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache = {}
  end
  
  local hits = -1
  metrics = string_trim(metrics):lower()
  
  if seconds == -1 then
    ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache[metrics] = -1
  else
    local pre_expired_seconds = number_value(ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache[metrics])
    if pre_expired_seconds ~= -1 then
      ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache[metrics] = math.max(pre_expired_seconds, seconds)
    end
  end
  
  local server_key = get_server_key() or ""
  
  if "global_current_uri" == metrics then
    hits = get_global_current_uri_hits(server_key, get_uri_key(), timestamp_second, seconds)
  elseif "global_total_uris" == metrics then
    hits = get_global_total_uris_hits(server_key, timestamp_second, seconds)
  elseif "device_current_uri" == metrics then
    if not is_device_id_valid(get_device_id(), get_device_key(), ngx.var.remote_addr, ngx.var.uri, ngx.time(), ngx.req.get_headers(), ngx.var.server_name, ngx.var.server_port) then
      return true
    end
    hits = get_device_current_uri_hits(server_key, get_device_key(), get_uri_key(), timestamp_second, seconds)
  elseif "device_total_uris" == metrics then
    if not is_device_id_valid(get_device_id(), get_device_key(), ngx.var.remote_addr, ngx.var.uri, ngx.time(), ngx.req.get_headers(), ngx.var.server_name, ngx.var.server_port) then
      return true
    end
    hits = get_device_total_uris_hits(server_key, get_device_key(), timestamp_second, seconds)
  else
    ngx.log(ngx.ERR, 'limit by metrics[' .. metrics .. '] is invalid!')
    return false
  end
  
  if hits < 0 then
    return false
  end
  
  return hits >= times
  
end

--Synchronously verify the legality of the deviceId; 
--Please note that：
--1. If no address for verifying the deviceId is found, or if the call to that address times out or fails, then return true
--2. Even if this method is not called, the legality of the deviceId will still be verified asynchronously
function _M.check()
  local device_id = get_device_id()
  if device_id == nil then
    return false
  end

  local server_name = ngx.var.server_name
  local server_port = ngx.var.server_port
  
  if get_check_url(server_name, server_port) == nil then
    return true
  end  
  
  local device_key = get_device_key()
  local remote_addr = ngx.var.remote_addr or ""
  local req_uri = ngx.var.uri
  local req_headers = ngx.req.get_headers() or {}
  
  if ngx.ctx.device_ratelimit_device_id_valid == nil then
    --Attempt to retrieve the verification status of the deviceId from Redis
    local client = get_redis_client()
    local val = client:get("resty_device_ratelimit_" .. device_key .. "_valid")
    close_redis_client(client)
    
    if val == ngx.null then
      ngx.ctx.device_ratelimit_device_id_valid = do_check_device_id(device_id, device_key, remote_addr, req_uri, ngx.time(), req_headers, server_name, server_port)
    else
      ngx.ctx.device_ratelimit_device_id_valid = boolean_value(val)
    end
  end  
  return ngx.ctx.device_ratelimit_device_id_valid
end

--Asynchronously log this access to Redis
function _M.record()
  if ngx.ctx.device_ratelimit_recorded then
    return
  end

  local device_key = get_device_key()
  local uri_key = get_uri_key()
  if device_key == nil or uri_key == nil then
    return
  end
  local server_key = get_server_key() or ""
  
  ngx.ctx.device_ratelimit_recorded = true
  
  local metrics_expired_cache = ngx.ctx.devie_ratelimit_metrics_expired_seconds_cache or {}
  
  local ok, err = ngx.timer.at(0, timer_incr_visit_hits, ngx.time(), server_key, device_key, uri_key, metrics_expired_cache)
  if not ok then
      ngx.log(ngx.ERR, "failed to create timer: ", err)
  end
end


function _M.set_response_cookie(name, value, expires, path, domain)
  expires = tonumber(expires) or 0
  
  local cookie = name .. "=" .. ngx.escape_uri(value)
  if expires > 0 then
      cookie = cookie .. "; Expires=" .. ngx.cookie_time(expires)
  end
  
  if string_isNullOrEmpty(path) then
    path = "/"
  end
  cookie = cookie .. "; Path=" .. path
  if domain then
      cookie = cookie .. "; Domain=" .. domain
  end

  
  local cookies = ngx.header["Set-Cookie"]
  if type(cookies) == "table" then
      table.insert(cookies, cookie)
  elseif cookies then
      ngx.header["Set-Cookie"] = {cookies, cookie}
  else
      ngx.header["Set-Cookie"] = cookie
  end
end

-- AES256/CBC/PKCS7Padding, return hex encrypted data
function _M.encrypt(data, secret)
  if string_isNullOrEmpty(data) or string_isNullOrEmpty(secret) then
    return data
  end
  
  -- key = sha256(secret)
  local sha256 = resty_sha256:new()
  sha256:update(secret)
  local key = sha256:final()
  
  -- iv = md5(secret):sub(1,16)
  local iv = ngx.md5(secret):sub(1, 16)  
  
  local aes_256_cbc_with_padding = resty_aes:new(key, nil, resty_aes.cipher(256, "cbc"), { iv = iv })
  local encrypted = aes_256_cbc_with_padding:encrypt(data)
  return resty_string.to_hex(encrypted)
end

function _M.decrypt(encrypt_hex, secret)
  if string_isNullOrEmpty(encrypt_hex) or string_isNullOrEmpty(secret) then
    return encrypt_hex
  end
  
  -- key = sha256(secret)
  local sha256 = resty_sha256:new()
  sha256:update(secret)
  local key = sha256:final()
  
  -- iv = md5(secret):sub(1,16)
  local iv = ngx.md5(secret):sub(1, 16)  
  
  local aes_256_cbc_with_padding = resty_aes:new(key, nil, resty_aes.cipher(256, "cbc"), { iv = iv })
  
  local encrypted_data = encrypt_hex:gsub('..', function(h) return string.char(tonumber(h, 16)) end)
  return aes_256_cbc_with_padding:encrypt(encrypted_data)
end


--The backend_url must be a real address and does not accept upstream variables
function _M.proxy_pass(backend_url)
  local httpc = http.new()
  local req_method = ngx.req.get_method()
  local req_headers = ngx.req.get_headers()
  
  req_headers["Connection"] = nil
  req_headers["Host"] = ngx.var.host .. ':' .. ngx.var.server_port
  req_headers["X-Real-IP"] = ngx.var.remote_addr
  req_headers["X-Real-PORT"] = ngx.var.remote_port
  local x_forwarded_for = req_headers["X-Forwarded-For"]
  if x_forwarded_for then
    x_forwarded_for = x_forwarded_for .. ", " .. ngx.var.remote_addr
  else
    x_forwarded_for = ngx.var.remote_addr
  end
  req_headers["X-Forwarded-For"] = x_forwarded_for
  
  ngx.req.read_body()
  
  local pass_url = backend_url:gsub("/+$", "") .. ngx.var.uri
  if ngx.var.query_string then
    pass_url = pass_url .. "?" .. ngx.var.query_string
  end

  local res, err = httpc:request_uri(pass_url, {
    method = req_method,
    headers = req_headers,
    body = ngx.req.get_body_data(),
    keepalive_timeout = 60,
    keepalive_pool = 10
  })

  if not res then
    res = {
      status = 500,
      headers = {},
      body = err
    }
    res.header['Content-Type'] = "text/plain;charset=utf-8"
    ngx.log(ngx.ERR, "proxy_pass[" .. backend_url .. "] failed", err)
  end
  
  ngx.status = res.status
  
  res.headers["Transfer-Encoding"] = nil
  res.headers["Connection"] = nil

  for k, v in pairs(res.headers) do
    ngx.header[k] = v
  end

  return res
end

return _M