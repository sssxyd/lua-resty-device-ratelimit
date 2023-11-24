--[[
Author: xuyd
Date: 2023/10/23
Initialization operations performed inside init_by_lua_block:

]]


local _M = {}
local config_redis = {
  host = '127.0.0.1',
  port = 6379,
  pswd = nil,
  pool_size = 100,
  idle_mills = 10000
}
local config_expired_seconds = 600
local config_device_id_header = 'x-device-id'
local config_device_id_verification_address = nil

local function string_trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function string_isNullOrEmpty(str)
  if str == nil or str == ngx.null or type(str) ~= "string" then
      return true
  end
  return str == ""
end

local function isValidHttpUrl(url)
    return string.match(url, "^https?://[%w-_%.%?%.:/%+=&]+") ~= nil
end


local function get_redis_client()
  local red = redis:new()
  red:set_timeout(config_redis.idle_millis)
  local ok, err = red:connect(config_redis.host, config_redis.port)
  if not ok then
    ngx.log(ngx.ERR, "Failed to connect redis server: " .. config_redis.host .. ":" .. config_redis.port)
    return nil
  end
  
  if not string_isNullOrEmpty(config_redis.pswd) then
    local ok, err = red:auth(config_redis.pswd)
    if not ok then
      ngx.log(ngx.ERR, "Failed to authenticate to Redis server: " .. err)
      return nil
    end
  end

  return red
end

local function close_redis_client(client)
  if client == nil then
    return
  end
  local ok, err = client:set_keepalive(config_redis.pswd.idle_millis, config_redis.pswd.pool_size)
  if not ok then
    ngx.log(ngx.ERR, "failed to set keepalive: " .. err)
  end
end

-- { redis = {host = '', port = 6379, pswd = 'xxx', pool_size = 50, idle_mills = 100000}, expired_seconds = 60, device_id_header = 'x-device-no', device_id_verification_address = '' } 
function _M.config(params)
  if params == nil or next(params) == nil or params.redis == nil or next(params.redis) == nil then
    ngx.log(ngx.ERR, "need redis config!")
    return
  end
  
  --config redis
  config_redis.host = string_trim(params.redis.host) or config_redis.host
  config_redis.port = tonumber(params.redis.port) or config_redis.port
  config_redis.pswd = string_trim(params.redis.pswd) or config_redis.pswd
  config_redis.pool_size = tonumber(params.redis.pool_size) or config_redis.pool_size
  config_redis.idle_millis = tonumber(params.redis.idle_millis) or config_redis.idle_millis
  
  --config expired_seconds
  if params.expired_seconds ~= nil then
    local expired_seconds = tonumber(params.expired_seconds)
    if expired_seconds ~= nil and expired_seconds > 0 then
      config_expired_seconds = expired_seconds
    end
  end
  
  --config device_id_header
  if not string_isNullOrEmpty(params.device_id_header) then
    config_device_id_header = params.device_id_header
  end  
  
  --config device_id_verification_address
  if not string_isNullOrEmpty(params.device_id_verification_address) then
    if isValidHttpUrl(params.device_id_verification_address) then
      config_device_id_verification_address = params.device_id_verification_address
    else
      ngx.log(ngx.ERR, 'device_id_verification_address[', params.device_id_verification_address, '] is not valid http url')
    end
  end
  
end

-- { metric = '', latest_seconds_interval = 30, threshold = 
function _M.check(rule)
  
end

return _M