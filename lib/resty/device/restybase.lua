--[[
Author: xuyd
Date: 2023/10/23
Initialization operations performed inside init_by_lua_block:
1. restybase.config_redis(host, port, auth, pool_size, idle_millis): Configure the Redis connection.
2. restybase.load_rules(): Load the rules.
]]

local _M = {}
_M.redis_host = "127.0.0.1"
_M.redis_port = 6379
_M.redis_auth = nil
_M.redis_pool_size = 100
_M.redis_idle_millis = 10000
_M.rule_path = "/usr/local/openresty/nginx/conf/rules"
_M.time_offset_base_seconds = 0  -- The base time for calculating the microsecond offset, defaulting to 2023/10/01 00:00:00.

local redis = require("resty.redis")
local cjson = require("cjson")
local ngx_re = require("ngx.re")
local ffi = require("ffi")
ffi.cdef[[
    struct timeval {
        long int tv_sec;
        long int tv_usec;
    };
    int gettimeofday(struct timeval *tv, void *tz);
]];
local tm = ffi.new("struct timeval");

function string.split(input, delimiter)
  local parts, err = ngx_re.split(input, delimiter)
  if not parts then
      ngx.log(ngx.ERR, "split failed: ", err)
      return
  end
  return parts
end


function string.trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function string.isEmpty(str)
  return str == ""
end

function string.isNullOrEmpty(str)
  if str == nil or str == ngx.null or type(str) ~= "string" then
      return true
  end
  return str == ""
end

function string.indexOf(s, sub)
  local index = string.find(s, sub, 1, true)
  if index then
    return index
  else
    return -1
  end
end


function string.lastIndexOf(s, sub)
  local index = string.find(s:reverse(), sub:reverse(), 1, true)
  if index then
    return #s - index - #sub + 2
  else
    return -1
  end
end


function string.replace(s, old, new)
  local index = s:find(old, 1, true)
  if index then
    return s:sub(1, index - 1) .. new .. s:sub(index + #old)
  else
    return s
  end
end


function string.replaceAll(input, search, replace)
    local result = string.gsub(input, search, replace)
    return result
end


function string.startsWith(s, sub)
  return s:sub(1, #sub) == sub
end


function string.endsWith(s, sub)
  return sub == "" or s:sub(-#sub) == sub
end

local function private_load_json_file(file_path)
  local file = io.open(file_path, "r")
  if not file then
      ngx.log(ngx.ERR, "Failed to open file: " .. file_path)
      return nil
  end
  local content = file:read("*a")
  file:close()
  local ok, result_or_error = pcall(cjson.decode, content)
  if not ok then
      ngx.log(ngx.ERR, "Failed to decode JSON from file: " .. file_path .. ". Error: " .. result_or_error)
      return nil
  end
  return result_or_error
end

local function private_load_rules(path)
  if _G.rules == nil then
    _G.rules = {}
  end

  if string.isNullOrEmpty(path) then
    path = _M.rules_dir
  end

  local handle = io.popen("ls " .. path)
  if not handle then
    ngx.log(ngx.ERR, "Failed to open directory: " .. path)
    return
  end

  local result = handle:read("*a")
  handle:close()
  
  if string.isNullOrEmpty(result) then
    return
  end

  local file_names = result:split("\\r?\\n")
  if next(file_names) == nil then
    ngx.log(ngx.ERR, "Failed to split result: " .. err)
    return
  end

  for _, file_name in ipairs(file_names) do
    if file_name:endsWith(".json") then
      local file_path = path .. "/" .. file_name
      local file_key = file_name:replaceAll("%.json$", ""):replaceAll("[^%w]", "_")
      _G.rules[file_key] = private_load_json_file(file_path)
      ngx.log(ngx.INFO, "Loaded JSON file to global rules: " .. file_key)
    end
  end
end

function _M.accurate_timestamp()   
    ffi.C.gettimeofday(tm,nil);
    local sec =  tonumber(tm.tv_sec);
    local usec =  tonumber(tm.tv_usec);
    return sec + usec * 10^-6;
end

--获取距离指定时间的微秒数
function _M.microseconds_offset()
  ffi.C.gettimeofday(tm,nil);
  local sec =  tonumber(tm.tv_sec);
  local usec =  tonumber(tm.tv_usec);
  return (sec - _M.time_offset_base_seconds) * 10^6 + usec
end

function _M.get_redis_client()
  local red = redis:new()
  red:set_timeout(_M.redis_idle_millis)
  local ok, err = red:connect(_M.redis_host, _M.redis_port)
  if not ok then
    ngx.log(ngx.ERR, "Failed to connect redis server: " .. _M.redis_host .. ":" .. _M.redis_port)
    return nil
  end
  
  if _M.redis_auth ~= nil and _M.redis_auth ~= "" then
    local ok, err = red:auth(_M.redis_auth)
    if not ok then
      ngx.log(ngx.ERR, "Failed to authenticate to Redis server: " .. err)
      return nil
    end
  end

  return red
end

function _M.close_redis_client(client)
  if client == nil then
    return
  end
  local ok, err = client:set_keepalive(_M.redis_idle_millis, _M.redis_pool_size)
  if not ok then
    ngx.log(ngx.ERR, "failed to set keepalive: " .. err)
  end
end

function _M.get_request_command_rules(command, header_name, rule_name)
  local rules = {}
  if string.isNullOrEmpty(command) then
    return rules
  end
  
  --First, extract the client-defined rules from the request header
  if not string.isNullOrEmpty(header_name) then
    local rule_str = ngx.req.get_headers()[header_name]
    if not string.isNullOrEmpty(rule_str) then 
      local feature, duration, threshold, probability
      local list_rules = rule_str:trim():split(",")
      for _, rule in ipairs(list_rules) do
        local items = rule:trim():split(":")
        local len = #items
        if len == 3 then
          table.insert(rules, {feature = items[1]:trim(), duration = tonumber(items[2]:trim()), threshold = tonumber(items[3]:trim()), probability = 100 })
        elseif len == 4 then
          table.insert(rules, {feature = items[1]:trim(), duration = tonumber(items[2]:trim()), threshold = tonumber(items[3]:trim()), probability = tonumber(items[4]:trim()) })
        end 
      end    
    end
  end
  
  --Retrieve the server-defined rules from the rule file
  if string.isNullOrEmpty(rule_name) or _G.rules[rule_name] == nil then
    return rules
  end
  
  local json_rules = _G.rules[rule_name]
  if json_rules.commands ~= nil and json_rules.commands[command] ~= nil then
    --Second, extract the specific rules for the current command from the rule file.
    local specified_command_rules = json_rules.commands[command]
    for i = 1, #specified_command_rules do
      rules[#rules + 1] = specified_command_rules[i]
    end
  elseif json_rules.global ~= nil then
    --Finally, if the specific rules for the current command do not exist in the rule file, use the global rules.
    for i = 1, #json_rules.global do
      rules[#rules + 1] = json_rules.global[i]
    end
  end
  
  return rules
end

function _M.get_request_command()
  return ngx.ctx.request_command
end

function _M.get_command_redis_key(command)
  return string.gsub(command, "%W", "_")
end

function _M.get_request_header_rules(header_name)
  if string.isNullOrEmpty(header_name) then
    return nil
  end
  local rule_str = ngx.req.get_headers()[header_name]
  if string.isNullOrEmpty(rule_str) then
    return nil
  end
  
  local result = {}
  local feature, duration, threshold, probability
  local rules = rule_str:trim():split(",")
  for _, rule in ipairs(rules) do
    local items = rule:trim():split(":")
    local len = #items
    if len == 3 then
      table.insert(result, {feature = items[1]:trim(), duration = tonumber(items[2]:trim()), threshold = tonumber(items[3]:trim()), probability = 100 })
    elseif len == 4 then
      table.insert(result, {feature = items[1]:trim(), duration = tonumber(items[2]:trim()), threshold = tonumber(items[3]:trim()), probability = tonumber(items[4]:trim()) })
    end 
  end
  
  if next(result) == nil then
    return nil
  end
  
  return result  
end

function _M.get_request_start_time()
  return ngx.ctx.request_start_time
end

function _M.check_probability(probability)
  if probability == nil or tonumber(probability) == nil then
    return true
  end
  
  local val = tonumber(probability)
  if val >= 100 then
    return true
  end
  
  if val <= 0 then
    return false
  end
  
  return math.random() * 100 < val
end

function _M.split_list(input_list, chunk_size)
  if input_list == nil or next(input_list) == nil then
    return {}
  end
  
  local result = {}
  local chunk_count = 0
  local chunk = {}

  for i, value in ipairs(input_list) do
    local index = (i - 1) % chunk_size + 1
    chunk[index] = value
    
    if index == chunk_size then
      chunk_count = chunk_count + 1
      result[chunk_count] = chunk
      chunk = {}
    end
  end

  if #chunk > 0 then
    chunk_count = chunk_count + 1
    result[chunk_count] = chunk
  end

  return result
end

-- Initialize the module; params include {redis: {host: ?, port: ?, auth: ?, pool_size: ?, idle_millis: ?}, rule_path: ?}.
function _M.init_by_lua_block(params)
  if params == nil or next(params) == nil or params.redis == nil or next(params.redis) == nil then
    ngx.log(ngx.ERR, "restbase need redis config!")
    return
  end
  
  --config redis
  _M.redis_host = string.trim(params.redis.host) or _M.redis_host
  _M.redis_port = tonumber(params.redis.port) or _M.redis_port
  _M.redis_auth = string.trim(params.redis.auth) or _M.redis_auth
  _M.redis_pool_size = tonumber(params.redis.pool_size) or _M.redis_pool_size
  _M.redis_idle_millis = tonumber(params.redis.idle_millis) or _M.redis_idle_millis
  
  --load rules
  local rule_path = string.trim(params.rule_path) or _M.rule_path
  private_load_rules(rule_path)
  
  --set microseconds_offset_base
  local start_date = {
    year = 2023,
    month = 10,
    day = 1,
    hour = 0,
    min = 0,
    sec = 0,
    isdst = false,
  }
  _M.time_offset_base_seconds = math.floor(os.time(start_date))
  
end

function _M.init_worker_by_lua_block()
  --set radom seed
  math.randomseed(ngx.now() * 1000)
end

function _M.access_by_lua_block()
  -- Store the request start time.
  ngx.ctx.request_start_time = ngx.now()
  
  -- Parse the command associated with this request.
  local path = string.sub(ngx.var.uri, 2)
  local pathes = string.split(path, "/")
  local command = ""
  for _, item in ipairs(pathes) do
    local num = tonumber(item)
    if num == nil then
      command = command .. "/" .. item
    end
  end
  
  if #command > 0 then
    command = string.sub(command, 2)
  end
  
  if #command == 0 or "favicon.ico" == command then
    ngx.ctx.request_command = nil
  else
    ngx.ctx.request_command = command
  end
  
end

return _M