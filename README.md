# lua-resty-device-ratelimit
Using OpenResty, add non-intrusive client interface access permissions and rate limits to your site.

## Install OpenResty and Modules
Please follow the official documentation to install OpenResty
Then, install the following modules:

1. openresty/lua-resty-redis
2. pintsized/lua-resty-http
3. sssxyd/lua-resty-device-ratelimit

For CentOS, you can install them using the following commands:

```bash
yum install -y yum-utils

# For CentOS 8 or older
yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo
# For CentOS 9 or later
yum-config-manager --add-repo https://openresty.org/package/centos/openresty2.repo

yum install -y openresty
yum install -y openresty-opm openresty-resty

opm get openresty/lua-resty-redis
opm get pintsized/lua-resty-http
opm get pintsized/lua-resty-device-ratelimit

systemctl enable openresty

```

## Non-Intrusive Configuration
### Demo
- [nginx.conf](./t/zero-intrusion-demo/usr/local/openresty/nginx/conf/nginx.conf)
- [your-site.conf](./t/zero-intrusion-demo/etc/nginx/conf.d/zero-intrusion-ratelimit.conf)

### Config
`vim /usr/local/openresty/nginx/conf/nginx.conf`  
redis_uri: redis :// [: password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]]  
server_device_check_urls: { ["server_name:listen_port"] = "your validate device uri for this site"}  

```lua
    init_by_lua_block {
        local drl = require("resty.device.ratelimit")
        drl.config({
            redis_uri = "redis://:YourRedisPassword@127.0.0.1:6379/0",
            device_id_cookie_name = "CookieNameForDeviceId",
            server_device_check_urls = {
                ["www.yoursite.com:80"] = "http://www.yoursite.com/check-device-id"
            }
        })
    }
```

### Proxy Your Login URI
`vim /etc/nginx/conf.d/your-site.conf`
```
    location /ajax/login {
        rewrite /ajax/(.*) /$1 break;
        access_by_lua_block {
            local cjson = require("cjson")
            local drl = require("resty.device.ratelimit")
            local secret = "Your_Secret_For_Encrypt"

            -- pass this uri to backend
            local res = drl.proxy_pass("http://backend-server:8080")
            
            if res.status ~= 200 then
                ngx.say(res.body)
                ngx.exit(res.status)
            end

            --Assume that your login interface returns a JSON format as follows：
            --{ "code":1, "message":"", "result":{"userId":156, ...} }
            local apiResponse = cjson.decode(res.body)
            if apiResponse and (tonumber(apiResponse.code) or 0) == 1 then
                local result = apiResponse.result
                if result and result.userId then
                    local now = os.date("*t") 
                    local tomorrow_end = os.time({year = now.year, month = now.month, day = now.day + 1, hour = 23, min = 59, sec = 59})
                    local data = {
                        userId = result.userId,
                        expired = tomorrow_end
                    }
                    -- encrypt userId and expiredTime as deviceId (hex format)
                    local deviceId = drl.encrypt(cjson.encode(data), secret)
                    drl.set_response_cookie("deviceId", deviceId, tomorrow_end)
                end
            end
            
            ngx.say(res.body)
            ngx.exit(res.status)
        }
    }
```

### Create Validate DeviceId URI
`vim /etc/nginx/conf.d/your-site.conf`
```
    location /check-device-id {
        allow  127.0.0.1;
        deny  all;

        access_by_lua_block {
            local cjson = require("cjson")
            local drl = require("resty.device.ratelimit")
            local secret = "Your_Secret_For_Encrypt"

            -- default response body
            local response = {
                valid = false,
                expired_seconds = 1800
            }

            -- get deviceId from post json
            ngx.req.read_body()
            local body_data = ngx.req.get_body_data()
            local args, err
            if not body_data then
                err = "failed to read request body"
            else
                args, err = cjson.decode(body_data)
            end
            if not args then
                ngx.log(ngx.ERR, "failed to decode JSON: ", err)
                args = {}
            end

            -- decrypt deviceId and response 
            local encrypted_data_hex = args.device_id or ""
            if encrypted_data_hex ~= "" then
                local datajson = drl.decrypt(encrypted_data_hex, secret)
                if datajson then
                    local data = cjson.decode(datajson)
                    if data then
                        local expired = tonumber(data.expired) or 0
                        local expired_seconds = expired - os.time()
                        if expired_seconds < 0 then
                            response.valid = false
                            response.expired_seconds = 0
                        else
                            response.valid = true
                            response.expired_seconds = expired_seconds
                        end
                    end
                end
            end
            
            ngx.header.content_type = 'application/json; charset=utf-8'
            ngx.say(cjson.encode(response))
            ngx.exit(200)
        }
    }
```
### Check And Limit Your URIs
`vim /etc/nginx/conf.d/your-site.conf`
```
    # no limit
    location /ajax/guest/ {
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit within the entire site, each interface to a maximum of 4 accesses within 10 seconds
    location /ajax/io/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("global_current_uri", 10, 4) then
                ngx.exit(503)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit a single device to a maximum of 1 access per interface within 1 seconds
    location /ajax/key/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("device_current_uri", 1, 1) then
                ngx.exit(429)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit a single device to a maximum of 1 access per interface within 3 seconds, and a total of no more than 40 accesses across all interfaces within 10 seconds
    location /ajax/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("device_current_uri", 3, 1) or drl.limit("device_total_uris", 10, 40) then
                ngx.exit(429)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    location / {
        try_files $uri  $uri/ /index.html;
    }
```

## Intrusive Configuration
### Demo
- [nginx.conf](./t/demo-server/usr/local/openresty/nginx/conf/nginx.conf)
- [your-site.conf](./t/demo-server/etc/nginx/conf.d/device-ratelimit.conf)

### Config
`vim /usr/local/openresty/nginx/conf/nginx.conf`  
redis_uri: redis :// [: password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]]  
server_device_check_urls: { ["server_name:listen_port"] = "your validate device uri for this site"}  

```lua
    init_by_lua_block {
        local drl = require("resty.device.ratelimit")
        drl.config({
            redis_uri = "redis://:YourRedisPassword@127.0.0.1:6379/0",
            device_id_header_name = "x-device-id",
            server_device_check_urls = {
                ["www.yoursite.com:80"] = "http://backend-server:8080/your-validate-device-id-api"
            }
        })
    }
```

### Define The DeviceId
1. Please ensure that the DeviceId is unique.
2. Please ensure that the DeviceId you set is verifiable on the server.

### Implement Validate DeviceId URI
Implement an interface to verify the validity of the deviceId. This interface should receive a JSON via POST and return a JSON  
Received JSON
```json
{
"device_id": "device id",
"remote_addr": "client ip",
"request_uri": "request uri",
"request_time": "unix timestamp",
"request_headers": {"x-device-id":"your device id", "other-header":""},
"server_name": "server_name defined in server block",
"server_port": "listening port defined in server block"
}
```
Response JSON
```json
{
    "valid": true,
    "expired": 3600
}
```

### Check And Limit Your URIs
`vim /etc/nginx/conf.d/your-site.conf`
```
    # no limit
    location /ajax/guest/ {
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit within the entire site, each interface to a maximum of 4 accesses within 10 seconds
    location /ajax/io/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("global_current_uri", 10, 4) then
                ngx.exit(503)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit a single device to a maximum of 1 access per interface within 1 seconds
    location /ajax/key/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("device_current_uri", 1, 1) then
                ngx.exit(429)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    # Limit a single device to a maximum of 1 access per interface within 3 seconds, and a total of no more than 40 accesses across all interfaces within 10 seconds
    location /ajax/ {
        access_by_lua_block {
            local drl = require("resty.device.ratelimit")
            if not drl.check() then
                ngx.exit(401)
            end
            if drl.limit("device_current_uri", 3, 1) or drl.limit("device_total_uris", 10, 40) then
                ngx.exit(429)
            end
            drl.record()
        }
        rewrite /ajax/(.*) /$1 break;
        proxy_pass http://backend-server:8080;
    }

    location / {
        try_files $uri  $uri/ /index.html;
    }
```


