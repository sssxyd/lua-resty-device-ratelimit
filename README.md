# lua-resty-device-ratelimit
Using OpenResty, add non-intrusive client interface access permissions and rate limits to your site.

## Install OpenResty and Modules
Please follow the official documentation to install OpenResty
Then, install the following modules:

1. openresty/lua-resty-redis
2. pintsized/lua-resty-http
3. sssxyd/lua-resty-device-ratelimit

For CentOS, you can install them using the following commands:

<pre lang="no-highlight"><code>
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

</code></pre>

## Non-Intrusive Configuration
### Demo
- [nginx.conf](./t/zero-intrusion-demo/usr/local/openresty/nginx/conf/nginx.conf)
- [your-site.conf](./t/zero-intrusion-demo/etc/nginx/conf.d/zero-intrusion-ratelimit.conf)

### Config

### Proxy Your Login URI

### Create Validate DeviceId URI

### Check And Limit Your URIs

## Intrusive Configuration
### Demo
- [nginx.conf](./t/demo-server/usr/local/openresty/nginx/conf/nginx.conf)
- [your-site.conf](./t/demo-server/etc/nginx/conf.d/device-ratelimit.conf)

### Config
```lua
    init_by_lua_block {
        local drl = require("resty.device.ratelimit")
        --redis_uri: redis :// [: password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]] [&database=database]]
        --server_device_check_urls: { ["server_name:listen_port"] = "your validate device uri for this site"}
        drl.config({
            redis_uri = "redis://:YourRedisPassword@127.0.0.1:6379/0",
            device_id_cookie_name = "CookieNameForDeviceId",
            server_device_check_urls = {
                ["www.yoursite.com:443"] = "http://backend-server:8080/check-device-id"
            }
        })
    }
```

### Define The DeviceId

### Implement Validate DeviceId URI

### Check And Limit Your URIs

## Rate Limiting Metrics

## Rate Limiting API Specification

## Check Device ID API Specification

