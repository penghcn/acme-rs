## Usage
1)  The default CA is Let's Encrypt, and the default domain algorithm is EC3, which is secp384r1.
```
git clone https://github.com/penghcn/acme-rs.git
cd acme-rs/

cargo run --  dns=ai8.rs,www.ai8.rs dir=/www/ai8.rs
```

2) To use another CA like ZeroSSL, like this:
```
cargo run --  dns=ai8.rs,www.ai8.rs dir=/www/ai8.rs ca=z email=a@a.rs alg=ec5
```

3) For more parameter configurations, please refer to the following.

key | default | description
-|-|-
dns     | -    | Required, single or multiple, separated by commas. For example: ai8.rs,www.ai8.rs
dir     | -    | Required, acme root path, must match your nginx config, e.g. /www/ai8.rs
email   | -    | Register account email
eab_kid | -    | `<eab_kid>`, for Google Trust
eab_key | -    | `<eab_hmac_key>`, for Google Trust
ca      | le   | Case-insensitive. The defalut is "le", which stands for Let's Encrypt. ZeroSSL can be abbreviated as "Z","z","zero". Google Trust as "g"
alg     | ec3  | Case-insensitive. Algorithm abbreviation: ec2,ec3,ec5,rsa2,rsa4, which are secp256r1,secp384r1,secp521r1,rsa2048,rsa4096
log     | info | Case-insensitive. Log level: info,debug,trace

4) Nginx configuration.
```
    ## for acme ssl
    server {
        listen 80;
        server_name ai8.rs www.ai8.rs;
        location /.well-known/acme-challenge/ {
            alias /www/ai8.rs/challenges/;
            try_files $uri =404;
        }

        location / {
            rewrite ^/(.*)$ https://$http_host/$1 permanent;
        }       
    }

    server {
        listen 443 ssl http2;
        server_name ai8.rs www.ai8.rs;

        include ssl.conf; # Recommended SSL ciphers 

        ssl_certificate /www/ai8.rs/.acme/chained.pem;
        ssl_certificate_key /www/ai8.rs/.acme/domain.key;

        real_ip_header X-Real-IP;
        
        location / {
            proxy_set_header    X-Real-IP       $remote_addr;
            proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
            #proxy_set_header   Host            $http_host;
            proxy_set_header    X-NginX-Proxy   true;
            proxy_set_header    Connection      "";
            proxy_http_version  1.1;
            proxy_pass          https://bing.com;
        }
    }
```

Parameter must match the nginx configuration. For example:
``` 
    ## dns=ai8.rs,www.ai8.rs
    server_name ai8.rs www.ai8.rs;

    ## The "/challenges/" directory is a fixed path
    ## dir=/www/ai8.rs
    alias /www/ai8.rs/challenges/;

    ## The files "/.acme/chained.pem" and "/.acme/domain.key" are at fixed paths
    ## dir=/www/ai8.rs
    ssl_certificate /www/ai8.rs/.acme/chained.pem;
    ssl_certificate_key /www/ai8.rs/.acme/domain.key;
```

Recommended SSL ciphers. Typically located at "ssl.conf" file. 
```
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;
```

5) Install rust. [Official link.](https://www.rust-lang.org/tools/install)
```
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh

```
Fix some errors.
```
# For Debian, Ubuntu 
# error: linker `cc` not found
# error: could not compile `proc-macro2` (build script) due to 1 previous error rust
sudo apt update
sudo apt install curl build-essential gcc make -y

# failed to run custom build command for `openssl-sys v0.9.102`
sudo apt install libssl-dev pkg-config -y
```
