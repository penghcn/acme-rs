## Usage
1)  The default CA (Certificate Authority) is Let's Encrypt, and the default algorithm is EC3, which is secp384r1.
```
cargo run --  dns=ai8.rs,www.ai8.rs dir=~/www/ai8.rs
```

2) To use another CA like ZeroSSL, like this:
```
cargo run --  dns=ai8.rs,www.ai8.rs dir=~/www/ai8.rs ca=z email=a@a.rs alg=ec5
```

3) For more parameter configurations, please refer to the following.

key | default | description
-|-|-
dns   | -   | required, single or multiple, separated by commas. For example: ai8.rs,v.ai8.rs,www.ai8.rs
dir   | -   | required, acme well-known root directory, must match your Nginx configuration, e.g. /www/ai8.rs
email | -   | register account email. when ca is zerossl, email required
ca    | le  | le,z,zero,g,google,b,buypass
alg   | ec3 | ec2,ec3,ec5,rsa2,rsa4, which are secp256r1,secp384r1,secp521r1,rsa2048,rsa4096

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
```

Recommended SSL ciphers.
```
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;
```

5) Install rust. [Click link.](https://www.rust-lang.org/tools/install)