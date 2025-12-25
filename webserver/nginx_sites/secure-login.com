server {
    listen 192.168.50.40:80;
    server_name secure-login.com;
    return 301 https://$host$request_uri;
}

server {
    listen 192.168.50.40:443 ssl;
    server_name secure-login.com;

    ssl_certificate     /etc/ssl/certs/secure-login.crt;
    ssl_certificate_key /etc/ssl/private/secure-login.key;

    root /var/www/secure-login.com;
    index secure-login.html;

    location /submit {
        return 200 "Submitted\n";
    }

    location / {
        try_files $uri $uri/ =404;
    }
}