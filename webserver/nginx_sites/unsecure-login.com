server {
    listen 192.168.50.40:80;
    server_name unsecure-login.com;

    root /var/www/unsecure-login.com;
    index unsecure-login.html;

    location /submit {
        return 200 "Submitted\n";
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}