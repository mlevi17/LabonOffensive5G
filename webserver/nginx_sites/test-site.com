server {
    listen 192.168.50.40:80;
    server_name test-site.com;

    root /var/www/test-site.com;
    index index.html;

    location /submit {
        return 200 "Submitted\n";
    }
    
    location / {
        try_files $uri $uri/ =404;
    }

}