# disable systemd-resolved so that port 53 is free
systemctl stop systemd-resolved
systemctl disable systemd-resolved
systemctl mask systemd-resolved
# make sure DNS queries still get resolved 
echo "nameserver 8.8.8.8" > /etc/resolv.conf

#apt-get update
#apt-get upgrade -y

# install DNS service
apt-get install -y dnsmasq

rm -f /etc/resolv.conf
# remove default dnsmasq config file
rm -f /etc/dnsmasq.conf
# link DNS config file from shared folder
ln -s /home/vagrant/dns-config/dnsmasq.conf /etc/dnsmasq.conf
# enable and restart DNS service
systemctl enable dnsmasq
systemctl restart dnsmasq

# Point the host resolver at the local dnsmasq instance
echo "nameserver 127.0.0.1" > /etc/resolv.conf

sudo apt-get install -y openssl
sudo openssl genrsa -out /etc/ssl/private/secure-login.key 2048
sudo openssl req -new -x509 \
    -key /etc/ssl/private/secure-login.key \
    -out /etc/ssl/certs/secure-login.crt \
    -days 365 \
    -subj "/C=NL/ST=Noord-Holland/L=Eindhoven/O=SecureLogin/OU=Tue/CN=secure-login.com"

# install nginx
sudo apt install nginx -y
systemctl enable nginx
systemctl restart nginx
sudo ln -s /home/vagrant/nginx_sites/secure-login.com /etc/nginx/sites-enabled/secure-login.com
