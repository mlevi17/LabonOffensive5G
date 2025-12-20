systemctl stop systemd-resolved
systemctl disable systemd-resolved
echo "nameserver 8.8.8.8" > /etc/resolv.conf

apt-get update
apt-get upgrade -y

# install DNS 
apt-get install -y dnsmasq

# Completely disable systemd-resolved and configure dnsmasq
systemctl mask systemd-resolved
rm -f /etc/resolv.conf

# Copy dnsmasq configuration and set it up
rm -f /etc/dnsmasq.conf
ln -s /home/vagrant/dns-config/dnsmasq.conf /etc/dnsmasq.conf
systemctl enable dnsmasq
systemctl restart dnsmasq

# Point the host resolver at the local dnsmasq instance
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# install nginx
sudo apt install nginx -y
sudo ln -s /home/vagrant/nginx_sites/test-site.com /etc/nginx/sites-enabled/test-site.com
