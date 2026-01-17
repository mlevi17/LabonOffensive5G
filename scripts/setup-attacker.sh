apt-get update
apt-get upgrade -y

# Ensure right IPs are assigned via NetworkManager
nmcli con show "attacker-eth2" >/dev/null 2>&1 || \
nmcli con add type ethernet ifname eth1 con-name "attacker-eth2" ipv4.method manual ipv4.addresses 192.168.56.10/24 ipv4.gateway "" ipv4.dns "" autoconnect yes
nmcli con mod "attacker-eth2" ipv4.addresses 192.168.50.10/24 ipv4.method manual ipv4.gateway "" ipv6.method ignore
nmcli con up "attacker-eth2"

#Install packages
apt-get install -y \
    python3 \
    python3-pip \
    scapy \
    tcpdump

sudo apt install python3-netfilterqueue

#configure ip forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

rm -f /etc/resolv.conf
echo "nameserver 192.168.50.30" > /etc/resolv.conf

# install opneSSL and create a cert
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

# Create symlink for website
sudo ln -s /home/vagrant/nginx_sites/secure-login.com /etc/nginx/sites-enabled/secure-login.com

