apt-get update
apt-get upgrade -y

# Force DNS resolution through the server VM
systemctl stop systemd-resolved
systemctl disable systemd-resolved
rm -f /etc/resolv.conf
echo "nameserver 192.168.50.30" > /etc/resolv.conf