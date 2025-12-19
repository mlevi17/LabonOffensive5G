apt-get update
apt-get upgrade -y

# Ensure right IPs are assigned via NetworkManager
nmcli con show "attacker-eth1" >/dev/null 2>&1 || \
nmcli con add type ethernet ifname eth1 con-name "attacker-eth1" ipv4.method manual ipv4.addresses 192.168.56.10/24 ipv4.gateway "" ipv4.dns "" autoconnect yes
nmcli con mod "attacker-eth1" ipv4.addresses 192.168.50.10/24 ipv4.method manual ipv4.gateway "" ipv6.method ignore
nmcli con up "attacker-eth1"

#Install packages
apt-get install -y \
    python3 \
    python3-pip \
    scapy \
    tcpdump

#configure ip forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

