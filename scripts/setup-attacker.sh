apt-get update
apt-get upgrade -y

#Install packages
apt-get install -y \
    python3 \
    python3-pip \
    scapy

#configure ip forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

