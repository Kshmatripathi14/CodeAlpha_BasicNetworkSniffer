#!/usr/bin/env python3
"""
Basic Network Sniffer using Scapy.
Captures live packets and prints source/destination IPs, protocol, and packet length.
Run with sudo/administrator rights.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = ""
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "OTHER"
        length = len(packet)
        print(f"[+] Packet: {ip_src} -> {ip_dst} | Protocol: {proto} | Length: {length}")

if __name__ == "__main__":
    print("[*] Starting network sniffer...")
    sniff(prn=packet_callback, store=False)
