# CodeAlpha_BasicNetworkSniffer

## Overview
This project is a simple Python-based network sniffer that captures live packets, analyzes their structure, and displays key details such as source/destination IPs, protocols, and payloads.

## Tools & Libraries
- Python 3.x
- [scapy](https://scapy.net/) for packet capture and analysis
- socket (optional, for basic capture)

## Features
- Captures packets in real-time
- Displays source IP, destination IP, protocol, and payload size
- Can be extended to log packets to a file
- Protocol identification (TCP, UDP, ICMP, others)

## Installation
1. Install scapy:
   ```bash
   python3 -m pip install scapy
