from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, getmacbyip


def arp_spoof_detect(packet):
    if ARP in packet and packet[ARP].op in (1, 2):  # ARP Request (1) or ARP Reply (2)
        arp_src_mac = packet[ARP].hwsrc
        arp_src_ip = packet[ARP].psrc
        if arp_src_mac != getmacbyip(arp_src_ip):
            print(f"Possible ARP spoofing detected: {arp_src_ip} is claiming to have MAC {arp_src_mac}")

def ip_spoof_detect(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_src_mac = packet.src
        if ip_src_mac != getmacbyip(ip_src):
            print(f"Possible IP spoofing detected: {ip_src} is using MAC {ip_src_mac}")

def packet_callback(packet):
    arp_spoof_detect(packet)
    ip_spoof_detect(packet)

# Sniffing Ethernet traffic on the specified interface (change 'eth0' to your interface name)
sniff(iface='eth0', prn=packet_callback, store=0)