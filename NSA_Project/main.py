# Define known bad MAC addresses and rogue AP addresses
from scapy.layers.dot11 import Dot11Deauth, Dot11Beacon, Dot11
from scapy.layers.inet import IP
from scapy.layers.l2 import getmacbyip, ARP
from scapy.sendrecv import sniff

# Define initial known bad MAC addresses and rogue AP addresses
bad_mac_addresses = ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]
rogue_ap_addresses = ["00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff"]

# List of authorized channels for wifi
authorized_channels = [1, 6, 11]  # Example: authorized channels 1, 6, and 11

# Sender/Deauth dictionary
deauth_count = {}

# Threat Scores for each MAC address
threat_scores = {}
def update_threat_score(mac_address, score_increment):
    if mac_address not in threat_scores:
        threat_scores[mac_address] = 0
    threat_scores[mac_address] += score_increment

def arp_spoof_detect(packet):
    global bad_mac_addresses
    if ARP in packet and packet[ARP].op in (1, 2):  # ARP Request (1) or ARP Reply (2)
        arp_src_mac = packet[ARP].hwsrc
        arp_src_ip = packet[ARP].psrc
        if arp_src_mac != getmacbyip(arp_src_ip):
            print(f"Possible ARP spoofing detected: {arp_src_ip} is claiming to have MAC {arp_src_mac}")
            if arp_src_mac not in bad_mac_addresses:
                bad_mac_addresses.append(arp_src_mac)
                print(f"Added {arp_src_mac} to bad MAC addresses list")


def ip_spoof_detect(packet):
    global bad_mac_addresses
    if IP in packet:
        ip_src = packet[IP].src
        ip_src_mac = packet.src
        if ip_src_mac != getmacbyip(ip_src):
            print(f"Possible IP spoofing detected: {ip_src} is using MAC {ip_src_mac}")
            if ip_src_mac not in bad_mac_addresses:
                bad_mac_addresses.append(ip_src_mac)
                print(f"Added {ip_src_mac} to bad MAC addresses list")


def deauth_detect(packet):
    global deauth_count
    if Dot11Deauth in packet:
        sender_mac = packet[Dot11].addr2  # MAC address of the sender
        if sender_mac not in deauth_count:
            deauth_count[sender_mac] = 1
        else:
            deauth_count[sender_mac] += 1

        # Check if the sender has sent an excessive number of deauth packets (e.g., more than 10)
        if deauth_count[sender_mac] > 10:
            print(f"Excessive deauthentication packets detected from MAC address {sender_mac}")

def rogue_ap_detect(packet):
    global rogue_ap_addresses
    if Dot11Beacon in packet:
        bssid = packet[Dot11].addr2.lower()
        if bssid not in rogue_ap_addresses:
            print(f"Rogue access point detected: BSSID {bssid}")
            rogue_ap_addresses.append(bssid)
            print(f"Added {bssid} to rogue AP addresses list")


def unauthorized_channel_detect(packet, authorized_channels):
    if Dot11Beacon in packet:
        channel = ord(packet[Dot11Beacon].info[0])
        if channel not in authorized_channels:
            print(f"Unauthorized Wi-Fi channel detected: Channel {channel}")


# Add unauthorized_channel_detect to the packet_callback function
def packet_callback(packet):
    arp_spoof_detect(packet)
    ip_spoof_detect(packet)
    deauth_detect(packet)
    rogue_ap_detect(packet)
    unauthorized_channel_detect(packet)


# Add unauthorized_channel_detect to the packet_callback function
def packet_callback(packet):
    arp_spoof_detect(packet)
    ip_spoof_detect(packet)
    deauth_detect(packet)
    rogue_ap_detect(packet)
    unauthorized_channel_detect(packet)

# Sniffing Wi-Fi traffic on the specified interface (change 'wlan0' to your interface name)
sniff(iface='wlan0', prn=packet_callback, store=0)
