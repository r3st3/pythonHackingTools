#!/usr/bin/env python
import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniffed_packets)


def get_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_arp_request = broadcast/arp_request
        answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
        clients_list = []
        #print(answered_list[0])
        return answered_list[0][1].hwsrc


def processed_sniffed_packets(packet):

    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[+] You are under attack")
        except IndexError:
            pass
        except KeyboardInterrupt:
            print("[!] CTRL + C Detected.... Quitting")





sniff("eth0")