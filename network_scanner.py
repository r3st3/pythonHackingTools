#!/usr/bin/env python

import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast/arp_request
    answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        clients_dic = {"ip" : element[1].psrc, "mac" : element[1].hwsrc}
        clients_list.append(clients_dic)
    return clients_list

def print_results(results_list):
    print("IP\t\t\tMAC\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP or Range")
    options = parser.parse_args()# leggo arguments e options
    if not options.target:
        parser.error("[!] Please specify a target, --help for more info")
    return options


options = get_arguments()
scan_results = scan(options.target)
print_results(scan_results)
