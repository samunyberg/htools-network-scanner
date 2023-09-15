#!/usr/bin/env python

import optparse
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether


def get_options():
    parser = optparse.OptionParser()
    parser.add_option(
        "-t", "--target", dest="target", help="Target network IP address range."
    )
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error(
            "[-] Please specify a target IP address range. Use --help for more info."
        )

    return options


def get_connected_clients(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_requests = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for request in answered_requests:
        clients.append({"ip": request[1].psrc, "mac": request[1].hwsrc})

    return clients


def print_output(clients):
    if not clients:
        print("No clients found in specified network.")
        return

    print("IP\t\t\tMac Address")
    print("-----------------------------------------")
    for client in clients:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_options()
connected_clients = get_connected_clients(options.target)
print_output(connected_clients)
