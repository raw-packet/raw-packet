#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
arp_scan.py: ARP scan local network
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
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from argparse import ArgumentParser
from ipaddress import IPv4Address
from prettytable import PrettyTable
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
__status__ = 'Development'
# endregion


# region Main function
if __name__ == "__main__":

    # region Check user, platform and print banner
    Base = Base()
    Base.check_user()
    Base.check_platform()
    Base.print_banner()
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='ARP scan local network')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner')
    parser.add_argument('-I', '--target_ip', type=str, help='Set target IP address', default=None)
    parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=3)', default=3)
    parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=3)', default=3)

    args = parser.parse_args()
    # endregion

    # region Get your network settings
    if args.interface is None:
        Base.print_warning("Please set a network interface for sniffing ARP responses ...")
    current_network_interface = Base.netiface_selection(args.interface)

    your_mac_address = Base.get_netiface_mac_address(current_network_interface)
    if your_mac_address is None:
        Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
        exit(1)

    your_ip_address = Base.get_netiface_ip_address(current_network_interface)
    if your_ip_address is None:
        Base.print_error("Network interface: ", current_network_interface, " do not have IP address!")
        exit(1)

    first_ip_address = str(IPv4Address(unicode(Base.get_netiface_first_ip(current_network_interface))) - 1)
    last_ip_address = str(IPv4Address(unicode(Base.get_netiface_last_ip(current_network_interface))) + 1)
    # endregion

    # region Target IP is set
    if args.target_ip is not None:
        if not Base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address):
            Base.print_error("Bad value `-I, --target_ip`: ", args.target_ip,
                             "; target IP address must be in range: ", first_ip_address + " - " + last_ip_address)
            exit(1)
    # endregion

    # region General output
    Base.print_info("Network interface: ", current_network_interface)
    Base.print_info("Your IP address: ", your_ip_address)
    Base.print_info("Your MAC address: ", your_mac_address)

    # If target IP address is set print target IP, else print first and last IP
    if args.target_ip is not None:
        Base.print_info("Target IP: ", args.target_ip)
    else:
        Base.print_info("First IP: ", first_ip_address)
        Base.print_info("Last IP: ", last_ip_address)

    Base.print_info("Timeout: ", str(args.timeout) + " sec.")
    Base.print_info("Retry: ", str(args.retry))
    # endregion

    # region Start scanner
    arp_scan = ArpScan()
    results = arp_scan.scan(current_network_interface, args.timeout, args.retry, args.target_ip, True)
    # endregion

    # region Print results
    if len(results) > 0:
        Base.print_success("Found devices:")
        pretty_table = PrettyTable([Base.cINFO + 'IP address' + Base.cEND,
                                    Base.cINFO + 'MAC address' + Base.cEND,
                                    Base.cINFO + 'Vendor' + Base.cEND])
        for result in results:
            pretty_table.add_row([result['ip-address'], result['mac-address'], result['vendor']])
        print pretty_table
    else:
        Base.print_error("Could not find devices in local network on interface: ", current_network_interface)
    # endregion

# endregion