#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
icmpv6_scan.py: ICMPv6 scan local network
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
from raw_packet.Utils.network import Ethernet_raw
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
# endregion

# region Import libraries
from argparse import ArgumentParser
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
    parser = ArgumentParser(description='ICMPv6 scanner script')
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner')
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=3)', default=5)
    parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=1)', default=3)
    parser.add_argument('-s', '--router_search', action='store_true', help='Search router IPv6 link local address')
    args = parser.parse_args()
    # endregion

    # region Get your network settings
    if args.interface is None:
        Base.print_warning("Please set a network interface for sniffing ICMPv6 responses ...")
    current_network_interface = Base.netiface_selection(args.interface)

    your_mac_address = Base.get_netiface_mac_address(current_network_interface)
    if your_mac_address is None:
        Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
        exit(1)

    your_ipv6_link_address = Base.get_netiface_ipv6_link_address(current_network_interface)
    if your_ipv6_link_address is None:
        Base.print_error("Network interface: ", current_network_interface, " do not have link local IPv6 address!")
        exit(1)
    # endregion

    # region Target MAC is set
    eth = Ethernet_raw()
    target_mac_address = None

    if args.target_mac is not None:
        if eth.convert_mac(args.target_mac):
            target_mac_address = str(args.target_mac).lower()
    # endregion

    # region General output
    Base.print_info("Network interface: ", current_network_interface)
    Base.print_info("Your IPv6 address: ", your_ipv6_link_address)
    Base.print_info("Your MAC address: ", your_mac_address)

    if target_mac_address is not None:
        Base.print_info("Target MAC address: ", target_mac_address)

    Base.print_info("Timeout: ", str(args.timeout) + " sec.")
    Base.print_info("Retry: ", str(args.retry))
    # endregion

    # region Init ICMPv6 scanner
    icmpv6_scan = ICMPv6Scan()
    # endregion

    # region Search IPv6 router
    if args.router_search:
        router_info = icmpv6_scan.search_router(current_network_interface, args.timeout, args.retry)
        if len(router_info.keys()) > 0:
            Base.print_success("Found IPv6 router:")
            Base.print_info("Router IPv6 link local address: ", router_info['router_ipv6_address'])

            if 'dns-server' in router_info.keys():
                Base.print_info("DNS server IPv6 address: ", str(router_info['dns-server']))

            Base.print_info("Router MAC address: ", router_info['router_mac_address'])
            Base.print_info("Router lifetime (s): ", str(router_info['router-lifetime']))
            Base.print_info("Reachable time (ms): ", str(router_info['reachable-time']))
            Base.print_info("Retrans timer (ms): ", str(router_info['retrans-timer']))

            if 'prefix' in router_info.keys():
                Base.print_info("Prefix: ", str(router_info['prefix']))
            if 'mtu' in router_info.keys():
                Base.print_info("MTU: ", str(router_info['mtu']))
    # endregion

    # region Scan IPv6 hosts
    else:
        results = icmpv6_scan.scan(current_network_interface, args.timeout, args.retry, target_mac_address, True)

        # region Print results
        if len(results) > 0:
            Base.print_success("Found devices:")
            pretty_table = PrettyTable([Base.cINFO + 'IPv6 address' + Base.cEND,
                                        Base.cINFO + 'MAC address' + Base.cEND,
                                        Base.cINFO + 'Vendor' + Base.cEND])
            for result in results:
                pretty_table.add_row([result['ip-address'], result['mac-address'], result['vendor']])
            print pretty_table
        else:
            Base.print_error("Could not find devices with IPv6 link local address in local network on interface: ",
                             current_network_interface)
        # endregion
    # endregion

# endregion
