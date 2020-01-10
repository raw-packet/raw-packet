#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
icmpv6_scan.py: ICMPv6 scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from argparse import ArgumentParser
from prettytable import PrettyTable
from typing import Union, Dict, List
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Main function
if __name__ == "__main__":

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet
    from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan

    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan()
    # endregion

    # region Check user, platform and print banner
    base.check_user()
    base.check_platform()
    base.print_banner()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='ICMPv6 scanner script')
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner')
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=3)', default=3)
    parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=3)', default=3)
    parser.add_argument('-s', '--router_search', action='store_true', help='Search router IPv6 link local address')
    args = parser.parse_args()
    # endregion

    # region Get your network settings
    if args.interface is None:
        base.print_warning("Please set a network interface for sniffing ICMPv6 responses ...")
    current_network_interface: str = base.network_interface_selection(args.interface)
    your_mac_address: str = base.get_interface_mac_address(current_network_interface)
    your_ipv6_link_address: str = base.get_interface_ipv6_link_address(current_network_interface)
    # endregion

    # region Set Target MAC address
    target_mac_address: Union[None, str] = None
    if args.target_mac is not None:
        base.mac_address_validation(args.target_mac, True)
        target_mac_address: str = str(args.target_mac).lower()
    # endregion

    # region General output
    base.print_info("Network interface: ", current_network_interface)
    base.print_info("Your IPv6 address: ", your_ipv6_link_address)
    base.print_info("Your MAC address: ", your_mac_address)
    if target_mac_address is not None:
        base.print_info("Target MAC address: ", target_mac_address)
    base.print_info("Timeout: ", str(args.timeout) + " sec.")
    base.print_info("Retry: ", str(args.retry))
    # endregion

    # region Search IPv6 router
    if args.router_search:
        router_info: Dict[str, Union[int, str]] = icmpv6_scan.search_router(network_interface=current_network_interface,
                                                                            timeout=args.timeout, retry=args.retry,
                                                                            exit_on_failure=True)
        base.print_success("Found IPv6 router:")
        base.print_info("Router IPv6 link local address: ", router_info['router_ipv6_address'])
        if 'dns-server' in router_info.keys():
            base.print_info("DNS server IPv6 address: ", str(router_info['dns-server']))
        base.print_info("Router MAC address: ", router_info['router_mac_address'])
        if 'vendor' in router_info.keys():
            base.print_info("Router vendor: ", router_info['vendor'])
        base.print_info("Router lifetime (s): ", str(router_info['router-lifetime']))
        base.print_info("Reachable time (ms): ", str(router_info['reachable-time']))
        base.print_info("Retrans timer (ms): ", str(router_info['retrans-timer']))
        if 'prefix' in router_info.keys():
            base.print_info("Prefix: ", str(router_info['prefix']))
        if 'mtu' in router_info.keys():
            base.print_info("MTU: ", str(router_info['mtu']))
    # endregion

    # region Scan IPv6 hosts
    else:
        results: List[Dict[str, str]] = icmpv6_scan.scan(network_interface=current_network_interface,
                                                         timeout=args.timeout, retry=args.retry,
                                                         target_mac_address=target_mac_address, check_vendor=True,
                                                         exit_on_failure=True)
        base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', current_network_interface)
        pretty_table = PrettyTable([base.cINFO + 'IPv6 address' + base.cEND,
                                    base.cINFO + 'MAC address' + base.cEND,
                                    base.cINFO + 'Vendor' + base.cEND])
        for result in results:
            pretty_table.add_row([result['ip-address'], result['mac-address'], result['vendor']])
        print(pretty_table)
    # endregion

# endregion
