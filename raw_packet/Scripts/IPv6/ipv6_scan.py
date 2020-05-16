#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
icmpv6_scan.py: ICMPv6 scan (icmpv6_scan)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
from raw_packet.Scanners.icmpv6_router_search import ICMPv6RouterSearch
from argparse import ArgumentParser, RawDescriptionHelpFormatter
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
__script_name__ = 'ICMPv6 scan (icmpv6_scan)'
# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    utils: Utils = Utils()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner')
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=5)', default=5)
    parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=5)', default=5)
    parser.add_argument('-s', '--router_search', action='store_true', help='Search router IPv6 link local address')
    args = parser.parse_args()
    base.print_banner()
    # endregion

    # region Get your network settings
    current_network_interface: str = \
        base.network_interface_selection(interface_name=args.interface,
                                         message='Please select a network interface for ' +
                                                 __script_name__ + ' from table: ')
    current_network_interface_settings: Dict[str, Union[None, str, List[str]]] = \
        base.get_interface_settings(interface_name=current_network_interface,
                                    required_parameters=['mac-address',
                                                         'ipv4-address'])
    if current_network_interface_settings['ipv6-link-address'] is None:
        current_network_interface_settings['ipv6-link-address'] = \
            base.make_ipv6_link_address(current_network_interface_settings['mac-address'])
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan(network_interface=current_network_interface)
    router_search: ICMPv6RouterSearch = ICMPv6RouterSearch(network_interface=current_network_interface)
    # endregion

    # region Set Target MAC address
    target_mac_address: Union[None, str] = None
    if args.target_mac is not None:
        target_mac_address: str = utils.check_mac_address(mac_address=args.target_mac,
                                                          parameter_name='target MAC address')
    # endregion

    # region General output
    base.print_info("Network interface: ", current_network_interface)
    base.print_info("Your IPv6 address: ", current_network_interface_settings['ipv6-link-address'])
    base.print_info("Your MAC address: ", current_network_interface_settings['mac-address'])
    if target_mac_address is not None:
        base.print_info("Target MAC address: ", target_mac_address)
    base.print_info("Timeout: ", str(args.timeout) + " sec.")
    base.print_info("Retry: ", str(args.retry))
    # endregion

    # region Search IPv6 router
    if args.router_search:
        router_info: Dict[str, Union[int, str]] = router_search.search(timeout=args.timeout, retry=args.retry,
                                                                       exit_on_failure=True)
        base.print_success("Found IPv6 router:")
        base.print_info("Router IPv6 link local address: ", router_info['router_ipv6_address'])
        if 'dns-server' in router_info.keys():
            base.print_info("DNS server IPv6 address: ", str(router_info['dns-server']))
        if 'router_mac_address' in router_info.keys():
            base.print_info("Router MAC address: ", router_info['router_mac_address'])
        if 'vendor' in router_info.keys():
            base.print_info("Router vendor: ", router_info['vendor'])
        if 'router-lifetime' in router_info.keys():
            base.print_info("Router lifetime (s): ", str(router_info['router-lifetime']))
        if 'reachable-time' in router_info.keys():
            base.print_info("Reachable time (ms): ", str(router_info['reachable-time']))
        if 'retrans-timer' in router_info.keys():
            base.print_info("Retrans timer (ms): ", str(router_info['retrans-timer']))
        if 'prefix' in router_info.keys():
            base.print_info("Prefix: ", str(router_info['prefix']))
        if 'mtu' in router_info.keys():
            base.print_info("MTU: ", str(router_info['mtu']))
    # endregion

    # region Scan IPv6 hosts
    else:
        results: List[Dict[str, str]] = icmpv6_scan.scan(timeout=args.timeout, retry=args.retry,
                                                         target_mac_address=target_mac_address, check_vendor=True,
                                                         exit_on_failure=True)
        base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', current_network_interface)
        pretty_table = PrettyTable([base.cINFO + 'Index' + base.cEND,
                                    base.cINFO + 'IPv6 address' + base.cEND,
                                    base.cINFO + 'MAC address' + base.cEND,
                                    base.cINFO + 'Vendor' + base.cEND])
        index: int = 1
        for result in results:
            pretty_table.add_row([index, result['ip-address'], result['mac-address'], result['vendor']])
            index += 1
        print(pretty_table)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
