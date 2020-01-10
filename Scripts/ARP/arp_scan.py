#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
arp_scan.py: ARP scan script
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
from typing import List, Dict
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
# endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Scanners.arp_scanner import ArpScan

    base: Base = Base()
    arp_scan: ArpScan = ArpScan()
    # endregion

    try:
        # region Check user, platform and print banner
        base.check_user()
        base.check_platform()
        base.print_banner()
        # endregion

        # region Parse script arguments
        parser = ArgumentParser(description='ARP scan script')
        parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner', default=None)
        parser.add_argument('-T', '--target_ip', type=str, help='Set target IP address', default=None)
        parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=3)', default=3)
        parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=3)', default=3)
        args = parser.parse_args()
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP responses ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_ip_address: str = base.get_interface_ip_address(current_network_interface)
        first_ip_address: str = base.get_first_ip_on_interface(current_network_interface)
        last_ip_address: str = base.get_last_ip_on_interface(current_network_interface)
        # endregion

        # region Target IP is set
        if args.target_ip is not None:
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad value `-T, --target_ip`: ' + base.error_text(args.target_ip) + \
                '; target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
        # endregion

        # region General output
        base.print_info('Network interface: ', current_network_interface)
        base.print_info('Your IP address: ', your_ip_address)
        base.print_info('Your MAC address: ', your_mac_address)

        # If target IP address is set print target IP, else print first and last IP
        if args.target_ip is not None:
            base.print_info('Target IP: ', args.target_ip)
        else:
            base.print_info('First IP: ', first_ip_address)
            base.print_info('Last IP: ', last_ip_address)
        base.print_info('Timeout: ', str(args.timeout) + ' sec.')
        base.print_info('Retry: ', str(args.retry))
        # endregion

        # region Start scanner
        results: List[Dict[str, str]] = arp_scan.scan(network_interface=current_network_interface, timeout=args.timeout,
                                                      retry=args.retry, target_ip_address=args.target_ip,
                                                      check_vendor=True, exclude_ip_addresses=None,
                                                      exit_on_failure=False, show_scan_percentage=True)
        # endregion

        # region Print results
        assert len(results) != 0, \
            'Could not find devices in local network on interface: ' + base.error_text(current_network_interface)

        base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', current_network_interface)
        pretty_table = PrettyTable([base.cINFO + 'IP address' + base.cEND,
                                    base.cINFO + 'MAC address' + base.cEND,
                                    base.cINFO + 'Vendor' + base.cEND])
        for result in results:
            pretty_table.add_row([result['ip-address'], result['mac-address'], result['vendor']])
        print(pretty_table)
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion
