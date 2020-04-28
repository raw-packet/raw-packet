#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_scan.py: ARP Scan (arp_scan)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Scanners.arp_scanner import ArpScan
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from prettytable import PrettyTable
from typing import List, Dict, Union
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
__script_name__ = 'ARP Scan (arp_scan)'
# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base()
    # endregion

    # region Check user and platform and print banner
    base.check_user()
    base.check_platform(available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    script_description: str = \
        base.get_banner() + '\n' + \
        ' ' * (int((55 - len(__script_name__)) / 2)) + \
        base.info_text(__script_name__) + '\n\n'
    parser = ArgumentParser(description=script_description, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner', default=None)
    parser.add_argument('-T', '--target_ip', type=str, help='Set target IP address', default=None)
    parser.add_argument('-t', '--timeout', type=int, help='Set timeout (default=3)', default=3)
    parser.add_argument('-r', '--retry', type=int, help='Set number of retry (default=3)', default=3)
    args = parser.parse_args()
    # endregion

    # region Print banner
    base.print_banner()
    # endregion

    try:
        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP responses ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        current_network_interface_settings: Dict[str, Union[None, str, List[str]]] = \
            base.get_interface_settings(interface_name=current_network_interface,
                                        required_parameters=['mac-address', 'ipv4-address',
                                                             'first-ipv4-address', 'last-ipv4-address'])
        your_mac_address: str = current_network_interface_settings['mac-address']
        your_ip_address: str = current_network_interface_settings['ipv4-address']
        first_ip_address: str = current_network_interface_settings['first-ipv4-address']
        last_ip_address: str = current_network_interface_settings['last-ipv4-address']
        arp_scan: ArpScan = ArpScan(network_interface=current_network_interface)
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
        results: List[Dict[str, str]] = arp_scan.scan(timeout=args.timeout,
                                                      retry=args.retry, target_ip_address=args.target_ip,
                                                      check_vendor=True, exclude_ip_addresses=None,
                                                      exit_on_failure=False, show_scan_percentage=True)
        # endregion

        # region Print results
        assert len(results) != 0, \
            'Could not find devices in local network on interface: ' + base.error_text(current_network_interface)

        base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', current_network_interface)
        pretty_table = PrettyTable([base.cINFO + 'Index' + base.cEND,
                                    base.cINFO + 'IP address' + base.cEND,
                                    base.cINFO + 'MAC address' + base.cEND,
                                    base.cINFO + 'Vendor' + base.cEND])
        index: int = 1
        for result in results:
            pretty_table.add_row([index, result['ip-address'], result['mac-address'], result['vendor']])
            index += 1
        print(pretty_table)
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
