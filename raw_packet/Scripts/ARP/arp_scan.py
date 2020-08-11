#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_scan.py: ARP Scanner (arp_scan)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
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
__script_name__ = 'ARP Scanner (arp_scan)'
# endregion

# region Init Raw-packet Base class
base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
# endregion


# region Scan function
def scan(interface: Union[None, str] = None,
         target_ip: Union[None, str] = None,
         timeout: int = 5,
         retry: int = 5):
    """
    ARP scan
    :param interface: Network interface name for ARP scanner
    :param target_ip: Target IPv4 address
    :param timeout: Timeout (default=5)
    :param retry: Number of retry packets (default=5)
    :return: None
    """
    # region Print banner
    base.print_banner(__script_name__)
    # endregion

    try:
        # region Get your network interface settings
        current_network_interface: str = \
            base.network_interface_selection(interface_name=interface,
                                             message='Please select a network interface for ' +
                                                     __script_name__ + ' from table: ')
        current_network_interface_settings: Dict[str, Union[None, str, List[str]]] = \
            base.get_interface_settings(interface_name=current_network_interface,
                                        required_parameters=['mac-address',
                                                             'ipv4-address',
                                                             'first-ipv4-address',
                                                             'last-ipv4-address'])
        # endregion

        # region Target IP is set
        if target_ip is not None:
            utils: Utils = Utils()
            utils.check_ipv4_address(network_interface=current_network_interface,
                                     ipv4_address=target_ip,
                                     is_local_ipv4_address=True,
                                     parameter_name='target IPv4 address')
        # endregion

        # region General output
        base.print_info('Network interface: ', current_network_interface_settings['network-interface'])
        base.print_info('Your IP address: ', current_network_interface_settings['ipv4-address'])
        base.print_info('Your MAC address: ', current_network_interface_settings['mac-address'])

        # If target IP address is set print target IP, else print first and last IP
        if target_ip is not None:
            base.print_info('Target IP: ', target_ip)
        else:
            base.print_info('First IP: ', current_network_interface_settings['first-ipv4-address'])
            base.print_info('Last IP: ', current_network_interface_settings['last-ipv4-address'])
        base.print_info('Timeout: ', str(timeout) + ' sec.')
        base.print_info('Retry: ', str(retry))
        # endregion

        # region Start scanner
        arp_scan: ArpScan = ArpScan(network_interface=current_network_interface)
        results: List[Dict[str, str]] = arp_scan.scan(timeout=timeout, retry=retry,
                                                      target_ip_address=target_ip,
                                                      check_vendor=True, exclude_ip_addresses=None,
                                                      exit_on_failure=False, show_scan_percentage=True)
        # endregion

        # region Print results
        assert len(results) != 0, \
            'Could not find devices in local network on interface: ' + base.error_text(current_network_interface)

        if target_ip is None:
            base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', current_network_interface)
        else:
            base.print_success('Found target: ', target_ip)
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


# region Main function
def main() -> None:
    """
    Start ARP Scanner (arp_scan)
    :return: None
    """

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for ARP scanner', default=None)
    parser.add_argument('-t', '--target_ip', type=str, help='Set target IPv4 address', default=None)
    parser.add_argument('--timeout', type=int, help='Set timeout (default=5)', default=5)
    parser.add_argument('--retry', type=int, help='Set number of retry packets (default=5)', default=5)
    args = parser.parse_args()
    # endregion

    # region Scan
    scan(interface=args.interface,
         target_ip=args.target_ip,
         timeout=args.timeout,
         retry=args.retry)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
