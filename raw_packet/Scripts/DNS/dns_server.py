#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dns_server.py: DNS server (dns_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Servers.dns_server import DnsServer
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from typing import List, Dict, Union
from re import sub
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
__script_name__ = 'DNS server (dns_server)'
# endregion


# region Main function
def main() -> None:
    """
    Start DNS server (dns_server)
    :return: None
    """

    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    utils: Utils = Utils()
    # endregion

    # region Variables
    fake_domains: List[str] = list()
    no_such_domains: List[str] = list()
    fake_ipv4_addresses: List[str] = list()
    fake_ipv6_addresses: List[str] = list()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', help='Set interface name for send DNS reply packets', default=None)
    parser.add_argument('-p', '--port', type=int,
                        help='Set UDP port for listen DNS request packets (default: 53)', default=53)
    parser.add_argument('-t', '--target_mac', help='Set target MAC address', default=None)
    parser.add_argument('--T4', help='Set target IPv4 address', default=None)
    parser.add_argument('--T6', help='Set target IPv6 address', default=None)
    parser.add_argument('-c', '--config_file',
                        help='Set json config file name, example: --config_file "dns_server_config.json"',
                        default=None)
    parser.add_argument('--fake_domains',
                        help='Set fake domain regexp or domains, example: --fake_domains ".*apple.com,.*google.com"',
                        default=None)
    parser.add_argument('--no_such_domains', help='Set no such domain or domains, ' +
                                                  'example: --no_such_domains "apple.com,google.com"', default=None)
    parser.add_argument('--fake_ipv4',
                        help='Set fake IP address or addresses, example: --fake_ipv4 "192.168.0.1,192.168.0.2"',
                        default=None)
    parser.add_argument('--fake_ipv6',
                        help='Set fake IPv6 address or addresses, example: --fake_ipv6 "fd00::1,fd00::2"',
                        default=None)
    parser.add_argument('--ipv6', action='store_true', help='Enable IPv6')
    parser.add_argument('--disable_ipv4', action='store_true', help='Disable IPv4')
    parser.add_argument('--log_file_name', type=str,
                        help='Set file name for save DNS queries (default: "dns_server_log")',
                        default='dns_server_log')
    parser.add_argument('--log_file_format', type=str,
                        help='Set file format for save results: csv, xml, json, txt (default: "json")',
                        default='json')
    parser.add_argument('-f', '--fake_answer', action='store_true',
                        help='Set your IPv4 or IPv6 address in all answers')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    try:

        # region Get listen network interface, your IP and MAC address, first and last IP in local network
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
        # endregion

        # region General output
        base.print_info('Network interface: ', current_network_interface_settings['network-interface'])
        base.print_info('Your IPv4 address: ', current_network_interface_settings['ipv4-address'])
        base.print_info('Your IPv6 address: ', current_network_interface_settings['ipv6-link-address'])
        base.print_info('Your MAC address: ', current_network_interface_settings['mac-address'])
        # endregion

        # region Create fake domains list
        if args.fake_domains is not None:
            _fake_domains: str = sub(r' +', '', args.fake_domains)
            for domain_name in _fake_domains.split(','):
                fake_domains.append(domain_name)
        # endregion

        # region Create no such name list
        if args.no_such_domains is not None:
            _no_such_domains: str = sub(r' +', '', args.no_such_domains)
            for no_such_name in _no_such_domains.split(','):
                no_such_domains.append(no_such_name)
        # endregion

        # region Create fake ipv4 addresses list
        if args.fake_ipv4 is not None:
            _fake_ipv4: str = sub(r' +', '', args.fake_ipv4)
            for _ipv4_address in _fake_ipv4.split(','):
                fake_ipv4_addresses.append(utils.check_ipv4_address(network_interface=current_network_interface,
                                                                    ipv4_address=_ipv4_address,
                                                                    is_local_ipv4_address=False,
                                                                    parameter_name='fake IPv4 address'))
        # endregion

        # region Create fake ipv6 addresses list
        if args.fake_ipv6 is not None:
            _fake_ipv6: str = sub(r' +', '', args.fake_ipv6)
            for _ipv6_address in _fake_ipv6.split(','):
                fake_ipv6_addresses.append(utils.check_ipv6_address(network_interface=current_network_interface,
                                                                    ipv6_address=_ipv6_address,
                                                                    is_local_ipv6_address=False,
                                                                    parameter_name='fake IPv6 address',
                                                                    check_your_ipv6_address=False))
        # endregion

        # region Start DNS server
        dns_server: DnsServer = DnsServer(network_interface=current_network_interface)
        dns_server.start(listen_port=args.port,
                         target_mac_address=args.target_mac,
                         target_ipv4_address=args.T4,
                         target_ipv6_address=args.T6,
                         fake_answers=args.fake_answer,
                         fake_ipv4_addresses=fake_ipv4_addresses,
                         fake_ipv6_addresses=fake_ipv6_addresses,
                         fake_domains_regexp=fake_domains,
                         no_such_domains=no_such_domains,
                         listen_ipv6=args.ipv6,
                         disable_ipv4=args.disable_ipv4,
                         config_file=args.config_file,
                         log_file_name=args.log_file_name,
                         log_file_format=args.log_file_format)
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
