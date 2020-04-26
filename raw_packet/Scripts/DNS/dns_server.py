#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dns_server.py: DNS server script
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Servers.dns_server import RawDnsServer
from argparse import ArgumentParser
from typing import List
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
def main():

    # region Init Raw-packet classes
    base: Base = Base()
    dns_server: RawDnsServer = RawDnsServer()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform()
    # endregion

    # region Variables
    fake_domains: List[str] = list()
    no_such_domains: List[str] = list()
    fake_ipv4_addresses: List[str] = list()
    fake_ipv6_addresses: List[str] = list()
    # endregion

    try:
        # region Parse script arguments
        parser = ArgumentParser(description='DNS server')
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

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing DNS queries ...')
        current_network_interface = base.network_interface_selection(args.interface)
        # endregion

        # region Create fake domains list
        if args.fake_domains is not None:
            for domain_name in str(args.fake_domains).replace(' ', '').split(','):
                fake_domains.append(domain_name)
        # endregion

        # region Create no such name list
        if args.no_such_domains is not None:
            for no_such_name in str(args.no_such_domains).replace(' ', '').split(','):
                no_such_domains.append(no_such_name)
        # endregion

        # region Create fake ipv4 addresses list
        if args.fake_ipv4 is not None:
            for ipv4_address in str(args.fake_ipv4).replace(' ', '').split(','):
                assert base.ip_address_validation(ipv4_address), \
                    'Illegal fake IPv4 address: ' + base.error_text(ipv4_address)
                fake_ipv4_addresses.append(ipv4_address)
        # endregion

        # region Create fake ipv6 addresses list
        if args.fake_ipv6 is not None:
            for ipv6_address in str(args.fake_ipv6).replace(' ', '').split(','):
                assert base.ipv6_address_validation(ipv6_address), \
                    'Illegal fake IPv6 address: ' + base.error_text(ipv6_address)
                fake_ipv6_addresses.append(ipv6_address)
        # endregion

        # region Script arguments condition check and print info message
        if not args.quiet:

            # region Argument fake_answer is set
            if args.fake_answer:
                if not args.disable_ipv4:
                    base.print_info('DNS answer fake IPv4 address: ', (', '.join(fake_ipv4_addresses)),
                                    ' for all DNS queries')
                if len(fake_ipv6_addresses) > 0:
                    base.print_info('DNS answer fake IPv6 address: ', (', '.join(fake_ipv6_addresses)),
                                    ' for all DNS queries')
            # endregion

            # region Argument fake_answer is NOT set
            else:
                # region Fake domains list is set
                if len(fake_domains) > 0:
                    if args.fake_ipv4 is not None:
                        base.print_info('DNS answer fake IPv4 address: ', (', '.join(fake_ipv4_addresses)),
                                        ' for domain: ', (', '.join(fake_domains)))
                    if args.fake_ipv6 is not None:
                        base.print_info('DNS answer fake IPv6 address: ', (', '.join(fake_ipv6_addresses)),
                                        ' for domain: ', (', '.join(fake_domains)))
                # endregion

                # region Fake domains list is NOT set
                else:
                    if args.fake_ipv4 is not None:
                        base.print_info('DNS answer fake IPv4 address: ', (', '.join(fake_ipv4_addresses)),
                                        ' for all DNS queries')
                    if args.fake_ipv6 is not None:
                        base.print_info('DNS answer fake IPv6 address: ', (', '.join(fake_ipv6_addresses)),
                                        ' for all DNS queries')
                # endregion

            # endregion

        # endregion

        # region Print info message
        if not args.quiet:
            base.print_info('Waiting for a DNS requests ...')
        # endregion

        # region Start DNS server
        dns_server.listen(listen_network_interface=current_network_interface,
                          listen_port=args.port,
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
