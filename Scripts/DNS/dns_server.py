#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
dns_server.py: DNS server
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
from raw_packet.Servers.dns_server import DnsServer
# endregion

# region Import libraries
from argparse import ArgumentParser
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

    # region Check user and platform
    Base = Base()
    Base.check_user()
    Base.check_platform()
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='DNS server')

    parser.add_argument('-i', '--interface', help='Set interface name for send DNS reply packets', default=None)
    parser.add_argument('-p', '--port', type=int,
                        help='Set UDP port for listen DNS request packets (default: 53)', default=53)

    parser.add_argument('-t', '--target_mac', help='Set target MAC address', default=None)
    parser.add_argument('--T4', help='Set target IPv4 address', default=None)
    parser.add_argument('--T6', help='Set target IPv6 address', default=None)

    parser.add_argument('--fake_domains',
                        help='Set fake domain or domains, example: --fake_domains "apple.com,google.com"',
                        default=None)
    parser.add_argument('--no_such_names', help='Set no such domain or domains, ' +
                                                'example: --no_such_names "apple.com,google.com"', default=None)
    parser.add_argument('--fake_ip',
                        help='Set fake IP address or addresses, example: --fake_ip "192.168.0.1,192.168.0.2"',
                        default=None)
    parser.add_argument('--fake_ipv6',
                        help='Set fake IPv6 address or addresses, example: --fake_ipv6 "fd00::1,fd00::2"',
                        default=None)

    parser.add_argument('--ipv6', action='store_true', help='Enable IPv6')
    parser.add_argument('--disable_ipv4', action='store_true', help='Disable IPv4')
    parser.add_argument('-f', '--fake_answer', action='store_true', help='Set your IPv4 or IPv6 address in all answers')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

    args = parser.parse_args()
    # endregion

    # region Print banner if argument quit is not set
    if not args.quiet:
        Base.print_banner()
    # endregion

    # region Get your network settings
    if args.interface is None:
        Base.print_warning("Please set a network interface for sniffing DNS queries ...")
    current_network_interface = Base.netiface_selection(args.interface)
    # endregion

    # region Create fake domains list
    fake_domains = []
    if args.fake_domains is not None:

        # Delete spaces
        fake_domains_string = args.fake_domains.replace(" ", "")

        # Create list
        for domain_name in fake_domains_string.split(","):
            fake_domains.append(domain_name)
    # endregion

    # region Create no such name list
    no_such_names = []

    if args.no_such_names is not None:

        # Delete spaces
        no_such_names_string = args.no_such_names.replace(" ", "")

        # Create list
        for no_such_name in no_such_names_string.split(","):
            no_such_names.append(no_such_name)
            no_such_names.append("www." + no_such_name)
    # endregion

    # region Create fake ipv4 addresses list
    fake_ip_addresses = []
    if args.fake_ip is not None:

        # Delete spaces
        fake_ip_string = args.fake_ip.replace(" ", "")

        # Create list
        for ip_address in fake_ip_string.split(","):
            if Base.ip_address_validation(ip_address):
                fake_ip_addresses.append(ip_address)
            else:
                Base.print_error("Illegal IPv4 address: ", ip_address)
                exit(1)
    # endregion

    # region Create fake ipv6 addresses list
    fake_ipv6_addresses = []
    if args.fake_ipv6 is not None:

        # Delete spaces
        fake_ipv6_string = args.fake_ipv6.replace(" ", "")

        # Create list
        for ipv6_address in fake_ipv6_string.split(","):
            if Base.ipv6_address_validation(ipv6_address):
                fake_ipv6_addresses.append(ipv6_address)
            else:
                Base.print_error("Illegal IPv6 address: ", ipv6_address)
                exit(1)
    # endregion

    # region Script arguments condition check and print info message
    if not args.quiet:

        # region Argument fake_answer is set
        if args.fake_answer:
            if not args.disable_ipv4:
                Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_ip_addresses)), " for all DNS queries")

            if len(fake_ipv6_addresses) > 0:
                Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_ipv6_addresses)), " for all DNS queries")

        # endregion

        # region Argument fake_answer is NOT set
        else:

            # region Fake domains list is set
            if len(fake_domains) > 0:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_ip_addresses)),
                                    " for domain: ", (", ".join(fake_domains)))

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_ipv6_addresses)),
                                    " for domain: ", (", ".join(fake_domains)))

            # endregion

            # region Fake domains list is NOT set
            else:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_ip_addresses)),
                                    " for all DNS queries")

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_ipv6_addresses)),
                                    " for all DNS queries")

            # endregion

        # endregion

    # endregion

    # region Print info message
    if not args.quiet:
        Base.print_info("Waiting for a DNS requests ...")
    # endregion

    # region Start DNS server
    dns_server = DnsServer()
    dns_server.listen(listen_network_interface=current_network_interface,
                      listen_port=args.port,
                      target_mac_address=args.target_mac,
                      target_ip_address=args.T4,
                      target_ipv6_address=args.T6,
                      fake_answers=args.fake_answer,
                      fake_ip_addresses=fake_ip_addresses,
                      fake_ipv6_addresses=fake_ipv6_addresses,
                      fake_domains=fake_domains,
                      no_such_names=no_such_names,
                      listen_ipv6=args.ipv6,
                      disable_ipv4=args.disable_ipv4)
    # endregion

# endregion
