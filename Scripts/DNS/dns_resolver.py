#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dns_resolver.py: DNS resolver script
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath, isfile
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Senders.dns_resolver import DnsResolver
from raw_packet.Scanners.arp_scanner import ArpScan
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import getaddrinfo, AF_INET, AF_INET6, gaierror
from csv import DictWriter
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Main function
if __name__ == '__main__':

    # region Init raw packet classes
    base = Base()
    arp_scan = ArpScan()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform()
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='DNS resolver')

    parser.add_argument('-i', '--interface', help='Set interface name for send DNS request packets', default=None)

    parser.add_argument('-s', '--nsservers_name', type=str,
                        help='NS servers name (example: "ns1.test.com,ns2.test.com")', default=None)
    parser.add_argument('-n', '--nsservers_ip', type=str,
                        help='NS servers IP (example: "8.8.8.8,2001:4860:4860::8888")', default=None)
    parser.add_argument('-p', '--port', type=int,
                        help='Set UDP port for listen DNS request packets (default: 53)', default=53)

    parser.add_argument('-d', '--domain', type=str, required=True, help='Set target domain name (example: test.com)')
    parser.add_argument('--subdomains_list', type=str,
                        help='Set list of subdomains (example: "admin,registry")', default=None)
    parser.add_argument('--subdomains_file', type=str,
                        help='Set file containing subdomains (example: "/tmp/subdomains.txt")', default=None)
    parser.add_argument('-b', '--subdomains_brute', action='store_true',
                        help='Brute all subdomains containing 1,2,3,4 symbols ' +
                             '(example: "a,b,c,d,.... aa,ab,ac,... ")')

    parser.add_argument('-t', '--max_threats', type=int, help='Maximum threats count (default: 10)', default=10)
    parser.add_argument('-f', '--format', type=str,
                        help='Set file format for save results: csv, xml, json (default: csv)', default='csv')
    parser.add_argument('--timeout', type=int, help='Set timeout seconds (default: 10)', default=10)
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

    args = parser.parse_args()
    # endregion

    try:

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for send and sniff DNS packets ...')
        current_network_interface = base.netiface_selection(args.interface)

        your_mac_address = base.get_netiface_mac_address(current_network_interface)
        your_ipv4_address = base.get_netiface_ip_address(current_network_interface)
        your_ipv4_network = base.get_netiface_net(current_network_interface)
        your_ipv6_address = base.get_netiface_ipv6_link_address(current_network_interface, False)

        base.print_info('Find IPv4 and IPv6 gateway on network interface: ', current_network_interface, ' .... ')

        gateway_ipv4_address = base.get_netiface_gateway(current_network_interface)
        gateway_ipv4_mac_address = arp_scan.get_mac_address(current_network_interface, gateway_ipv4_address)

        gateway_ipv6_address = base.get_netiface_ipv6_gateway(current_network_interface, False)
        gateway_ipv6_mac_address = 'ff:ff:ff:ff:ff:ff'
        # endregion

        # region Init DnsResolver class
        dns_resolver = DnsResolver(
            network_interface=current_network_interface,
            quiet=args.quiet
        )
        # endregion

        # region Variables
        subdomains = list()
        ns_servers = list()
        # endregion

        # region Parse arguments nsservers

        # region Parse nsservers_name
        if args.nsservers_name is not None:
            for name in str(args.nsservers_name).replace(' ', '').split(','):
                ns_server_ipv4_addresses = None
                ns_server_ipv6_addresses = None
                uniq_ipv4_addresses = list()
                uniq_ipv6_addresses = list()

                try:
                    ns_server_ipv4_addresses = getaddrinfo(name, None, AF_INET)
                    for address in ns_server_ipv4_addresses:
                        ipv4_address = str(address[4][0])
                        if ipv4_address not in uniq_ipv4_addresses:
                            uniq_ipv4_addresses.append(ipv4_address)
                            if base.ip_address_in_network(ipv4_address, your_ipv4_network):
                                ns_servers.append({
                                    'ipv4 address': ipv4_address,
                                    'mac address': arp_scan.get_mac_address(current_network_interface, ipv4_address)
                                })
                            else:
                                ns_servers.append({
                                    'ipv4 address': ipv4_address,
                                    'mac address': gateway_ipv4_mac_address
                                })
                except gaierror:
                    base.print_warning('Could not resolve IPv4 address for name: ', name)

                # Not work

                # try:
                #     ns_server_ipv6_addresses = getaddrinfo(name, None, AF_INET6)
                #     if ns_server_ipv6_addresses is not None:
                #         for address in ns_server_ipv6_addresses:
                #             ipv6_address = str(address[4][0])
                #             if ipv6_address not in uniq_ipv6_addresses:
                #                 uniq_ipv6_addresses.append(ipv6_address)
                #                 ns_servers.append({
                #                     'ipv6': ipv6_address,
                #                     'mac': gateway_ipv4_mac_address
                #                 })
                #
                # except gaierror:
                #     base.print_warning('Could not resolve IPv6 address for name: ', name)

                assert not (ns_server_ipv4_addresses is None and ns_server_ipv6_addresses is None), \
                    'Could not resolve IPv4/IPv6 address for name: ' + base.error_text(name)
        # endregion

        # region Parse nsservers_ip
        if args.nsservers_ip is not None:
            for ip_address in str(args.nsservers_ip).replace(' ', '').split(','):

                assert (base.ip_address_validation(ip_address) or base.ipv6_address_validation(ip_address)), \
                    'Could not parse IPv4/IPv6 address: ' + base.error_text(ip_address)

                if base.ip_address_validation(ip_address):
                    if base.ip_address_in_network(ip_address, your_ipv4_network):
                        ns_servers.append({
                            'ipv4 address': ip_address,
                            'mac address': arp_scan.get_mac_address(current_network_interface, ip_address)
                        })
                    else:
                        ns_servers.append({
                            'ipv4 address': ip_address,
                            'mac address': gateway_ipv4_mac_address
                        })

                # Not work

                # if base.ipv6_address_validation(ip_address):
                #     ipv6_ns_servers.add(ip_address)

        # endregion

        # region Check length of NS servers
        assert not (len(ns_servers) == 0), \
            'List containing NS server addresses is empty, please set any of this parameters: ' \
            + base.info_text('--nsservers_ip') + ' or ' \
            + base.info_text('--nsservers_name')
        # endregion

        # endregion

        # region Parse arguments with subdomains

        # region Parse subdomains list from argument
        if args.subdomains_list is not None:
            for subdomain in str(args.subdomains_list).replace(' ', '').split(','):
                subdomains.append(subdomain)
        # endregion

        # region Check file with subdomains list
        if args.subdomains_file is not None:
            assert isfile(args.subdomains_file), \
                'File with subdomains list:' + base.error_text(args.subdomains_file) + ' not found!'
        # endregion

        # region Check arguments with subdomains
        assert not (args.subdomains_list is None and args.subdomains_file is None and not args.subdomains_brute), \
            'List containing subdomains is empty, please set any of this parameters: ' \
            + base.info_text('--subdomain_list') + ' or ' \
            + base.info_text('--subdomain_file') + ' or ' \
            + base.info_text('--subdomain_brute')
        # endregion

        # endregion

        # region General output
        if not args.quiet:

            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('Your IPv4 address: ', your_ipv4_address)

            if your_ipv6_address is not None:
                base.print_info('Your IPv6 address: ', your_ipv6_address)

            base.print_info('IPv4 Gateway address: ', gateway_ipv4_address)
            base.print_info('IPv4 Gateway MAC address: ', gateway_ipv4_mac_address)

            if gateway_ipv6_address is not None:
                base.print_info('IPv6 Gateway address: ', gateway_ipv6_address)
                base.print_info('IPv6 Gateway MAC address: ', gateway_ipv6_mac_address)

            base.print_info('Target domain: ', args.domain)
            base.print_info('Length of subdomains list: ', str(len(subdomains)))

            for ns_server in ns_servers:
                if 'ipv4 address' in ns_server.keys():
                    base.print_info('NS server IPv4 address: ', ns_server['ipv4 address'],
                                    ' mac address: ', ns_server['mac address'])
                if 'ipv6 address' in ns_server.keys():
                    base.print_info('NS server IPv6 address: ', ns_server['ipv6 address'],
                                    ' mac address: ', ns_server['mac address'])
        # endregion

        # region Start DNS resolver
        resolve_results = dns_resolver.resolve(ns_servers=ns_servers,
                                               domain=args.domain,
                                               max_threats_count=args.max_threats,
                                               udp_destination_port=args.port,
                                               timeout=args.timeout,
                                               subdomains_list=subdomains,
                                               subdomains_file=args.subdomains_file,
                                               subdomains_brute=args.subdomains_brute)
        # endregion

        # region Save resolve results to file: dns_resolver_results.csv
        results_file_name = 'dns_resolver_results'
        if args.format == 'csv':
            with open(results_file_name + '.csv', 'w') as results_csv_file:
                csv_writer = DictWriter(results_csv_file, fieldnames=['Domain', 'IPv4 address', 'IPv6 address'])
                csv_writer.writeheader()
                for resolve_result in resolve_results:
                    csv_writer.writerow(resolve_result)
        # endregion

    except AssertionError as Error:
        base.print_error(Error.args[0])

        if Error.args[0].startswith('Could not resolve IPv4/IPv6 address for name'):
            exit(1)

        if Error.args[0].startswith('Could not parse IPv4/IPv6 address'):
            exit(2)

        if Error.args[0].startswith('List containing NS server addresses is empty'):
            exit(3)

        if Error.args[0].startswith('File with subdomains list'):
            exit(4)

        if Error.args[0].startswith('List containing subdomains is empty'):
            exit(5)

    except KeyboardInterrupt:
        base.print_info('Exit ...')
        exit(0)

# endregion
