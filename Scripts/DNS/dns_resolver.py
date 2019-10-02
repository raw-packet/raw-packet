#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dns_resolver.py: DNS resolver
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
from raw_packet.Utils.network import DNS_raw, Sniff_raw
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, getaddrinfo, AF_INET, AF_INET6, gaierror
from random import randint
from time import sleep
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


# region Parse DNS packet function
def parse_packet(request):
    _base = Base()
    if 'DNS' in request.keys():
        if len(request['DNS']['answers']) > 0:
            for answer in request['DNS']['answers']:
                if answer['type'] == 1:
                    _base.print_success('Domain: ', answer['name'][:-1], " IPv4: ", answer['address'])
                if answer['type'] == 28:
                    _base.print_success('Domain: ', answer['name'][:-1], " IPv6: ", answer['address'])
# endregion


# region Sniff DNS packets function
def sniff_packets(destination_mac_address, destination_ipv4_address, destination_ipv6_address, source_port):
    network_filters = {
        'Ethernet': {'destination': destination_mac_address},
        'IP': {'destination-ip': destination_ipv4_address},
        'IPv6': {'destination-ip': destination_ipv6_address},
        'UDP': {'source-port': source_port}
    }
    sniff = Sniff_raw()
    sniff.start(protocols=['Ethernet', 'IP', 'IPv6', 'UDP', 'DNS'], prn=parse_packet, filters=network_filters)
# endregion


# region Main function
if __name__ == '__main__':

    # region Init raw packet classes
    base = Base()
    dns = DNS_raw()
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
    parser.add_argument('--subdomain_list', type=str,
                        help='Set list of subdomains (example: "admin,registry")', default=None)
    parser.add_argument('--subdomain_file', type=str,
                        help='Set file containing subdomains (example: "/tmp/subdomains.txt")', default=None)
    parser.add_argument('-b', '--subdomain_brute', action='store_true',
                        help='Brute all subdomains containing 1,2,3,4 symbols ' +
                             '(example: "a,b,c,d,.... aa,ab,ac,... ")')
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

        base.print_info('Search Gateways ...')

        gateway_ipv4_address = base.get_netiface_gateway(current_network_interface)
        gateway_ipv4_mac_address = arp_scan.get_mac_address(current_network_interface, gateway_ipv4_address)

        gateway_ipv6_address = base.get_netiface_ipv6_gateway(current_network_interface, False)
        gateway_ipv6_mac_address = 'ff:ff:ff:ff:ff:ff'
        # endregion

        # region Variables
        subdomains = list()
        ns_servers = list()
        available_characters = list(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                     'w', 'x', 'y', 'z', '-'])
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

        # region Parse argument subdomain

        # Parse subdomain list from argument
        if args.subdomain_list is not None:
            for subdomain in str(args.subdomain_list).replace(' ', '').split(','):
                subdomains.append(subdomain)

        else:

            # Read file with subdomain list
            if args.subdomain_file is not None:
                assert isfile(args.subdomain_file), \
                    'File with subdomain list:' + base.error_text(args.subdomain_file) + ' not found!'

                with open(args.subdomain_file) as subdomain_file:
                    for subdomain in subdomain_file:
                        subdomains.append(subdomain)

            # Make list of subdomains for brute
            else:
                if args.subdomain_brute:
                    for character1 in available_characters:
                        subdomains.append(character1)
                        for character2 in available_characters:
                            subdomains.append(character1 + character2)
                            for character3 in available_characters:
                                subdomains.append(character1 + character2 + character3)

        # Check length of subdomain list
        assert len(subdomains) != 0, \
            'List containing subdomains is empty, please set any of this parameters: ' \
            + base.info_text('--subdomain_list') + ' or ' \
            + base.info_text('--subdomain_file') + ' or ' \
            + base.info_text('--subdomain_brute')
        # endregion

        # region Make queries list
        queries = list()
        for subdomain in subdomains:
            # DNS query type: 1 (A), class: 1 (IN)
            queries.append({'type': 1, 'class': 1, 'name': subdomain + '.' + args.domain})
            # DNS query type: 28 (AAAA), class: 1 (IN)
            queries.append({'type': 28, 'class': 1, 'name': subdomain + '.' + args.domain})
        # endregion

        # region Create raw socket
        raw_socket = socket(AF_PACKET, SOCK_RAW)
        raw_socket.bind((current_network_interface, 0))
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
            # if len(ipv4_ns_servers) > 0:
            #     base.print_info('NS server IPv4 address: ', str(','.join(ipv4_ns_servers))[:-1])
            # if len(ipv6_ns_servers) > 0:
            #     base.print_info('NS server IPv6 address: ', str(','.join(ipv6_ns_servers))[:-1])
            base.print_info('Length of subdomain list: ', str(len(subdomains)))
        # endregion

        # region Sniff DNS answers
        base.print_info("Start DNS answers sniffer ...")
        tm = ThreadManager(2)
        tm.add_task(sniff_packets, your_mac_address, your_ipv4_address, your_ipv6_address, args.port)
        # end

        # region Send DNS queries
        for query in queries:

            udp_source_port = randint(2049, 65535)
            dns_transaction_id = randint(1, 65535)

            for ns_server in ns_servers:

                if 'ipv4 address' in ns_server.keys():
                    raw_socket.send(dns.make_request_packet(src_mac=your_mac_address,
                                                            dst_mac=ns_server['mac address'],
                                                            src_ip=your_ipv4_address,
                                                            dst_ip=ns_server['ipv4 address'],
                                                            src_port=udp_source_port,
                                                            dst_port=args.port,
                                                            tid=dns_transaction_id,
                                                            queries=[query]))

                if 'ipv6 address' in ns_server.keys():
                    raw_socket.send(dns.make_request_packet(src_mac=your_mac_address,
                                                            dst_mac=ns_server['mac address'],
                                                            src_ip=your_ipv6_address,
                                                            dst_ip=ns_server['ipv6 address'],
                                                            src_port=udp_source_port,
                                                            dst_port=args.port,
                                                            tid=dns_transaction_id,
                                                            queries=[query]))
        # endregion

        sleep(30)

    except AssertionError as Error:
        base.print_error(Error.args[0])

        if Error.args[0].startswith('Could not resolve IPv4/IPv6 address for name'):
            exit(1)

        if Error.args[0].startswith('Could not parse IPv4/IPv6 address'):
            exit(2)

        if Error.args[0].startswith('List containing NS server addresses is empty'):
            exit(3)

        if Error.args[0].startswith('File with subdomain list'):
            exit(4)

        if Error.args[0].startswith('List containing subdomains is empty'):
            exit(5)

    except KeyboardInterrupt:
        base.print_info('Exit ...')
        exit(0)

# endregion
