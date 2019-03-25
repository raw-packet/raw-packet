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

# region Add path with Raw-packet modules
from sys import path
from os.path import dirname, abspath

project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"

path.append(utils_path)
# endregion

# region Raw-packet modules
from base import Base
from network import Sniff_raw, DNS_raw
# endregion

# region Import libraries
from ipaddress import IPv4Address
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, getaddrinfo, AF_INET, AF_INET6, gaierror, htons
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

parser.add_argument('--fake_domains', help='Set fake domain or domains, example: --fake_domains "apple.com,google.com"',
                    default=None)
parser.add_argument('--no_such_names', help='Set no such domain or domains, ' +
                                            'example: --no_such_names "apple.com,google.com"', default=None)
parser.add_argument('--fake_ip', help='Set fake IP address or addresses, example: --fake_ip "192.168.0.1,192.168.0.2"',
                    default=None)
parser.add_argument('--fake_ipv6', help='Set fake IPv6 address or addresses, example: --fake_ipv6 "fd00::1,fd00::2"',
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

# region Set global variables

dns = DNS_raw()

destination_port = 0

target_ip_address = None
target_ipv6_address = None

fake_domains = []
no_such_names = []
fake_ip_addresses = []
fake_ipv6_addresses = []
fake_addresses = {}

A_DNS_QUERY = 1
AAAA_DNS_QUERY = 28

if args.ipv6:
    if args.disable_ipv4:
        DNS_QUERY_TYPES = [28]
    else:
        DNS_QUERY_TYPES = [1, 28]
else:
    DNS_QUERY_TYPES = [1]

# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing DNS queries ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
    exit(1)

your_ip_address = Base.get_netiface_ip_address(current_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have IP address!")
    exit(1)

if args.ipv6:
    your_ipv6_addresses = Base.get_netiface_ipv6_link_address(current_network_interface)
    if len(your_ipv6_addresses) == 0:
        if not args.quiet:
            Base.print_warning("Network interface: ", current_network_interface, " do not have IPv6 local address!")
        fake_addresses[28] = None
    else:
        fake_addresses[28] = [your_ipv6_addresses]
else:
    fake_addresses[28] = None

if not args.disable_ipv4:
    fake_addresses[1] = [your_ip_address]
# endregion

# region Create fake domains list
if args.fake_domains is not None:

    # Delete spaces
    fake_domains_string = args.fake_domains.replace(" ", "")

    # Create list
    for domain_name in fake_domains_string.split(","):
        fake_domains.append(domain_name)
# endregion

# region Create no such name list
if args.no_such_names is not None:

    # Delete spaces
    no_such_names_string = args.no_such_names.replace(" ", "")

    # Create list
    for no_such_name in no_such_names_string.split(","):
        no_such_names.append(no_such_name)
        no_such_names.append("www." + no_such_name)
# endregion

# region Create fake ipv4 addresses list
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

    # Set fake IPv4 addresses dictionary
    fake_addresses[1] = fake_ip_addresses

# endregion

# region Create fake ipv6 addresses list
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

    # Set fake IPv6 addresses dictionary
    fake_addresses[28] = fake_ipv6_addresses

    # Rewrite available DNS query types
    if args.disable_ipv4:
        DNS_QUERY_TYPES = [28]
    else:
        DNS_QUERY_TYPES = [1, 28]

# endregion

# region Create raw socket
SOCK = socket(AF_PACKET, SOCK_RAW)
SOCK.bind((current_network_interface, 0))
# endregion

# region Get first and last IP address in your network
first_ip_address = str(IPv4Address(unicode(Base.get_netiface_first_ip(current_network_interface))) - 1)
last_ip_address = str(IPv4Address(unicode(Base.get_netiface_last_ip(current_network_interface))) + 1)
# endregion

# region Check UDP destination port
if 0 < args.port < 65535:
    destination_port = args.port
else:
    Base.print_error("Bad value `-p, --port`: ", str(args.port),
                     "; listen UDP port must be in range: ", "1 - 65534")
    exit(1)
# endregion

# region Check target IPv4
if args.T4 is not None:
    if not Base.ip_address_in_range(args.T4, first_ip_address, last_ip_address):
        Base.print_error("Bad value `--T4`: ", args.T4,
                         "; target IPv4 address must be in range: ", first_ip_address + " - " + last_ip_address)
        exit(1)
    else:
        target_ip_address = args.T4
# endregion

# region Check target IPv6
if args.T6 is not None:
    if not Base.ipv6_address_validation(args.T6):
        Base.print_error("Bad IPv6 address in parameter `--T6`: ", args.T6)
        exit(1)
    else:
        target_ipv6_address = args.T6
# endregion

# region Get first IPv4 or IPv6 address of domain
def get_domain_address(query_name, query_type=1):

    # Set proto
    if query_type == 28:
        proto = AF_INET6
    else:
        proto = AF_INET

    try:
        # Get list of addresses
        addresses = getaddrinfo(query_name, None, proto)

        # Return first address from list
        return [addresses[0][4][0]]

    except gaierror:

        # Could not resolve name
        return None

# endregion


# region DNS reply function
def reply(request):

    # region Define global variables
    global SOCK
    global dns
    global args
    global fake_domains
    global fake_addresses
    global DNS_QUERY_TYPES
    # endregion

    # region This request is DNS query
    if 'DNS' in request.keys():

        for request_query in request['DNS']['queries']:

            # region Get DNS query type
            query_type = request_query['type']
            # endregion

            # region Type of DNS query type: A or AAAA
            if query_type in DNS_QUERY_TYPES:

                try:

                    # region Local variables
                    query_class = request_query['class']
                    answer = []
                    addresses = None
                    # endregion

                    # region Create query list
                    if request_query['name'].endswith("."):
                        query_name = request_query['name'][:-1]
                    else:
                        query_name = request_query['name']

                    query = [{
                        "type": query_type,
                        "class": query_class,
                        "name": query_name
                    }]
                    # endregion

                    # region Script arguments condition check

                    # region Argument fake_answer is set
                    if args.fake_answer:
                        addresses = fake_addresses[query_type]
                    # endregion

                    # region Argument fake_answer is NOT set
                    else:

                        # region Fake domains list is set
                        if len(fake_domains) > 0:

                            # region Fake domains list is set and DNS query name in fake domains list
                            if query_name in fake_domains:

                                # region A DNS query
                                if query_type == 1:

                                    # Fake IPv4 is set
                                    if args.fake_ip is not None:
                                        addresses = fake_addresses[query_type]

                                    # Fake IPv4 is NOT set
                                    else:
                                        addresses = get_domain_address(query_name, query_type)

                                # endregion

                                # region AAAA DNS query
                                if query_type == 28:

                                    # Fake IPv6 is set
                                    if args.fake_ipv6 is not None:
                                        addresses = fake_addresses[query_type]

                                    # Fake IPv6 is NOT set
                                    else:
                                        addresses = get_domain_address(query_name, query_type)

                                # endregion

                            # endregion

                            # region Fake domains list is set and DNS query name NOT in fake domains list
                            else:
                                addresses = get_domain_address(query_name, query_type)
                            # endregion

                        # endregion

                        # region Fake domains list is NOT set
                        else:

                            # region A DNS query
                            if query_type == 1:

                                # Fake IPv4 is set
                                if args.fake_ip is not None:
                                    addresses = fake_addresses[query_type]

                                # Fake IPv4 is NOT set
                                else:
                                    addresses = get_domain_address(query_name, query_type)

                            # endregion

                            # region AAAA DNS query
                            if query_type == 28:

                                # Fake IPv6 is set
                                if args.fake_ipv6 is not None:
                                    addresses = fake_addresses[query_type]

                                # Fake IPv6 is NOT set
                                else:
                                    addresses = get_domain_address(query_name, query_type)

                            # endregion

                        # endregion

                    # endregion

                    # endregion

                    # region Query name in no_such_names list

                    if query_name in no_such_names:
                        addresses = ['no such name']

                    # endregion

                    # region Answer addresses is set

                    if addresses is not None:

                        # region Create answer list
                        dns_answer_flags = 0x8580

                        for address in addresses:
                            if address == 'no such name':
                                dns_answer_flags = 0x8183
                                answer = []
                                break
                            else:
                                answer.append({"name": query_name,
                                               "type": query_type,
                                               "class": query_class,
                                               "ttl": 0xffff,
                                               "address": address})

                        # endregion

                        # region Make dns answer packet
                        if 'IP' in request.keys():
                            dns_answer_packet = dns.make_response_packet(src_mac=request['Ethernet']['destination'],
                                                                         dst_mac=request['Ethernet']['source'],
                                                                         src_ip=request['IP']['destination-ip'],
                                                                         dst_ip=request['IP']['source-ip'],
                                                                         src_port=53,
                                                                         dst_port=request['UDP']['source-port'],
                                                                         tid=request['DNS']['transaction-id'],
                                                                         flags=dns_answer_flags,
                                                                         queries=query,
                                                                         answers_address=answer)
                        elif 'IPv6' in request.keys():
                            dns_answer_packet = dns.make_response_packet(src_mac=request['Ethernet']['destination'],
                                                                         dst_mac=request['Ethernet']['source'],
                                                                         src_ip=request['IPv6']['destination-ip'],
                                                                         dst_ip=request['IPv6']['source-ip'],
                                                                         src_port=53,
                                                                         dst_port=request['UDP']['source-port'],
                                                                         tid=request['DNS']['transaction-id'],
                                                                         flags=dns_answer_flags,
                                                                         queries=query,
                                                                         answers_address=answer)
                        else:
                            dns_answer_packet = None
                        # endregion

                        # region Send DNS answer packet
                        if dns_answer_packet is not None:
                            SOCK.send(dns_answer_packet)
                        # endregion

                        # region Print info message
                        if 'IP' in request.keys():
                            if query_type == 1:
                                Base.print_info("DNS query from: ", request['IP']['source-ip'],
                                                " to ", request['IP']['destination-ip'], " type: ", "A",
                                                " domain: ", query_name, " answer: ", (", ".join(addresses)))
                            if query_type == 28:
                                Base.print_info("DNS query from: ", request['IP']['source-ip'],
                                                " to ", request['IP']['destination-ip'], " type: ", "AAAA",
                                                " domain: ", query_name, " answer: ", (", ".join(addresses)))

                        if 'IPv6' in request.keys():
                            if query_type == 1:
                                Base.print_info("DNS query from: ", request['IPv6']['source-ip'],
                                                " to ", request['IPv6']['destination-ip'], " type: ", "A",
                                                " domain: ", query_name, " answer: ", (", ".join(addresses)))
                            if query_type == 28:
                                Base.print_info("DNS query from: ", request['IPv6']['source-ip'],
                                                " to ", request['IPv6']['destination-ip'], " type: ", "AAAA",
                                                " domain: ", query_name, " answer: ", (", ".join(addresses)))
                        # endregion

                    # endregion

                except:
                    pass
            # endregion

    # endregion

# endregion


# region Main function
if __name__ == "__main__":

    # region Script arguments condition check and print info message
    if not args.quiet:

        # region Argument fake_answer is set
        if args.fake_answer:
            if not args.disable_ipv4:
                Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])), " for all DNS queries")

            if fake_addresses[28] is not None:
                Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])), " for all DNS queries")

        # endregion

        # region Argument fake_answer is NOT set
        else:

            # region Fake domains list is set
            if len(fake_domains) > 0:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])),
                                    " for domain: ", (", ".join(fake_domains)))

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])),
                                    " for domain: ", (", ".join(fake_domains)))

            # endregion

            # region Fake domains list is NOT set
            else:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])),
                                    " for all DNS queries")

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])),
                                    " for all DNS queries")

            # endregion

        # endregion

    # endregion

    # region Sniff network

    # region Print info message
    if not args.quiet:
        Base.print_info("Waiting for a DNS requests ...")
    # endregion

    # region Set network filter
    network_filters = {}

    if args.target_mac is not None:
        network_filters['Ethernet'] = {'source': args.target_mac}
    else:
        network_filters['Ethernet'] = {'not-source': your_mac_address}

    if target_ip_address is not None:
        network_filters['IP'] = {'source-ip': target_ip_address}

    if target_ipv6_address is not None:
        network_filters['IPv6'] = {'source-ip': target_ipv6_address}

    network_filters['IP'] = {'not-source-ip': '127.0.0.1'}
    network_filters['UDP'] = {'destination-port': destination_port}
    # endregion

    # region Start sniffer
    sniff = Sniff_raw()

    if args.ipv6:
        if args.disable_ipv4:
            sniff.start(protocols=['IPv6', 'UDP', 'DNS'], prn=reply, filters=network_filters)
        else:
            sniff.start(protocols=['IP', 'IPv6', 'UDP', 'DNS'], prn=reply, filters=network_filters)
    else:
        sniff.start(protocols=['IP', 'UDP', 'DNS'], prn=reply, filters=network_filters)
    # endregion

    # endregion

# endregion
