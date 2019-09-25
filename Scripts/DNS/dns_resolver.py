#!/usr/bin/env python
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
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
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

# region Check user and platform
Base = Base()
Base.check_user()
Base.check_platform()
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
                    help='Brute all subdomains containing 1,2,3,4 symbols (example: "a,b,c,e,.... aa,ab,ac,... ")')
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ICMPv6 responses ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
your_ipv4_address = Base.get_netiface_ip_address(current_network_interface)
your_ipv6_global_address = Base.get_netiface_ipv6_glob_address(current_network_interface, False)
# endregion

# region Global variables
target_ipv6_address = None
target_mac_address = None
gateway_ipv6_address = None
gateway_mac_address = None
dns_ipv6_address = None
# endregion

# region Create global raw socket
socket_global = socket(AF_PACKET, SOCK_RAW)
socket_global.bind((current_network_interface, 0))
# endregion

# region General output
if not args.quiet:
    Base.print_info("Network interface: ", current_network_interface)
    Base.print_info("Your MAC address: ", your_mac_address)
    Base.print_info("Your IPv4 address: ", your_ipv4_address)
    if your_ipv6_global_address is not None:
        Base.print_info("Your IPv6 global address: ", your_ipv6_global_address)
# endregion

# region Main function
if __name__ == "__main__":
    pass

# endregion
