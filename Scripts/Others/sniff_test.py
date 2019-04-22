#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
sniff_test.py: Test script for sniffing
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Import
from json import dumps
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Sniff_raw

Base = Base()
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


# region Print packet function
def print_packet(request):
    global Base

    print("\n")

    if 'ARP' in request.keys():
        Base.print_info("ARP packet from: ", request['Ethernet']['source'])

    if 'ICMPv6' in request.keys():
        Base.print_info("ICMPv6 packet from: ", request['Ethernet']['source'])

    if 'DNS' in request.keys():
        Base.print_info("DNS packet from: ", request['Ethernet']['source'])

    if 'DHCP' in request.keys():
        Base.print_info("DHCP packet from: ", request['Ethernet']['source'])

    if 'DHCPv6' in request.keys():
        Base.print_info("DHCPv6 packet from: ", request['Ethernet']['source'])

    print(dumps(request, indent=4))

# endregion


# region Main function
if __name__ == "__main__":

    # region Print info message
    Base.print_info("Available protocols: ", "Ethernet ARP IP IPv6 ICMPv6 UDP DNS DHCP DHCPv6")
    Base.print_info("Start test sniffing ...")
    # endregion

    # region Start sniffer
    sniff = Sniff_raw()
    sniff.start(protocols=['ARP', 'IP', 'IPv6', 'ICMPv6', 'UDP', 'DNS', 'DHCP', 'DHCPv6'], prn=print_packet)
    # endregion

# endregion
