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
from raw_packet.Utils.network import RawSniff

base: Base = Base()
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


# region Print packet function
def print_packet(request):
    global base

    print("\n")

    if 'ARP' in request.keys():
        base.print_info("ARP packet from: ", request['Ethernet']['source'])

    if 'ICMPv4' in request.keys():
        base.print_info("ICMPv4 packet from: ",
                        request['IPv4']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'ICMPv6' in request.keys():
        base.print_info("ICMPv6 packet from: ",
                        request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'DNS' in request.keys():

        if 'IP' in request.keys():
            base.print_info("DNS packet from: ",
                            request['IP']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

        if 'IPv6' in request.keys():
            base.print_info("DNS packet from: ",
                            request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    # if 'MDNS' in request.keys():
    #
    #     if 'IP' in request.keys():
    #         base.print_info("MDNS packet from: ",
    #                         request['IP']['source-ip'] + " (" + request['Ethernet']['source'] + ")")
    #
    #     if 'IPv6' in request.keys():
    #         base.print_info("MDNS packet from: ",
    #                         request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'DHCP' in request.keys():
        base.print_info("DHCP packet from: ", request['Ethernet']['source'])

    if 'DHCPv6' in request.keys():
        base.print_info("DHCPv6 packet from: ",
                        request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    print(dumps(request, indent=4))

# endregion


# region Main function
if __name__ == "__main__":

    # region Print info message
    base.print_info("Available protocols: ", "Ethernet ARP IPv4 IPv6 UDP DNS ICMPv4")
    base.print_info("Start test sniffing ...")
    # endregion

    # region Start sniffer
    sniff = RawSniff()
    sniff.start(protocols=['IPv4', 'IPv6', 'UDP', 'DNS', 'ICMPv4'],
                prn=print_packet, filters={'UDP': {'source-port': 53}})
    # endregion

# endregion
