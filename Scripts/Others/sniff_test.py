#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
sniff_test.py: Test script for sniffing
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
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
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Print packet function
def print_packet(request):
    global base

    print("\n")

    if '802.11' in request.keys():
        base.print_info("802.11 packet source: ", request['802.11']['source'],
                        " destination: ", request['802.11']['destination'],
                        " BSS ID: ", request['802.11']['bss id'])

    if 'ARP' in request.keys():
        base.print_info("ARP packet from: ", request['Ethernet']['source'])

    if 'ICMPv4' in request.keys():
        base.print_info("ICMPv4 packet from: ",
                        request['IPv4']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'ICMPv6' in request.keys():
        base.print_info("ICMPv6 packet from: ",
                        request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'DNS' in request.keys():

        if 'IPv4' in request.keys():
            base.print_info("DNS packet from: ",
                            request['IPv4']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

        if 'IPv6' in request.keys():
            base.print_info("DNS packet from: ",
                            request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    if 'DHCPv4' in request.keys():
        base.print_info("DHCPv4 packet from: ", request['Ethernet']['source'])

    if 'DHCPv6' in request.keys():
        base.print_info("DHCPv6 packet from: ",
                        request['IPv6']['source-ip'] + " (" + request['Ethernet']['source'] + ")")

    for proto in request.keys():
        if type(request[proto]) is dict:
            for key in request[proto].keys():

                if type(request[proto][key]) is bytes:
                    request[proto][key] = str(request[proto][key])

                if type(request[proto][key]) is dict:
                    for value in request[proto][key].keys():
                        if type(request[proto][key][value]) is bytes:
                            request[proto][key][value] = str(request[proto][key][value])

    print(dumps(request, sort_keys=True, indent=4))

# endregion


# region Main function
if __name__ == "__main__":

    # region Print info message
    base.print_info("Available protocols: ",
                    "Radiotap 802.11 Ethernet ARP IPv4 IPv6 UDP DNS ICMPv4 DHCPv4 ICMPv6 DHCPv4")
    base.print_info("Start test sniffing ...")
    # endregion

    # region Start sniffer
    sniff = RawSniff()
    sniff.start(protocols=['IPv4', 'IPv6', 'UDP', 'DNS', 'ICMPv4'],
                prn=print_packet, filters={'UDP': {'source-port': 53}})
    # sniff.start(protocols=['Radiotap', '802.11'], prn=print_packet,
    #             network_interface='wlan0', filters={'802.11': {'type': 0x88, 'bss id': '70:f1:1c:15:15:b8'}})
    # endregion

# endregion
