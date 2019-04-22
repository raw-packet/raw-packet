#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Ethernet_raw, IPv6_raw, ICMPv6_raw
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, htons
from time import sleep
from random import randint
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


# region class ICMPv6 scanner
class ICMPv6Scan:

    # region Set variables
    base = None
    eth = None
    ipv6 = None
    icmpv6 = None

    rawSocket = None

    network_interface = None
    your_mac_address = None
    your_ipv6_link_address = None

    target_mac_address = None

    results = None
    unique_results = None
    mac_addresses = None

    vendor_list = None

    retry_number = 0
    timeout = 0

    icmpv6_identifier = 0

    router_info = None
    router_search = False
    # endregion

    # region Init
    def __init__(self):
        self.base = Base()
        self.eth = Ethernet_raw()
        self.ipv6 = IPv6_raw()
        self.icmpv6 = ICMPv6_raw()

        self.rawSocket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

        self.results = []
        self.unique_results = []
        self.mac_addresses = []

        self.retry_number = 3
        self.timeout = 0

        self.router_info = {}

        # region Create vendor list
        self.vendor_list = self.base.get_mac_prefixes()
        # endregion

    # endregion

    # region Sniffer
    def sniff(self):
        while True:
            packets = self.rawSocket.recvfrom(2048)

            for packet in packets:

                # Parse Ethernet header
                ethernet_header = packet[0:14]
                ethernet_header_dict = self.eth.parse_header(ethernet_header)

                # Parse Ethernet header
                if ethernet_header_dict is None:
                    break

                # Source MAC address is target mac address
                if not self.router_search:
                    if self.target_mac_address != "33:33:00:00:00:01":
                        if ethernet_header_dict['source'] != self.target_mac_address:
                            break

                # Destination MAC address is your MAC address
                if not self.router_search:
                    if ethernet_header_dict['destination'] != self.your_mac_address:
                        break

                # Check type of ethernet header
                if ethernet_header_dict['type'] != self.ipv6.header_type:
                    break

                # Parse IPv6 header
                ipv6_header = packet[14:14 + self.ipv6.header_length]
                ipv6_header_dict = self.ipv6.parse_header(ipv6_header)

                # Check parse IPv6 header
                if ipv6_header_dict is None:
                    break

                # Check IPv6 next header type
                if ipv6_header_dict['next-header'] != self.icmpv6.packet_type:
                    break

                # Parse ICMPv6 packet
                icmpv6_packet = packet[14 + self.ipv6.header_length:]
                icmpv6_packet_dict = self.icmpv6.parse_packet(icmpv6_packet)

                # Check parse ICMPv6 packet
                if icmpv6_packet_dict is None:
                    break

                if self.router_search:
                    # 134 Type of ICMPv6 Router Advertisement
                    if icmpv6_packet_dict['type'] != 134:
                        break

                    # Save router information
                    self.router_info['router_mac_address'] = ethernet_header_dict['source']
                    self.router_info['router_ipv6_address'] = ipv6_header_dict['source-ip']
                    self.router_info['flags'] = hex(icmpv6_packet_dict['flags'])
                    self.router_info['router-lifetime'] = int(icmpv6_packet_dict['router-lifetime'])
                    self.router_info['reachable-time'] = int(icmpv6_packet_dict['reachable-time'])
                    self.router_info['retrans-timer'] = int(icmpv6_packet_dict['retrans-timer'])

                    for icmpv6_ra_option in icmpv6_packet_dict['options']:
                        if icmpv6_ra_option['type'] == 3:
                            self.router_info['prefix'] = str(icmpv6_ra_option['value']['prefix']) + "/" + \
                                                         str(icmpv6_ra_option['value']['prefix-length'])
                        if icmpv6_ra_option['type'] == 5:
                            self.router_info['mtu'] = int(icmpv6_ra_option['value'], 16)
                        if icmpv6_ra_option['type'] == 25:
                            self.router_info['dns-server'] = str(icmpv6_ra_option['value']['address'])

                    # Search router MAC address prefix in vendor list
                    router_mac_prefix = self.eth.get_mac_prefix(self.router_info['router_mac_address'])

                    for vendor_index in range(len(self.vendor_list)):
                        if router_mac_prefix == self.vendor_list[vendor_index]['prefix']:
                            self.router_info['vendor'] = self.vendor_list[vendor_index]['vendor']

                    # Could not find this prefix in vendor list
                    if 'vendor' not in self.router_info.keys():
                        self.router_info['vendor'] = "Unknown vendor"

                else:
                    # 129 Type of ICMPv6 Echo (ping) reply
                    if icmpv6_packet_dict['type'] != 129:
                        break

                    # Check ICMPv6 Echo (ping) reply identifier
                    if icmpv6_packet_dict['identifier'] == self.icmpv6_identifier:
                        self.results.append({
                            "mac-address": ethernet_header_dict['source'],
                            "ip-address": ipv6_header_dict['source-ip']
                        })
    # endregion

    # region Sender
    def send(self):
        self.your_mac_address = self.base.get_netiface_mac_address(self.network_interface)
        self.your_ipv6_link_address = self.base.get_netiface_ipv6_link_address(self.network_interface)

        send_socket = socket(AF_PACKET, SOCK_RAW)
        send_socket.bind((self.network_interface, 0))

        if self.router_search:
            request = self.icmpv6.make_router_solicit_packet(ethernet_src_mac=self.your_mac_address,
                                                             ipv6_src=self.your_ipv6_link_address)

        else:
            if self.target_mac_address is None:
                self.target_mac_address = "33:33:00:00:00:01"

            request = self.icmpv6.make_echo_request_packet(ethernet_src_mac=self.your_mac_address,
                                                           ethernet_dst_mac=self.target_mac_address,
                                                           ipv6_src=self.your_ipv6_link_address,
                                                           ipv6_dst="ff02::1",
                                                           id=self.icmpv6_identifier)

        for _ in range(self.retry_number):
            send_socket.send(request)
            sleep(0.1)

        send_socket.close()
    # endregion

    # region Scanner
    def scan(self, network_interface, timeout=3, retry=3, target_mac_address=None, check_vendor=True):

        # region Set variables
        self.target_mac_address = target_mac_address
        self.network_interface = network_interface
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        self.icmpv6_identifier = randint(1, 65535)
        # endregion

        # region Run sniffer
        tm = ThreadManager(2)
        tm.add_task(self.sniff)
        # endregion

        # region Run sender
        self.send()
        # endregion

        # region Wait
        sleep(self.timeout)
        # endregion

        # region Unique results
        for index in range(len(self.results)):
            if self.results[index]['mac-address'] not in self.mac_addresses:
                self.unique_results.append(self.results[index])
                self.mac_addresses.append(self.results[index]['mac-address'])
        # endregion

        # region Reset results and mac addresses list
        self.results = []
        self.mac_addresses = []
        # endregion

        # region Get vendors
        for result_index in range(len(self.unique_results)):

            # Get current MAC address prefix
            current_mac_prefix = self.eth.get_mac_prefix(self.unique_results[result_index]['mac-address'])

            # Search this prefix in vendor list
            for vendor_index in range(len(self.vendor_list)):
                if current_mac_prefix == self.vendor_list[vendor_index]['prefix']:
                    self.unique_results[result_index]['vendor'] = self.vendor_list[vendor_index]['vendor']
                    break

            # Could not find this prefix in vendor list
            if 'vendor' not in self.unique_results[result_index].keys():
                self.unique_results[result_index]['vendor'] = "Unknown vendor"

        # endregion

        # region Return results
        return self.unique_results
        # endregion

    # endregion

    # region Search IPv6 router
    def search_router(self, network_interface, timeout=3, retry=3):

        # region Set variables
        self.router_search = True
        self.network_interface = network_interface
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        # endregion

        # region Run sniffer
        tm = ThreadManager(2)
        tm.add_task(self.sniff)
        # endregion

        # region Run sender
        self.send()
        # endregion

        # region Wait
        sleep(self.timeout)
        # endregion

        # region Return results
        return self.router_info
        # endregion

    # endregion

# endregion
