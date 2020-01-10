#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawEthernet, RawIPv6, RawICMPv6
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, htons
from time import sleep
from random import randint
from typing import Union, Dict, List
# endregion

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


# region class ICMPv6 scanner
class ICMPv6Scan:

    # region Set variables
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ipv6: RawIPv6 = RawIPv6()
    icmpv6: RawICMPv6 = RawICMPv6()

    raw_socket: socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

    network_interface: Union[None, str] = None
    your_mac_address: Union[None, str] = None
    your_ipv6_link_address: Union[None, str] = None
    target_mac_address: str = '33:33:00:00:00:01'

    results: List[Dict[str, str]] = list()
    unique_results: List[Dict[str, str]] = list()
    mac_addresses: List[str] = list()

    retry_number: int = 3
    timeout: int = 3

    icmpv6_identifier: int = 0

    router_info: Dict[str, Union[int, str]] = dict()
    router_search: bool = False
    # endregion

    # region Sniffer
    def _sniff(self) -> None:
        """
        Sniff ICMPv6 packets
        :return: None
        """
        while True:
            packets = self.raw_socket.recvfrom(2048)
            for packet in packets:
                try:
                    # Parse Ethernet header
                    ethernet_header = packet[0:14]
                    ethernet_header_dict = self.eth.parse_header(packet=ethernet_header)

                    # Parse Ethernet header
                    assert ethernet_header_dict is not None, 'Not Ethernet packet!'

                    # Source MAC address is target mac address
                    if not self.router_search:
                        if self.target_mac_address != '33:33:00:00:00:01':
                            assert ethernet_header_dict['source'] == self.target_mac_address, \
                                'Bad source MAC address!'

                    # Destination MAC address is your MAC address
                    if not self.router_search:
                        assert ethernet_header_dict['destination'] == self.your_mac_address, \
                            'Bad destination MAC address!'

                    # Check type of ethernet header
                    assert ethernet_header_dict['type'] == self.ipv6.header_type, 'Not IPv6 packet!'

                    # Parse IPv6 header
                    ipv6_header = packet[14:14 + self.ipv6.header_length]
                    ipv6_header_dict = self.ipv6.parse_header(ipv6_header)

                    # Check parse IPv6 header
                    assert ipv6_header_dict is not None, 'Could not parse IPv6 packet!'

                    # Check IPv6 next header type
                    assert ipv6_header_dict['next-header'] == self.icmpv6.packet_type, 'Not ICMPv6 packet!'

                    # Parse ICMPv6 packet
                    icmpv6_packet = packet[14 + self.ipv6.header_length:]
                    icmpv6_packet_dict = self.icmpv6.parse_packet(packet=icmpv6_packet)

                    # Check parse ICMPv6 packet
                    assert icmpv6_packet_dict is not None, 'Could not parse ICMPv6 packet!'

                    if self.router_search:
                        # 134 Type of ICMPv6 Router Advertisement
                        assert icmpv6_packet_dict['type'] == 134, 'Not ICMPv6 Router Advertisement packet!'

                        # Save router information
                        self.router_info['router_mac_address'] = ethernet_header_dict['source']
                        self.router_info['router_ipv6_address'] = ipv6_header_dict['source-ip']
                        self.router_info['flags'] = hex(icmpv6_packet_dict['flags'])
                        self.router_info['router-lifetime'] = int(icmpv6_packet_dict['router-lifetime'])
                        self.router_info['reachable-time'] = int(icmpv6_packet_dict['reachable-time'])
                        self.router_info['retrans-timer'] = int(icmpv6_packet_dict['retrans-timer'])

                        for icmpv6_ra_option in icmpv6_packet_dict['options']:
                            if icmpv6_ra_option['type'] == 3:
                                self.router_info['prefix'] = str(icmpv6_ra_option['value']['prefix']) + '/' + \
                                                             str(icmpv6_ra_option['value']['prefix-length'])
                            if icmpv6_ra_option['type'] == 5:
                                self.router_info['mtu'] = int(icmpv6_ra_option['value'], 16)
                            if icmpv6_ra_option['type'] == 25:
                                self.router_info['dns-server'] = str(icmpv6_ra_option['value']['address'])

                        # Search router vendor
                        self.router_info['vendor'] = \
                            self.base.get_vendor_by_mac_address(self.router_info['router_mac_address'])

                    else:
                        # 129 Type of ICMPv6 Echo (ping) reply
                        assert icmpv6_packet_dict['type'] == 129, 'Not ICMPv6 Echo (ping) reply packet!'

                        # Check ICMPv6 Echo (ping) reply identifier
                        if icmpv6_packet_dict['identifier'] == self.icmpv6_identifier:
                            self.results.append({
                                'mac-address': ethernet_header_dict['source'],
                                'ip-address': ipv6_header_dict['source-ip']
                            })
                
                except AssertionError:
                    pass
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ICMPv6 packets
        :return: None
        """
        self.your_mac_address: str = self.base.get_interface_mac_address(self.network_interface)
        self.your_ipv6_link_address: str = self.base.get_interface_ipv6_link_address(self.network_interface)

        send_socket: socket = socket(AF_PACKET, SOCK_RAW)
        send_socket.bind((self.network_interface, 0))

        if self.router_search:
            request: bytes = self.icmpv6.make_router_solicit_packet(ethernet_src_mac=self.your_mac_address,
                                                                    ipv6_src=self.your_ipv6_link_address)

        else:
            request: bytes = self.icmpv6.make_echo_request_packet(ethernet_src_mac=self.your_mac_address,
                                                                  ethernet_dst_mac=self.target_mac_address,
                                                                  ipv6_src=self.your_ipv6_link_address,
                                                                  ipv6_dst='ff02::1',
                                                                  id=self.icmpv6_identifier)

        for _ in range(self.retry_number):
            send_socket.send(request)
            sleep(0.1)

        send_socket.close()
    # endregion

    # region Scanner
    def scan(self, network_interface: str = 'eth0', timeout: int = 3, retry: int = 3,
             target_mac_address: Union[None, str] = None, check_vendor: bool = True,
             exit_on_failure: bool = True) -> List[Dict[str, str]]:
        """
        Find alive IPv6 hosts in local network with echo (ping) request packets
        :param network_interface: Network interface name (example: 'eth0')
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_mac_address: Target MAC address (example: 192.168.0.1)
        :param check_vendor: Check vendor of hosts (default: True)
        :param exit_on_failure: Exit if alive IPv6 hosts in network not found (default: True)
        :return: List of alive hosts in network (example: [{'mac-address': '01:23:45:67:89:0a', 'ip-address': 'fe80::1234:5678:90ab:cdef', 'vendor': 'Apple, Inc.'}])
        """

        # region Clear lists with scan results
        self.results.clear()
        self.unique_results.clear()
        self.mac_addresses.clear()
        # endregion

        # region Set variables
        if target_mac_address is not None:
            self.base.mac_address_validation(mac_address=target_mac_address, exit_on_failure=True)
            self.target_mac_address = target_mac_address
        self.network_interface = network_interface
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        self.icmpv6_identifier = randint(1, 65535)
        # endregion

        # region Run _sniffer
        tm = ThreadManager(2)
        tm.add_task(self._sniff)
        # endregion

        # region Run _sender
        self._send()
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

        # region Get vendors
        if check_vendor:
            for result_index in range(len(self.unique_results)):
                self.unique_results[result_index]['vendor'] = \
                    self.base.get_vendor_by_mac_address(self.unique_results[result_index]['mac-address'])
        # endregion

        # region Return results
        if len(self.unique_results) == 0:
            if exit_on_failure:
                self.base.error_text('Could not found alive IPv6 hosts on interface: ' + self.network_interface)
                exit(1)
        return self.unique_results
        # endregion

    # endregion

    # region Search IPv6 router
    def search_router(self, network_interface: str = 'eth0', timeout: int = 3, retry: int = 3, 
                      exit_on_failure: bool = True) -> Dict[str, Union[int, str]]:
        """
        Search IPv6 router in network
        :param network_interface: Network interface name (example: 'eth0')
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param exit_on_failure: Exit if IPv6 router in network not found (default: True)
        :return: IPv6 router information dictionary (example: {'router_mac_address': '01:23:45:67:89:0a', 'router_ipv6_address': 'fe80::1234:5678:90ab:cdef', 'flags': '0x0', 'router-lifetime': 0, 'reachable-time': 0, 'retrans-timer': 0, 'prefix': 'fd00::/64', 'vendor': 'D-Link International'})
        """

        # region Clear lists with scan results
        self.results.clear()
        self.unique_results.clear()
        self.mac_addresses.clear()
        # endregion

        # region Set variables
        self.router_search = True
        self.network_interface = network_interface
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        # endregion

        # region Run _sniffer
        tm = ThreadManager(2)
        tm.add_task(self._sniff)
        # endregion

        # region Run _sender
        self._send()
        # endregion

        # region Wait
        sleep(self.timeout)
        # endregion

        # region Return IPv6 router information
        if len(self.router_info.keys()) == 0:
            if exit_on_failure:
                self.base.error_text('Could not found IPv6 Router on interface: ' + self.network_interface)
                exit(1)
        return self.router_info
        # endregion

    # endregion

# endregion
