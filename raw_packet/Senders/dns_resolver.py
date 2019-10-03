#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
dns_resolver.py: DNS resolver class
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath, isfile

path.append(dirname(abspath(__file__)))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import DNS_raw, Sniff_raw
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW
from random import randint
from time import sleep
from datetime import datetime
from typing import Dict, List, Union
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


# region class DNS resolver
class DnsResolver:

    # region Set variables
    base = Base()
    arp_scan = ArpScan()
    dns = DNS_raw()

    domain = ""
    subdomains = list()
    available_characters = list(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                                 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                 'w', 'x', 'y', 'z', '-'])
    results = list()
    # endregion

    # region Init
    def __init__(self,
                 network_interface: str,
                 quiet=False):

        self.network_interface = network_interface
        self.quiet = quiet

        self.your_mac_address = self.base.get_netiface_mac_address(self.network_interface)
        self.your_ipv4_address = self.base.get_netiface_ip_address(self.network_interface)
        self.your_ipv6_address = self.base.get_netiface_ipv6_link_address(self.network_interface, False)
    # endregion

    # region Parse DNS packet function
    def _parse_packet(self,
                      request: Dict[str, Union[int, str, Dict]]):
        if 'DNS' in request.keys():

            if len(request['DNS']['answers']) > 0:

                for answer in request['DNS']['answers']:

                    if self.domain in answer['name']:

                        if answer['type'] == 1:
                            self.results.append({
                                'Domain': answer['name'][:-1],
                                'IPv4 address': answer['address'],
                                'IPv6 address': '-'
                            })
                            self.base.print_success('Domain: ', answer['name'][:-1], ' IPv4: ', answer['address'])

                        if answer['type'] == 28:
                            self.results.append({
                                'Domain': answer['name'][:-1],
                                'IPv4 address': '-',
                                'IPv6 address': answer['address']
                            })

                            self.base.print_success('Domain: ', answer['name'][:-1], ' IPv6: ', answer['address'])
    # endregion

    # region Sniff DNS packets function
    def _sniff_packets(self,
                       destination_mac_address: str,
                       destination_ipv4_address: str,
                       destination_ipv6_address: str,
                       source_port=53):

        network_filters = {
            'Ethernet': {'destination': destination_mac_address},
            'IP': {'destination-ip': destination_ipv4_address},
            'IPv6': {'destination-ip': destination_ipv6_address},
            'UDP': {'source-port': source_port}
        }

        sniff = Sniff_raw()

        sniff.start(protocols=['Ethernet', 'IP', 'IPv6', 'UDP', 'DNS'],
                    prn=self._parse_packet,
                    filters=network_filters)
    # endregion

    # region Send DNS queries to IPv4 NS server
    def _send_ipv4_queries(self,
                           source_mac_address: str,
                           source_ipv4_address: str,
                           ns_server_mac_address: str,
                           ns_server_ipv4_address: str,
                           ns_server_port: int,
                           queries: List[Dict[str, Union[int, str]]],
                           send_socket):

        for query in queries:

            udp_source_port = randint(2049, 65535)
            dns_transaction_id = randint(1, 65535)

            send_socket.send(self.dns.make_request_packet(src_mac=source_mac_address,
                                                          dst_mac=ns_server_mac_address,
                                                          src_ip=source_ipv4_address,
                                                          dst_ip=ns_server_ipv4_address,
                                                          src_port=udp_source_port,
                                                          dst_port=ns_server_port,
                                                          tid=dns_transaction_id,
                                                          queries=[query]))
    # endregion

    # region Send IPv6 DNS queries to IPv6 NS server
    def _send_ipv6_queries(self,
                           source_mac_address: str,
                           source_ipv6_address: str,
                           ns_server_mac_address: str,
                           ns_server_ipv6_address: str,
                           ns_server_port: str,
                           queries: List[Dict[str, Union[int, str]]],
                           send_socket):

        for query in queries:

            udp_source_port = randint(2049, 65535)
            dns_transaction_id = randint(1, 65535)

            send_socket.send(self.dns.make_request_packet(src_mac=source_mac_address,
                                                          dst_mac=ns_server_mac_address,
                                                          src_ip=source_ipv6_address,
                                                          dst_ip=ns_server_ipv6_address,
                                                          src_port=udp_source_port,
                                                          dst_port=ns_server_port,
                                                          tid=dns_transaction_id,
                                                          queries=[query]))
    # endregion

    # region Send DNS queries function
    def _send_queries(self,
                      send_socket,
                      source_mac_address: str,
                      source_ipv4_address: str,
                      source_ipv6_address: str,
                      domain: str,
                      ns_servers: List[Dict[str, str]],
                      destination_port=53,
                      max_threats_count=9,
                      subdomains=['www'],
                      queries_type=[1, 28],
                      queries_class=[1]):

        # DNS query type: 1 (A)
        # DNS query type: 28 (AAAA)
        # DNS query class: 1 (IN)

        # region Init threat manager
        send_threats = ThreadManager(max_threats_count)
        # endregion

        # region Make queries list
        queries = list()
        for subdomain in subdomains:
            for query_type in queries_type:
                for query_class in queries_class:
                    queries.append({'type': query_type, 'class': query_class, 'name': subdomain + '.' + domain})
        # endregion

        # region Calculate number of DNS queries for one threat
        queries_len = len(queries)
        ipv4_ns_servers_len = 0
        ipv6_ns_servers_len = 0

        for ns_server in ns_servers:
            if 'ipv4 address' in ns_server.keys():
                ipv4_ns_servers_len += 1
            if 'ipv6 address' in ns_server.keys():
                ipv6_ns_servers_len += 1

        if source_ipv6_address is not None:
            queries_len_for_threat = int((queries_len * (ipv4_ns_servers_len + ipv6_ns_servers_len))
                                         / max_threats_count) + 1
        else:
            queries_len_for_threat = int((queries_len * ipv4_ns_servers_len)
                                         / max_threats_count) + 1
        # endregion

        # region Send DNS queries

        # region Send DNS queries to IPv4 NS servers
        for ns_server in ns_servers:
            if 'ipv4 address' in ns_server.keys():
                for query_index in range(0, queries_len, queries_len_for_threat):
                    send_threats.add_task(self._send_ipv4_queries,
                                          source_mac_address,
                                          source_ipv4_address,
                                          ns_server['mac address'],
                                          ns_server['ipv4 address'],
                                          destination_port,
                                          queries[query_index: query_index + queries_len_for_threat],
                                          send_socket)
        # endregion

        # region Send DNS queries to IPv6 NS servers
        if source_ipv6_address is not None:
            for ns_server in ns_servers:
                if 'ipv6 address' in ns_server.keys():
                    for query_index in range(0, queries_len, queries_len_for_threat):
                        send_threats.add_task(self._send_ipv6_queries,
                                              source_mac_address,
                                              source_ipv6_address,
                                              ns_server['mac address'],
                                              ns_server['ipv6 address'],
                                              destination_port,
                                              queries[query_index: query_index + queries_len_for_threat],
                                              send_socket)
        # endregion

        # endregion

        # region Wait all threats
        send_threats.wait_for_completion()
        # endregion

    # endregion

    # region Main function: resolve
    def resolve(self,
                ns_servers: List[Dict[str, str]],
                domain: str,
                max_threats_count=10,
                udp_destination_port=53,
                timeout=30,
                subdomains_list=[],
                subdomains_file=None,
                subdomains_brute=False) -> List[Dict[str, str]]:
        try:

            # region Set target domain
            self.domain = domain
            # endregion

            # region Subdomains list
            if len(subdomains_list) > 0:
                self.subdomains = subdomains_list
            # endregion

            # region Subdomains file
            if subdomains_file is not None:
                assert isfile(subdomains_file), \
                    'File with subdomain list:' + self.base.error_text(subdomains_file) + ' not found!'
                with open(subdomains_file) as subdomains_file_descriptor:
                    for subdomain in subdomains_file_descriptor.read().splitlines():
                        self.subdomains.append(subdomain)
            # endregion

            # region Subdomains brute
            if subdomains_brute:

                if not self.quiet:
                    self.base.print_info('Make subdomains list for brute .... ')

                for character1 in self.available_characters:
                    self.subdomains.append(character1)
                    for character2 in self.available_characters:
                        self.subdomains.append(character1 + character2)
                        for character3 in self.available_characters:
                            self.subdomains.append(character1 + character2 + character3)
            # endregion

            # region Check length of subdomains list
            assert len(self.subdomains) != 0, \
                'List containing subdomains is empty, please set any of this parameters: ' \
                + self.base.info_text('subdomain_list') + ' or ' \
                + self.base.info_text('subdomain_file') + ' or ' \
                + self.base.info_text('subdomain_brute')
            # endregion

            # region Create raw socket
            raw_socket = socket(AF_PACKET, SOCK_RAW)
            raw_socket.bind((self.network_interface, 0))
            # endregion

            # region Sniff DNS answers
            if not self.quiet:
                self.base.print_info('Start DNS answers sniffer ...')

            threats = ThreadManager(max_threats_count)

            threats.add_task(self._sniff_packets,
                             self.your_mac_address,
                             self.your_ipv4_address,
                             self.your_ipv6_address,
                             udp_destination_port)
            # endregion

            # region Send DNS queries
            self.base.print_info('Start sending DNS queries, time: ', str(datetime.now()))
            self._send_queries(send_socket=raw_socket,
                               source_mac_address=self.your_mac_address,
                               source_ipv4_address=self.your_ipv4_address,
                               source_ipv6_address=self.your_ipv6_address,
                               domain=domain,
                               ns_servers=ns_servers,
                               destination_port=udp_destination_port,
                               max_threats_count=int(max_threats_count) - 1,
                               subdomains=self.subdomains)
            self.base.print_info('All DNS queries is send, time: ', str(datetime.now()))
            # endregion

            # region Timeout
            self.base.print_info('Wait timeout: ', str(timeout) + ' sec')
            sleep(timeout)
            # endregion

            # region Return results
            return self.results
            # endregion

        except AssertionError as Error:
            self.base.print_error(Error.args[0])
            exit(1)

    # endregion

# endregion
