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
from raw_packet.Utils.network import RawDNS, RawSniff
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Scanners.arp_scanner import ArpScan
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
class RawDnsResolver:
    """
    DNS resolver class
    """

    #  DNS packet:
    #
    #  0                 16                 31
    #  +------------------+------------------+
    #  |  Transaction ID  |      Flags       |
    #  +------------------+------------------+
    #  |    Questions     |    Answer RRS    |
    #  +------------------+------------------+
    #  |  Authority RRs   |  Additional RRs  |
    #  +------------------+------------------+
    #  |          Queries ...
    #  +---------------- ...

    # region Set properties

    # region Init Raw-packet classes
    base: Base = Base()
    arp_scan: ArpScan = ArpScan()
    dns: RawDNS = RawDNS()
    # endregion

    # region Variables
    domain: str = ''
    subdomains: List[str] = list()
    available_characters: List[str] = list(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
                                            'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                                            'u', 'v', 'w', 'x', 'y', 'z', '-'])
    results: List[Dict[str, str]] = list()
    # endregion

    # endregion

    # region Init
    def __init__(self, network_interface: str = 'eth0', quiet: bool = False) -> None:
        """
        Init class DnsResolver
        :param network_interface: Network interface (example: eth0)
        :param quiet: Quiet mode on if True, quiet mode off if False (default: False)
        """

        # Set network interface for sending DNS queries
        self.network_interface: str = network_interface

        # Set quiet mode
        self.quiet: bool = quiet

        # Get MAC, IPv4 and IPv6 addresses for network interface
        self.your_mac_address: str = self.base.get_interface_mac_address(self.network_interface)
        self.your_ipv4_address: str = self.base.get_interface_ip_address(self.network_interface)
        self.your_ipv6_address: str = self.base.get_interface_ipv6_link_address(self.network_interface, False)
    # endregion

    # region Parse DNS packet function
    def _parse_packet(self, response: Dict[str, Union[int, str, Dict[str, Union[int, str]]]]) -> None:
        """
        Parse DNS answers
        :param response: DNS answer dictionary
        :return: None
        """
        try:
            if 'DNS' in response.keys():
                assert len(response['DNS']['answers']) != 0, 'Length of DNS answers is null!'
                for answer in response['DNS']['answers']:
                    assert self.domain in answer['name'], 'Not found target domain in DNS answer!'

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

        except AssertionError:
            pass
    # endregion

    # region Sniff DNS packets function
    def _sniff_packets(self,
                       destination_mac_address: str,
                       destination_ipv4_address: str,
                       destination_ipv6_address: str,
                       source_port: int = 53) -> None:
        """
        Sniff DNS answers
        :param destination_mac_address: Destination MAC address in DNS answer (most likely this is MAC address on your network interface)
        :param destination_ipv4_address: Destination IPv4 address in DNS answer (most likely this is IPv4 address on your network interface)
        :param destination_ipv6_address: Destination IPv6 address in DNS answer (most likely this is IPv6 address on your network interface)
        :param source_port: Source UDP port in DNS answer (default: 53 - default port for DNS servers)
        :return: None
        """
        network_filters: Dict[str, Dict[str, Union[int, str]]] = {
            'Ethernet': {'destination': destination_mac_address},
            'IPv4': {'destination-ip': destination_ipv4_address},
            'IPv6': {'destination-ip': destination_ipv6_address},
            'UDP': {'source-port': source_port}
        }
        sniff: RawSniff = RawSniff()
        sniff.start(protocols=['Ethernet', 'IPv4', 'IPv6', 'UDP', 'DNS'],
                    prn=self._parse_packet, filters=network_filters)
    # endregion

    # region Send DNS queries to IPv4 NS server
    def _send_ipv4_queries(self,
                           source_mac_address: str,
                           source_ipv4_address: str,
                           ns_server_mac_address: str,
                           ns_server_ipv4_address: str,
                           ns_server_port: int,
                           queries: List[Dict[str, Union[int, str]]],
                           send_socket: socket) -> None:
        """
        Send DNS queries to IPv4 DNS servers
        :param source_mac_address: Source MAC address for DNS query (most likely this is MAC address on your network interface)
        :param source_ipv4_address: Source IPv4 address for DNS query (most likely this is IPv4 address on your network interface)
        :param ns_server_mac_address: DNS server MAC address for DNS query
        :param ns_server_ipv4_address: DNS server IPv4 address for DNS query
        :param ns_server_port: DNS server destination UDP port for DNS query (default: 53)
        :param queries: List of DNS queries for sending (example: [{'type': 1, 'class': 1, 'name': 'www.test.com'}])
        :param send_socket: Raw socket for sending DNS queries
        :return: None
        """

        for query in queries:

            # Set source UDP port and DNS transaction ID for sending DNS query
            udp_source_port: int = randint(2049, 65535)
            dns_transaction_id: int = randint(1, 65535)

            send_socket.send(self.dns.make_ipv4_request_packet(ethernet_src_mac=source_mac_address,
                                                               ethernet_dst_mac=ns_server_mac_address,
                                                               ip_src=source_ipv4_address,
                                                               ip_dst=ns_server_ipv4_address,
                                                               udp_src_port=udp_source_port,
                                                               udp_dst_port=ns_server_port,
                                                               transaction_id=dns_transaction_id,
                                                               queries=[query]))
    # endregion

    # region Send IPv6 DNS queries to IPv6 NS server
    def _send_ipv6_queries(self,
                           source_mac_address: str,
                           source_ipv6_address: str,
                           ns_server_mac_address: str,
                           ns_server_ipv6_address: str,
                           ns_server_port: int,
                           queries: List[Dict[str, Union[int, str]]],
                           send_socket: socket) -> None:
        """
        Send DNS queries to IPv6 DNS servers
        :param source_mac_address: Source MAC address for DNS query (most likely this is MAC address on your network interface)
        :param source_ipv6_address: Source IPv6 address for DNS query (most likely this is IPv6 address on your network interface)
        :param ns_server_mac_address: DNS server MAC address for DNS query
        :param ns_server_ipv6_address: DNS server IPv6 address for DNS query
        :param ns_server_port: DNS server destination UDP port for DNS query (default: 53)
        :param queries: List of DNS queries for sending (example: [{'type': 1, 'class': 1, 'name': 'www.test.com'}])
        :param send_socket: Raw socket for sending DNS queries
        :return: None
        """

        for query in queries:

            # Set source UDP port and DNS transaction ID for sending DNS query
            udp_source_port: int = randint(2049, 65535)
            dns_transaction_id: int = randint(1, 65535)

            send_socket.send(self.dns.make_ipv6_request_packet(ethernet_src_mac=source_mac_address,
                                                               ethernet_dst_mac=ns_server_mac_address,
                                                               ip_src=source_ipv6_address,
                                                               ip_dst=ns_server_ipv6_address,
                                                               udp_src_port=udp_source_port,
                                                               udp_dst_port=ns_server_port,
                                                               transaction_id=dns_transaction_id,
                                                               queries=[query]))
    # endregion

    # region Send DNS queries function
    def _send_queries(self,
                      send_socket: socket,
                      source_mac_address: str,
                      source_ipv4_address: str,
                      source_ipv6_address: str,
                      domain: str,
                      ns_servers: List[Dict[str, str]],
                      destination_port: int = 53,
                      max_threats_count: int = 9,
                      subdomains: List[str] = ['www'],
                      queries_type: List[int] = [1, 28],
                      queries_class: List[int] = [1]) -> None:
        """
        Send DNS queries to IPv4/IPv6 DNS servers
        :param send_socket: Raw socket for sending DNS queries
        :param source_mac_address: Source MAC address for DNS query (most likely this is MAC address on your network interface)
        :param source_ipv4_address: Source IPv4 address for DNS query (most likely this is IPv4 address on your network interface)
        :param source_ipv6_address: Source IPv6 address for DNS query (most likely this is IPv6 address on your network interface)
        :param domain: Target domain (example: 'test.com')
        :param ns_servers: List of DNS servers (example: [{'ipv4 address': '8.8.8.8', 'mac address': '01:23:45:67:89:0a'}])
        :param destination_port: UDP destination port (default: 53)
        :param max_threats_count: Maximum threats count (default: 9)
        :param subdomains: List of subdomains (default: ['www'])
        :param queries_type: List of queries type (default: [1, 28]; type 1: A, type 28: AAAA)
        :param queries_class: List of queries class (default: [1]; class 1: IN)
        :return: None
        """

        # DNS query type: 1 (A)
        # DNS query type: 28 (AAAA)
        # DNS query class: 1 (IN)

        # region Init threat manager
        send_threats: ThreadManager = ThreadManager(max_threats_count)
        # endregion

        # region Make DNS queries list
        queries: List[Dict[str, Union[int, str]]] = list()
        for subdomain in subdomains:
            for query_type in queries_type:
                for query_class in queries_class:
                    queries.append({'type': query_type, 'class': query_class, 'name': subdomain + '.' + domain})
        # endregion

        # region Calculate number of DNS queries for one threat
        queries_len: int = len(queries)
        ipv4_ns_servers_len: int = 0
        ipv6_ns_servers_len: int = 0

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
                ns_servers: List[Dict[str, str]] = [{'ipv4 address': '8.8.8.8', 'mac address': '01:23:45:67:89:0a'}],
                domain: str = 'google.com',
                subdomains_list: List[str] = ['www', 'mail', 'ns', 'test'],
                subdomains_file: Union[None, str] = None,
                subdomains_brute: bool = False,
                max_threats_count: int = 10,
                udp_destination_port: int = 53,
                timeout: int = 30) -> List[Dict[str, str]]:
        """
        DNS resolve all subdomains in target domain
        :param ns_servers: List of DNS servers (example: [{'ipv4 address': '8.8.8.8', 'mac address': '01:23:45:67:89:0a'}])
        :param domain: Target domain (example: 'test.com')
        :param subdomains_list: List of subdomains (example: ['www','ns','mail'])
        :param subdomains_file: Name of file with subdomains (default: None)
        :param subdomains_brute: Brute mode on (auto make list with subdomains) if True, Brute mode off if False (default: False)
        :param max_threats_count: Maximum threats count (default: 10)
        :param udp_destination_port: UDP destination port (default: 53)
        :param timeout: Connection after send all DNS queries (default: 30)
        :return: List of dictionary (example: [{'Domain': 'www.test.com', 'IPv4 address': '1.2.3.4', 'IPv6 address': '-'}])
        """

        try:

            # region Set target domain
            assert not (domain == ''), \
                'Target domain is empty, please set target domain in this parameter: ' + self.base.info_text('domain')
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
            raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
            raw_socket.bind((self.network_interface, 0))
            # endregion

            # region Sniff DNS answers
            if not self.quiet:
                self.base.print_info('Start DNS answers sniffer ...')

            threats: ThreadManager = ThreadManager(max_threats_count)

            threats.add_task(self._sniff_packets,
                             self.your_mac_address,
                             self.your_ipv4_address,
                             self.your_ipv6_address,
                             udp_destination_port)
            # endregion

            # region Send DNS queries
            if not self.quiet:
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
            # endregion

            # region Timeout
            if not self.quiet:
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
