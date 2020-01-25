# region Description
"""
dns_resolver.py: DNS resolver class
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
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
from socket import socket, AF_PACKET, SOCK_RAW, gethostbyname_ex, herror
from random import randint
from time import sleep
from datetime import datetime
from typing import Dict, List, Union
from scapy.all import rdpcap, IP, UDP, DNS
from sys import stdout
from subprocess import Popen, PIPE, STDOUT, run
from os import remove, kill, system
from signal import SIGINT, SIGTERM
import pexpect
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
    uniq_hosts: List[Dict[str, str]] = list()
    uniq_domains: List[str] = list()
    number_of_dns_queries: int = 0
    index_of_dns_query: int = 0
    percent_of_complete: int = 0
    temporary_results_filename: str = '/tmp/dns_resolver_results.txt'
    tshark_process = None
    tshark_pcap_filename: str = '/tmp/dns_answers.pcap'
    tshark_number_of_dns_answers: int = 0
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
        self.your_ipv4_network: str = self.base.get_interface_network(self.network_interface)
        self.your_ipv6_address: str = self.base.get_interface_ipv6_link_address(self.network_interface, False)
    # endregion

    # region Write resolve results to file
    def _save_result(self, result: Dict[str, str]) -> None:
        try:
            self.results.append(result)
            if 'NS' in result.keys():
                self.base.print_success('Domain: ', result['Domain'], ' NS: ', result['NS'])
            else:
                with open(RawDnsResolver.temporary_results_filename, 'a') as temporary_file:
                    temporary_file.write('Domain: ' + result['Domain'] +
                                         ' IPv4 address: ' + result['IPv4 address'] +
                                         ' IPv6 address: ' + result['IPv6 address'] + '\n')
                if result['IPv6 address'] == '-':
                    print(self.base.cSUCCESS + '[' + str(len(self.uniq_hosts)) + '] ' + self.base.cEND +
                          result['Domain'] + ' - ' + result['IPv4 address'])
                else:
                    print(self.base.cSUCCESS + '[' + str(len(self.uniq_hosts)) + '] ' + self.base.cEND +
                          result['Domain'] + ' - ' + result['IPv6 address'])
        except AttributeError:
            pass

        except KeyError:
            pass
    # endregion

    # region Parse DNS packet function
    def _parse_packet(self, packet) -> None:
        """
        Parse DNS answers
        :param packet: DNS packet
        :return: None
        """
        try:
            assert packet.haslayer(IP), 'Is not IPv4 packet!'
            assert packet.haslayer(UDP), 'Is not UDP packet!'
            assert packet.haslayer(DNS), 'Is not DNS packet!'
            assert packet[IP].dst == self.your_ipv4_address, 'Not your destination IPv4 address!'
            assert packet[UDP].sport == 53, 'UDP source port != 53'
            assert packet[DNS].ancount != 0, 'DNS answer is empty!'
            for answer_index in range(packet[DNS].ancount):
                dns_answer = packet[DNS].an[answer_index]
                name: bytes = dns_answer.rrname
                name: str = name.decode('utf-8')[:-1]
                assert self.domain in name, 'Not found target domain in DNS answer!'
                address: str = ''
                if isinstance(dns_answer.rdata, bytes):
                    address: bytes = dns_answer.rdata
                    address: str = address.decode('utf-8')
                if isinstance(dns_answer.rdata, str):
                    address: str = dns_answer.rdata
                match_host = next((host for host in self.uniq_hosts if host['name'] == name
                                   and host['address'] == address), None)
                if match_host is None:
                    self.uniq_hosts.append({'name': name, 'address': address})

                    if dns_answer.type == 2:
                        self._save_result({'Domain': name,
                                           'NS': address})
                    if dns_answer.type == 1:
                        self._save_result({'Domain': name,
                                           'IPv4 address': address,
                                           'IPv6 address': '-'})
                    if dns_answer.type == 28:
                        self._save_result({'Domain': name,
                                           'IPv4 address': '-',
                                           'IPv6 address': address})

        except AssertionError:
            pass

        except UnicodeDecodeError:
            pass
    # endregion

    # region Start tshark
    def _sniff_start(self,
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
        while self.base.get_process_pid('tshark') != -1:
            kill(self.base.get_process_pid('tshark'), SIGINT)
            sleep(1)
        try:
            remove(RawDnsResolver.tshark_pcap_filename)
        except FileNotFoundError:
            pass
        tshark_command: str = 'tshark -i ' + self.network_interface + \
                              ' -f "ether dst ' + destination_mac_address + \
                              ' and ip dst ' + destination_ipv4_address + \
                              ' and udp src port ' + str(source_port) + \
                              '" -B 65535 -w ' + RawDnsResolver.tshark_pcap_filename + \
                              ' 1>/dev/null 2>&1'
        self.tshark_process = Popen(tshark_command, shell=True)
        sleep(0.5)
        while self.base.get_process_pid('tshark') == -1:
            input(self.base.c_warning + 'Start tshark: ' + self.base.info_text(tshark_command) +
                  ' and press Enter to continue ...')
            sleep(1)
    # endregion

    # region Check tshark
    def _sniff_check(self):
        while True:
            try:
                assert isfile(RawDnsResolver.tshark_pcap_filename), 'Tshark pcap file not found!'
                packets = rdpcap(RawDnsResolver.tshark_pcap_filename)
                for packet in packets:
                    self._parse_packet(packet)
            except ValueError:
                pass
            except AssertionError:
                pass
            sleep(1)
    # endregion

    # region Stop tshark
    def _sniff_stop(self):
        while self.base.get_process_pid('tshark') != -1:
            kill(self.base.get_process_pid('tshark'), SIGTERM)
            sleep(1)
        try:
            packets = rdpcap(RawDnsResolver.tshark_pcap_filename)
            for packet in packets:
                self._parse_packet(packet)
        except ValueError:
            pass
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
            # self.index_of_dns_query += 1
            # current_percent_of_complete = int((self.index_of_dns_query / self.number_of_dns_queries) * 100)
            # if current_percent_of_complete > self.percent_of_complete:
            #     self.percent_of_complete = current_percent_of_complete
            #     stdout.write('\r')
            #     stdout.write(self.base.c_info + 'Domain: ' + self.domain +
            #                  ' resolve percentage: ' + self.base.info_text(str(self.percent_of_complete) + '%'))
            #     stdout.flush()
            #     sleep(0.01)
    # endregion

    # region Send DNS queries to IPv6 NS server
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
            # self.index_of_dns_query += 1
            # current_percent_of_complete = int((self.index_of_dns_query / self.number_of_dns_queries) * 100)
            # if current_percent_of_complete > self.percent_of_complete:
            #     self.percent_of_complete = current_percent_of_complete
            #     stdout.write('\r')
            #     stdout.write(self.base.c_info + 'DNS resolve percentage: ' +
            #                  self.base.info_text(str(self.percent_of_complete) + '%') +
            #                  ' length of results: ' + self.base.info_text(str(len(self.results))))
            #     stdout.flush()
            #     sleep(0.01)
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
        :param ns_servers: List of DNS servers (example: [{'IPv4 address': '8.8.8.8', 'MAC address': '01:23:45:67:89:0a'}])
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
        self.number_of_dns_queries = queries_len * len(ns_servers)
        ipv4_ns_servers_len: int = 0
        ipv6_ns_servers_len: int = 0

        for ns_server in ns_servers:
            if 'IPv4 address' in ns_server.keys():
                ipv4_ns_servers_len += 1
            if 'IPv6 address' in ns_server.keys():
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
            if 'IPv4 address' in ns_server.keys():
                for query_index in range(0, queries_len, queries_len_for_threat):
                    send_threats.add_task(self._send_ipv4_queries,
                                          source_mac_address,
                                          source_ipv4_address,
                                          ns_server['MAC address'],
                                          ns_server['IPv4 address'],
                                          destination_port,
                                          queries[query_index: query_index + queries_len_for_threat],
                                          send_socket)
        # endregion

        # region Send DNS queries to IPv6 NS servers
        if source_ipv6_address is not None:
            for ns_server in ns_servers:
                if 'IPv6 address' in ns_server.keys():
                    for query_index in range(0, queries_len, queries_len_for_threat):
                        send_threats.add_task(self._send_ipv6_queries,
                                              source_mac_address,
                                              source_ipv6_address,
                                              ns_server['MAC address'],
                                              ns_server['IPv6 address'],
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
                ns_servers: List[Dict[str, str]] = [{'IPv4 address': '8.8.8.8', 'MAC address': '01:23:45:67:89:0a'}],
                domain: str = 'google.com',
                subdomains_list: List[str] = ['www', 'mail', 'ns', 'test'],
                subdomains_file: Union[None, str] = None,
                subdomains_brute: bool = False,
                max_threats_count: int = 10,
                udp_destination_port: int = 53,
                timeout: int = 30) -> List[Dict[str, str]]:
        """
        DNS resolve all subdomains in target domain
        :param ns_servers: List of DNS servers (example: [{'IPv4 address': '8.8.8.8', 'MAC address': '01:23:45:67:89:0a'}])
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

            # region Clear results list
            self.index_of_dns_query = 0
            self.results.clear()
            self.uniq_hosts.clear()
            # endregion

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

                for character1 in RawDnsResolver.available_characters:
                    self.subdomains.append(character1)
                    for character2 in RawDnsResolver.available_characters:
                        self.subdomains.append(character1 + character2)
                        for character3 in RawDnsResolver.available_characters:
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

            # region Truncate temporary results file
            temporary_results_file = open(RawDnsResolver.temporary_results_filename, 'r+')
            temporary_results_file.truncate()
            temporary_results_file.close()
            # endregion

            # region Sniff DNS answers
            if not self.quiet:
                self.base.print_info('Start DNS answers sniffer for domain: ', self.domain)

            threats: ThreadManager = ThreadManager(max_threats_count)
            self._sniff_start(self.your_mac_address, self.your_ipv4_address,
                              self.your_ipv6_address, udp_destination_port)
            threats.add_task(self._sniff_check)
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
            self._sniff_stop()
            if not self.quiet:
                if len(self.results) > 0:
                    self.base.print_success('Found ', str(len(self.results)),
                                            ' subdomains and addresses for domain: ', self.domain)
                else:
                    self.base.print_error('Not found subdomains in domain: ', self.domain)
            return self.results
            # endregion

        except AssertionError as Error:
            self.base.print_error(Error.args[0])
            exit(1)

    # endregion

    # region Get NS server of domain
    def get_name_servers(self, 
                         ipv4_gateway_mac: str = '01:23:45:67:89:0a',
                         ipv6_gateway_mac: str = '01:23:45:67:89:0b',
                         domain: str = 'google.com') -> List[Dict[str, str]]:
        """
        Get NS servers of domain
        :param ipv4_gateway_mac: MAC address of IPv4 gateway (example: '01:23:45:67:89:0a')
        :param ipv6_gateway_mac: MAC address of IPv6 gateway (example: '01:23:45:67:89:0b')
        :param domain: Target domain (example: 'google.com')
        :return: List of IP addresses (example: ['216.239.34.10', '216.239.36.10', '216.239.32.10', '216.239.38.10'])
        """

        # region Clear results list
        ns_servers: List[Dict[str, str]] = list()
        self.results.clear()
        # endregion

        # region Start sniffer
        if not self.quiet:
            self.base.print_info('Get NS records of domain: ' + domain + ' ...')
        self._sniff_start(self.your_mac_address, self.your_ipv4_address, self.your_ipv6_address, 53)
        # endregion

        # region Send DNS queries
        raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
        raw_socket.bind((self.network_interface, 0))

        name_servers_addresses = self.base.get_system_name_servers()
        for name_server_address in name_servers_addresses:
            if self.base.ip_address_validation(name_server_address):
                if self.base.ip_address_in_network(name_server_address, self.your_ipv4_network):
                    name_server_mac: str = self.arp_scan.get_mac_address(self.network_interface, name_server_address)
                else:
                    name_server_mac: str = ipv4_gateway_mac
                dns_query = self.dns.make_ns_query(ethernet_src_mac=self.your_mac_address,
                                                   ethernet_dst_mac=name_server_mac,
                                                   ip_src=self.your_ipv4_address,
                                                   ip_dst=name_server_address,
                                                   udp_src_port=randint(2049, 65535),
                                                   udp_dst_port=53,
                                                   transaction_id=randint(1, 65535),
                                                   name=domain)
                raw_socket.send(dns_query)
        # endregion

        # region Resolve NS servers
        sleep(5)
        self._sniff_stop()

        ns_servers_names: List[str] = list()
        ns_servers_addresses: List[str] = list()

        for ns_server in self.results:
            ns_servers_names.append(ns_server['NS'])

        for ns_server_name in ns_servers_names:
            try:
                ns_server_addresses = gethostbyname_ex(ns_server_name)
                if len(ns_server_addresses) > 0:
                    for ns_server_address in ns_server_addresses[2]:
                        if ns_server_address not in ns_servers_addresses:
                            ns_servers_addresses.append(ns_server_address)
            except herror:
                pass

        for ns_server_address in ns_servers_addresses:
            if self.base.ip_address_validation(ns_server_address):
                ns_servers.append({'IPv4 address': ns_server_address,
                                   'MAC address': ipv4_gateway_mac})
            if self.base.ipv6_address_validation(ns_server_address):
                ns_servers.append({'IPv6 address': ns_server_address,
                                   'MAC address': ipv6_gateway_mac})

        return ns_servers
        # endregion

    # endregion

# endregion
