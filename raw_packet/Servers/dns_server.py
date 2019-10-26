# region Description
"""
test_dns_server.py: DNS server in Raw sockets
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawSniff, RawDNS
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, getaddrinfo, AF_INET, AF_INET6, gaierror
from subprocess import run
from typing import List, Union, Dict
from re import match
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Class Raw DNS server
class RawDnsServer:

    # region Set properties
    base: Base = Base()
    sniff: RawSniff = RawSniff()
    dns: RawDNS = RawDNS()

    rawSocket: socket = socket(AF_PACKET, SOCK_RAW)

    port: int = 53

    network_interface: Union[None, str] = None
    your_mac_address: Union[None, str] = None
    your_ip_address: Union[None, str] = None
    your_ipv6_addresses: Union[None, str] = None

    target_mac_address: Union[None, str] = None
    target_ipv4_address: Union[None, str] = None
    target_ipv6_address: Union[None, str] = None

    fake_answers: bool = False
    fake_domains_regexp: List[str] = list()
    fake_addresses: Union[None, Dict[int, List[Union[None, str]]]] = dict()
    no_such_domains: List[str] = list()
    success_domains: List[str] = list()

    DNS_QUERY_TYPES: List[int] = list()
    A_DNS_QUERY: int = 1
    AAAA_DNS_QUERY: int = 28
    # endregion

    # region Init
    def __init__(self):
        # Iptables drop output ICMP and ICMPv6 destination-unreachable packets
        run('iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP', shell=True)
        run('ip6tables -I OUTPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j DROP', shell=True)
    # endregion

    # region DNS integer query type to string
    @staticmethod
    def _int_type_to_str_type(query_type: int = 1) -> str:
        if query_type == RawDnsServer.A_DNS_QUERY:
            return 'A'
        elif query_type == RawDnsServer.AAAA_DNS_QUERY:
            return 'AAAA'
        else:
            return 'Unknown DNS type'
    # endregion

    # region Get first IPv4 or IPv6 address of domain
    @staticmethod
    def _get_domain_address(query_name: str, query_type: int = 1) -> Union[List[str], None]:
        
        # region Check DNS query type and set proto
        if query_type == RawDnsServer.AAAA_DNS_QUERY:
            proto: int = AF_INET6
        elif query_type == RawDnsServer.A_DNS_QUERY:
            proto: int = AF_INET
        else:
            return None
        # endregion
        
        # region Resolve query name
        try:
            # Get list of addresses
            addresses = getaddrinfo(query_name, None, proto)
            # Return first address from list
            return [addresses[0][4][0]]
        except gaierror:
            # Could not resolve name
            return None
        # endregion

    # endregion

    # region DNS reply function
    def _reply(self, request: Dict) -> None:
        try:

            # region This request is DNS query
            assert 'DNS' in request.keys(), 'This is not DNS request!'

            for query in request['DNS']['queries']:

                # region Local variables
                assert ('IPv4' in request.keys() or 'IPv6' in request.keys()), 'Not found Network layer protocol!'
                ip_src: Union[None, str] = None
                ip_dst: Union[None, str] = None
                if 'IPv4' in request.keys():
                    ip_src: Union[None, str] = request['IPv4']['destination-ip']
                    ip_dst: Union[None, str] = request['IPv4']['source-ip']
                if 'IPv6' in request.keys():
                    ip_src: Union[None, str] = request['IPv6']['destination-ip']
                    ip_dst: Union[None, str] = request['IPv6']['source-ip']
                answers: List[Dict[str, Union[int, str]]] = list()
                addresses: Union[None, str, List[str]] = None
                # endregion

                # region Check query type
                assert query['type'] in self.DNS_QUERY_TYPES, 'Bad DNS query type!'
                # endregion

                # region Check query name
                if query['name'].endswith('.'):
                    query['name']: str = query['name'][:-1]
                # endregion

                # region Script arguments condition check

                # region Variable fake_answers is True
                if self.fake_answers:
                    addresses = self.fake_addresses[query['type']]
                # endregion

                # region Variable fake_answers is False
                else:

                    # region Query name in no_such_domains list
                    if query['name'] in self.no_such_domains:
                        addresses = ['no such name']
                    # endregion

                    # region DNS query name in fake domains regexp list
                    for fake_domain_regexp in self.fake_domains_regexp:

                        if match(fake_domain_regexp, query['name']):

                            # Fake address is set
                            if query['type'] in self.fake_addresses.keys():
                                if len(self.fake_addresses[query['type']]) > 0:
                                    addresses = self.fake_addresses[query['type']]
                                    break

                            # Fake address is NOT set
                            else:
                                addresses = self._get_domain_address(query['name'], query['type'])
                    # endregion

                    # region DNS query name NOT in fake domains regexp list
                    if addresses is None:
                        addresses = self._get_domain_address(query['name'], query['type'])
                    # endregion

                # endregion

                # endregion

                # region Answer addresses is set

                assert addresses is not None, 'Addresses in DNS answer is None!'

                # region Create answer list
                dns_answer_flags = 0x8080

                for address in addresses:
                    if address == 'no such name':
                        dns_answer_flags = 0x8183
                        answers = list()
                        break
                    else:
                        answers.append({'name': query['name'],
                                        'type': query['type'],
                                        'class': query['class'],
                                        'ttl': 65535,
                                        'address': address})

                # endregion

                # region Make dns answer packet
                dns_answer_packet: Union[None, bytes] = self.dns.make_response_packet(
                    ethernet_src_mac=request['Ethernet']['destination'],
                    ethernet_dst_mac=request['Ethernet']['source'],
                    ip_src=ip_src,
                    ip_dst=ip_dst,
                    udp_src_port=request['UDP']['destination-port'],
                    udp_dst_port=request['UDP']['source-port'],
                    transaction_id=request['DNS']['transaction-id'],
                    flags=dns_answer_flags,
                    queries=[query],
                    answers_address=answers)
                # endregion

                # region Send DNS answer packet
                if dns_answer_packet is not None:
                    self.rawSocket.send(dns_answer_packet)
                # endregion

                # region Print info message
                if query['name'] in self.success_domains:
                    self.base.print_success('DNS query from: ', ip_dst, ' to ', ip_src, ' type: ',
                                            self._int_type_to_str_type(query['type']), ' domain: ', query['name'],
                                            ' answer: ', (', '.join(addresses)))
                else:
                    self.base.print_info('DNS query from: ', ip_dst, ' to ', ip_src, ' type: ',
                                         self._int_type_to_str_type(query['type']), ' domain: ', query['name'],
                                         ' answer: ', (', '.join(addresses)))
                # endregion

                # endregion

            # endregion

        except AssertionError:
            pass
    # endregion

    # region Start DNS listener
    def listen(self,
               listen_network_interface: str = 'eth0',
               listen_port: int = 53,
               target_mac_address: Union[None, str] = None,
               target_ipv4_address: Union[None, str] = None,
               target_ipv6_address: Union[None, str] = None,
               fake_answers: bool = False,
               fake_ipv4_addresses: List[str] = [],
               fake_ipv6_addresses: List[str] = [],
               fake_domains_regexp: List[str] = [],
               no_such_domains: List[str] = [],
               listen_ipv6: bool = False,
               disable_ipv4: bool = False,
               success_domains: List[str] = []) -> None:
        try:
            # region Set success domains
            self.success_domains = success_domains
            # endregion

            # region Set fake answers
            self.fake_answers = fake_answers
            # endregion

            # region Set DNS_QUERY_TYPES
            if listen_ipv6:
                if disable_ipv4:
                    self.DNS_QUERY_TYPES = [RawDnsServer.AAAA_DNS_QUERY]
                else:
                    self.DNS_QUERY_TYPES = [RawDnsServer.A_DNS_QUERY, RawDnsServer.AAAA_DNS_QUERY]
            else:
                self.DNS_QUERY_TYPES = [RawDnsServer.A_DNS_QUERY]
            # endregion

            # region Set listen network interface
            self.network_interface = listen_network_interface
            # endregion

            # region Set listen UDP port
            if listen_port != 53:
                assert 0 < listen_port < 65536, 'Bad value in "listen_port": ' + \
                                                self.base.error_text(str(listen_port)) + \
                                                ' listen UDP port must be in range: ' + \
                                                self.base.info_text('1 - 65535')
                self.port = listen_port
            # endregion

            # region Get your MAC, IP and IPv6 addresses
            self.your_mac_address = self.base.get_interface_mac_address(self.network_interface)
            self.your_ip_address = self.base.get_interface_ip_address(self.network_interface)
            if listen_ipv6:
                self.your_ipv6_addresses = self.base.get_interface_ipv6_link_address(self.network_interface)
            # endregion

            # region Bind raw socket
            self.rawSocket.bind((self.network_interface, 0))
            # endregion

            # region Set fake addresses
            if len(fake_ipv4_addresses) > 0:
                self.fake_addresses[RawDnsServer.A_DNS_QUERY] = fake_ipv4_addresses
            else:
                if not disable_ipv4:
                    self.fake_addresses[RawDnsServer.A_DNS_QUERY] = [self.your_ip_address]

            if len(fake_ipv6_addresses) > 0:
                self.fake_addresses[RawDnsServer.AAAA_DNS_QUERY] = fake_ipv6_addresses
                if disable_ipv4:
                    self.DNS_QUERY_TYPES = [RawDnsServer.AAAA_DNS_QUERY]
                else:
                    self.DNS_QUERY_TYPES = [RawDnsServer.A_DNS_QUERY, RawDnsServer.AAAA_DNS_QUERY]
            else:
                if self.fake_answers:
                    if listen_ipv6:
                        self.fake_addresses[RawDnsServer.AAAA_DNS_QUERY] = [self.your_ipv6_addresses]
            # endregion

            # region Set fake domains and 'no such domains' lists
            self.fake_domains_regexp = fake_domains_regexp
            self.no_such_domains = no_such_domains
            # endregion

            # region Check target MAC address
            if target_mac_address is not None:
                assert self.base.mac_address_validation(target_mac_address), \
                    'Bad target MAC address: ' + self.base.error_text(target_mac_address) + \
                    ' example MAC address: ' + self.base.info_text('01:23:45:67:89:0a')
                self.target_mac_address = target_mac_address
            # endregion

            # region Check target IPv4 address
            if target_ipv4_address is not None:
                assert self.base.ip_address_validation(target_ipv4_address), \
                    'Bad target IPv4 address: ' + self.base.error_text(target_ipv4_address) + \
                    ' example IPv4 address: ' + self.base.info_text('192.168.1.1')
                self.target_ipv4_address = target_ipv4_address
            # endregion

            # region Check target IPv6 address
            if target_ipv6_address is not None:
                assert self.base.ipv6_address_validation(target_ipv6_address), \
                    'Bad target IPv6 address: ' + self.base.error_text(target_ipv6_address) + \
                    ' example IPv6 address: ' + self.base.info_text('fd00::1')
                self.target_ipv6_address = target_ipv6_address
            # endregion

            # region Sniffing DNS requests

            # region Set network filter
            network_filters = {}

            if self.network_interface != 'lo':
                if target_mac_address is not None:
                    network_filters['Ethernet'] = {'source': target_mac_address}
                else:
                    network_filters['Ethernet'] = {'not-source': self.your_mac_address}
                if self.target_ipv4_address is not None:
                    network_filters['IPv4'] = {'source-ip': self.target_ipv4_address}
                if self.target_ipv6_address is not None:
                    network_filters['IPv6'] = {'source-ip': self.target_ipv6_address}
                network_filters['IPv4'] = {'not-source-ip': '127.0.0.1'}
                network_filters['IPv6'] = {'not-source-ip': '::1'}
                network_filters['UDP'] = {'destination-port': self.port}
            else:
                network_filters['Ethernet'] = {'source': '00:00:00:00:00:00', 'destination': '00:00:00:00:00:00'}
                network_filters['IPv4'] = {'source-ip': '127.0.0.1', 'destination-ip': '127.0.0.1'}
                network_filters['IPv6'] = {'source-ip': '::1', 'destination-ip': '::1'}
                network_filters['UDP'] = {'destination-port': self.port}
            # endregion

            # region Clear fake_answers list
            if not self.fake_answers:
                if len(fake_ipv6_addresses) == 0:
                    del self.fake_addresses[RawDnsServer.AAAA_DNS_QUERY]
                if len(fake_ipv4_addresses) == 0:
                    del self.fake_addresses[RawDnsServer.A_DNS_QUERY]
            # endregion

            # region Start sniffer
            if listen_ipv6:
                if disable_ipv4:
                    self.sniff.start(protocols=['IPv6', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
                else:
                    self.sniff.start(protocols=['IPv4', 'IPv6', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
            else:
                self.sniff.start(protocols=['IPv4', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
            # endregion

            # endregion

        except AssertionError as Error:
            self.base.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion
