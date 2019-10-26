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
from os.path import isfile
from json import load
from json.decoder import JSONDecodeError
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
    your_ipv4_address: Union[None, str] = None
    your_ipv6_address: Union[None, str] = None
    config: Dict[str, Dict[str, Union[bool, str, List[str]]]] = dict()

    A_DNS_QUERY: int = 1
    AAAA_DNS_QUERY: int = 28
    NS_DNS_QUERY: int = 2
    MX_DNS_QUERY: int = 15
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
        elif query_type == RawDnsServer.NS_DNS_QUERY:
            return 'NS'
        elif query_type == RawDnsServer.MX_DNS_QUERY:
            return 'MX'
        else:
            return 'A'
    # endregion

    # region DNS string query type to integer
    @staticmethod
    def _str_type_to_int_type(query_type: str = 'A') -> int:
        if query_type == 'A':
            return RawDnsServer.A_DNS_QUERY
        elif query_type == 'AAAA':
            return RawDnsServer.AAAA_DNS_QUERY
        elif query_type == 'NS':
            return RawDnsServer.NS_DNS_QUERY
        elif query_type == 'MX':
            return RawDnsServer.MX_DNS_QUERY
        else:
            return 1
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
                success: bool = False
                # endregion

                # region Check query name
                if query['name'].endswith('.'):
                    query['name']: str = query['name'][:-1]
                # endregion

                # region Check config
                for fake_domain_regexp in self.config.keys():

                    if match(fake_domain_regexp, query['name']):

                        # region No such domain
                        if 'no such domain' in self.config[fake_domain_regexp].keys():
                            if self.config[fake_domain_regexp]['no such domain']:
                                addresses = ['no such domain']
                                break
                        # endregion

                        # region Success domain
                        if 'success' in self.config[fake_domain_regexp].keys():
                            if self.config[fake_domain_regexp]['success']:
                                success = True
                        # endregion

                        # region Fake addresses is set
                        query_type_string: str = self._int_type_to_str_type(query['type'])
                        if query_type_string in self.config[fake_domain_regexp].keys():
                            if type(self.config[fake_domain_regexp][query_type_string]) is str:
                                if self.config[fake_domain_regexp][query_type_string] == 'my ipv4 address':
                                    addresses = [self.your_ipv4_address]
                                elif self.config[fake_domain_regexp][query_type_string] == 'my ipv6 address':
                                    addresses = [self.your_ipv6_address]
                                else:
                                    addresses = [self.config[fake_domain_regexp][query_type_string]]
                            if type(self.config[fake_domain_regexp][query_type_string]) is list:
                                addresses = self.config[fake_domain_regexp][query_type_string]
                            break
                        # endregion

                        # region Fake address is NOT set
                        else:
                            addresses = self._get_domain_address(query['name'], query['type'])
                        # endregion

                # endregion

                # region DNS query name NOT in fake domains regexp list
                if addresses is None:
                    addresses = self._get_domain_address(query['name'], query['type'])
                # endregion

                # endregion

                # region Answer addresses is set

                assert addresses is not None, 'Addresses in DNS answer is None!'

                # region Create answer list
                dns_answer_flags = 0x8080

                for address in addresses:
                    if address == 'no such domain':
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
                if success:
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
               success_domains: List[str] = [],
               config_file: Union[None, str] = None) -> None:
        try:
            # region Set listen UDP port
            if listen_port != 53:
                assert 0 < listen_port < 65536, \
                    'Bad value in "listen_port": ' + self.base.error_text(str(listen_port)) + \
                    ' listen UDP port must be in range: ' + self.base.info_text('1 - 65535')
            # endregion

            # region Get your MAC, IP and IPv6 addresses
            your_mac_address = self.base.get_interface_mac_address(listen_network_interface)
            self.your_ipv4_address = self.base.get_interface_ip_address(listen_network_interface)
            self.your_ipv6_address = self.base.make_ipv6_link_address(your_mac_address)
            if listen_ipv6:
                self.your_ipv6_address = self.base.get_interface_ipv6_link_address(listen_network_interface)
            # endregion

            # region Bind raw socket
            self.rawSocket.bind((listen_network_interface, 0))
            # endregion

            # region Check config file
            if config_file is not None:
                assert isfile(config_file), 'Not found config file: ' + self.base.error_text(str(config_file))
                with open(config_file, 'r') as config_file_descriptor:
                    self.config = load(config_file_descriptor)
            # endregion

            # region Set fake ipv4 addresses
            if len(fake_ipv4_addresses) == 0:
                fake_ipv4_addresses = [self.your_ipv4_address]
            else:
                for fake_ipv4_address in fake_ipv4_addresses:
                    assert self.base.ip_address_validation(fake_ipv4_address), \
                        'Bad fake IPv4 address: ' + self.base.error_text(fake_ipv4_address) + \
                        ' example IPv4 address: ' + self.base.info_text('192.168.1.1')
            # endregion

            # region Set fake ipv6 addresses
            if len(fake_ipv6_addresses) == 0:
                fake_ipv6_addresses = [self.your_ipv6_address]
            else:
                for fake_ipv6_address in fake_ipv6_addresses:
                    assert self.base.ipv6_address_validation(fake_ipv6_address), \
                        'Bad fake IPv6 address: ' + self.base.error_text(fake_ipv6_address) + \
                        ' example IPv6 address: ' + self.base.info_text('fd00::1')
            # endregion

            # region Set success domains
            for success_domain in success_domains:
                try:
                    self.config[success_domain].update({'success': True})
                except KeyError:
                    self.config[success_domain] = {'success': True}
            # endregion

            # region Set no such domains
            for no_such_domain in no_such_domains:
                try:
                    self.config[no_such_domain].update({'no such domain': True})
                except KeyError:
                    self.config[no_such_domain] = {'no such domain': True}
            # endregion

            # region Set fake domains regexp
            for fake_domain_regexp in fake_domains_regexp:
                try:
                    self.config[fake_domain_regexp].update({'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses})
                except KeyError:
                    self.config[fake_domain_regexp] = {'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses}
            # endregion

            # region Set fake answers
            if fake_answers:
                try:
                    self.config['.*'].update({'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses})
                except KeyError:
                    self.config['.*'] = {'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses}
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
            # endregion

            # region Check target IPv6 address
            if target_ipv6_address is not None:
                assert self.base.ipv6_address_validation(target_ipv6_address), \
                    'Bad target IPv6 address: ' + self.base.error_text(target_ipv6_address) + \
                    ' example IPv6 address: ' + self.base.info_text('fd00::1')
            # endregion

            # region Sniffing DNS requests

            # region Set network filter
            network_filters = {}

            if listen_network_interface != 'lo':
                if target_mac_address is not None:
                    network_filters['Ethernet'] = {'source': target_mac_address}
                else:
                    network_filters['Ethernet'] = {'not-source': your_mac_address}
                if target_ipv4_address is not None:
                    network_filters['IPv4'] = {'source-ip': target_ipv4_address}
                if target_ipv6_address is not None:
                    network_filters['IPv6'] = {'source-ip': target_ipv6_address}
                network_filters['IPv4'] = {'not-source-ip': '127.0.0.1'}
                network_filters['IPv6'] = {'not-source-ip': '::1'}
                network_filters['UDP'] = {'destination-port': listen_port}
            else:
                network_filters['Ethernet'] = {'source': '00:00:00:00:00:00', 'destination': '00:00:00:00:00:00'}
                network_filters['IPv4'] = {'source-ip': '127.0.0.1', 'destination-ip': '127.0.0.1'}
                network_filters['IPv6'] = {'source-ip': '::1', 'destination-ip': '::1'}
                network_filters['UDP'] = {'destination-port': listen_port}
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

        except JSONDecodeError:
            self.base.print_error('Could not parse config file: ', config_file, ' invalid json syntax')
            exit(1)
    # endregion

# endregion
