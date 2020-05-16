# region Description
"""
dns_server.py: DNS server (dns_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawSniff, RawSend, RawDNS
from socket import getaddrinfo, AF_INET, AF_INET6, gaierror
from subprocess import run
from typing import List, Union, Dict
from re import match
from os.path import isfile, getsize
from json import load, dump
from json.decoder import JSONDecodeError
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


# region class DnsServer
class DnsServer:

    # region Set properties
    _base: Base = Base()
    _utils: Utils = Utils()
    _sniff: RawSniff = RawSniff()
    _dns: RawDNS = RawDNS()

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 
                                          'mac-address': None, 
                                          'ipv6-link-address': None,
                                          'ipv4-address': None}
    _target: Dict[str, Union[None, str]] = {'mac-address': None,
                                            'ipv4-address': None,
                                            'ipv6-address': None}
    _config: Dict[str, Dict[str, Union[bool, str, List[str]]]] = dict()

    _A_DNS_QUERY: int = 1
    _AAAA_DNS_QUERY: int = 28
    _NS_DNS_QUERY: int = 2
    _MX_DNS_QUERY: int = 15

    _log_file_name: Union[None, str] = None
    _log_file_format: Union[None, str] = None
    _quit: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface: str):
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv4-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)

        if self._base.get_platform().startswith('Linux'):
            run('iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP', shell=True)
            run('ip6tables -I OUTPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j DROP', shell=True)
    # endregion

    # region Start DNS Server
    def start(self,
              listen_port: int = 53,
              target_mac_address: Union[None, str] = None,
              target_ipv4_address: Union[None, str] = None,
              target_ipv6_address: Union[None, str] = None,
              fake_answers: bool = False,
              fake_ipv4_addresses: List[str] = [],
              fake_ipv6_addresses: List[str] = [],
              fake_domains_regexp: List[str] = [],
              no_such_domains: List[str] = [],
              listen_ipv6: bool = True,
              disable_ipv4: bool = False,
              success_domains: List[str] = [],
              config_file: Union[None, str] = None,
              log_file_name: str = 'dns_server_log',
              log_file_format: str = 'csv',
              quiet: bool = False) -> None:
        try:

            # region Variables
            self._log_file_name = log_file_name
            self._log_file_format = log_file_format
            self._quit = quiet
            # endregion

            # region Set listen UDP port
            if listen_port != 53:
                self._utils.check_value_in_range(value=listen_port,
                                                 first_value=0,
                                                 last_value=65536,
                                                 parameter_name='listen UDP port')
            # endregion

            # region Check your IPv6 address
            if self._your['ipv6-link-address'] is None:
                self._your['ipv6-link-address'] = self._base.make_ipv6_link_address(self._your['mac-address'])
            # endregion

            # region Check config file
            if config_file is not None:
                assert isfile(config_file), 'Not found config file: ' + self._base.error_text(str(config_file))
                with open(config_file, 'r') as config_file_descriptor:
                    self._config = load(config_file_descriptor)
            # endregion

            # region Set fake ipv4 addresses
            if len(fake_ipv4_addresses) == 0:
                fake_ipv4_addresses = [self._your['ipv4-address']]
            else:
                for _fake_ipv4_address in fake_ipv4_addresses:
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=_fake_ipv4_address,
                                                   is_local_ipv4_address=False,
                                                   parameter_name='fake IPv4 address')
            # endregion

            # region Set fake ipv6 addresses
            if len(fake_ipv6_addresses) == 0:
                fake_ipv6_addresses = [self._your['ipv6-link-address']]
            else:
                for _fake_ipv6_address in fake_ipv6_addresses:
                    self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                                   ipv6_address=_fake_ipv6_address,
                                                   is_local_ipv6_address=False,
                                                   parameter_name='fake IPv6 address',
                                                   check_your_ipv6_address=False)
            # endregion

            # region Set success domains
            for success_domain in success_domains:
                try:
                    self._config[success_domain].update({'success': True})
                except KeyError:
                    self._config[success_domain] = {'success': True}
            # endregion

            # region Set no such domains
            for no_such_domain in no_such_domains:
                try:
                    self._config[no_such_domain].update({'no such domain': True})
                except KeyError:
                    self._config[no_such_domain] = {'no such domain': True}
            # endregion

            # region Set fake domains regexp
            for _fake_domain_regexp in fake_domains_regexp:
                try:
                    self._config[_fake_domain_regexp].update({'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses})
                except KeyError:
                    self._config[_fake_domain_regexp] = {'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses}
            # endregion

            # region Set fake answers
            if fake_answers:
                try:
                    self._config['.*'].update({'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses})
                except KeyError:
                    self._config['.*'] = {'A': fake_ipv4_addresses, 'AAAA': fake_ipv6_addresses}
            # endregion

            # region Check target MAC address
            if target_mac_address is not None:
                self._target['mac-address'] = self._utils.check_mac_address(mac_address=target_mac_address,
                                                                            parameter_name='target MAC address')
            # endregion

            # region Check target IPv4 address
            if target_ipv4_address is not None:
                self._target['ipv4-address'] = \
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=target_ipv4_address,
                                                   is_local_ipv4_address=False,
                                                   parameter_name='target IPv4 address')
            # endregion

            # region Check target IPv6 address
            if target_ipv6_address is not None:
                self._target['ipv6-address'] = \
                    self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                                   ipv6_address=target_ipv6_address,
                                                   is_local_ipv6_address=False,
                                                   parameter_name='target IPv6 address')
            # endregion

            # region Script arguments condition check and print info message
            if not self._quit:

                # region Argument fake_answer is set
                if fake_answers:
                    if not disable_ipv4:
                        self._base.print_info('DNS answer fake IPv4 addresses: [', (', '.join(fake_ipv4_addresses)),
                                              '] for all DNS queries')
                    if len(fake_ipv6_addresses) > 0:
                        self._base.print_info('DNS answer fake IPv6 addresses: [', (', '.join(fake_ipv6_addresses)),
                                              '] for all DNS queries')
                # endregion

                # region Argument fake_answer is NOT set
                else:
                    # region Fake domains list is set
                    if len(fake_domains_regexp) > 0:
                        if len(fake_ipv4_addresses) > 0:
                            self._base.print_info('DNS answer fake IPv4 addresses: [', (', '.join(fake_ipv4_addresses)),
                                                  '] for domains: [', (', '.join(fake_domains_regexp)), ']')
                        if len(fake_ipv6_addresses) > 0:
                            self._base.print_info('DNS answer fake IPv6 addresses: [', (', '.join(fake_ipv6_addresses)),
                                                  '] for domains: [', (', '.join(fake_domains_regexp)), ']')
                    # endregion

                    # region Fake domains list is NOT set
                    else:
                        if fake_ipv4_addresses != [self._your['ipv4-address']]:
                            self._base.print_info('DNS answer fake IPv4 addresses: [', (', '.join(fake_ipv4_addresses)),
                                                  '] for all DNS queries')
                        if fake_ipv6_addresses != [self._your['ipv6-link-address']]:
                            self._base.print_info('DNS answer fake IPv6 addresses: [', (', '.join(fake_ipv6_addresses)),
                                                  '] for all DNS queries')
                    # endregion

                # endregion

                # region Print info message
                self._base.print_info('Waiting for a DNS requests ...')
                # endregion

            # endregion

            # region Sniffing DNS requests

            # region Set network filter
            sniff_filters: Dict = {'UDP': {'destination-port': listen_port}}

            if self._your['network-interface'] != 'lo':
                if self._target['mac-address'] is not None:
                    sniff_filters['Ethernet'] = {'source': self._target['mac-address']}
                else:
                    sniff_filters['Ethernet'] = {'not-source': self._your['mac-address']}

                if self._target['ipv4-address'] is not None:
                    sniff_filters['IPv4'] = {'source-ip': self._target['ipv4-address']}

                if self._target['ipv6-address'] is not None:
                    sniff_filters['IPv6'] = {'source-ip': self._target['ipv6-address']}

                sniff_filters['IPv4'] = {'not-source-ip': '127.0.0.1'}
                sniff_filters['IPv6'] = {'not-source-ip': '::1'}
            else:
                sniff_filters['Ethernet'] = {'source': '00:00:00:00:00:00', 'destination': '00:00:00:00:00:00'}
                sniff_filters['IPv4'] = {'source-ip': '127.0.0.1', 'destination-ip': '127.0.0.1'}
                sniff_filters['IPv6'] = {'source-ip': '::1', 'destination-ip': '::1'}
            # endregion

            # region Start sniffer
            if listen_ipv6:
                if disable_ipv4:
                    self._sniff.start(protocols=['IPv6', 'UDP', 'DNS'],
                                      prn=self._reply,
                                      filters=sniff_filters,
                                      network_interface=self._your['network-interface'],
                                      scapy_filter='ip6 and udp port ' + str(listen_port))
                else:
                    self._sniff.start(protocols=['IPv4', 'IPv6', 'UDP', 'DNS'],
                                      prn=self._reply,
                                      filters=sniff_filters,
                                      network_interface=self._your['network-interface'],
                                      scapy_filter='udp port ' + str(listen_port))
            else:
                self._sniff.start(protocols=['IPv4', 'UDP', 'DNS'],
                                  prn=self._reply,
                                  filters=sniff_filters,
                                  network_interface=self._your['network-interface'],
                                  scapy_filter='udp port ' + str(listen_port))
            # endregion

            # endregion

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)

        except JSONDecodeError:
            self._base.print_error('Could not parse config file: ', config_file, ' invalid json syntax')
            exit(1)

        except KeyboardInterrupt:
            self._base.print_info('Exit ....')
            exit(0)

    # endregion

    # region Write log file
    def _write_to_log(self, from_ip_address: str, to_ip_address: str,
                      query_type: str, query_name: str, answer_address: str):

        if not isfile(self._log_file_name + '.' + self._log_file_format):
            with open(file=self._log_file_name + '.' + self._log_file_format, mode='w') as log_file:
                if self._log_file_format == 'csv':
                    log_file.write('From IP address,To IP address,Query type,Query name,Answer address\n')
                if self._log_file_format == 'xml':
                    log_file.write('<?xml version="1.0" ?>\n<dns_queries>\n</dns_queries>\n')
                if self._log_file_format == 'json':
                    log_file.write('{\n"dns_queries": [\n')

        with open(file=self._log_file_name + '.' + self._log_file_format, mode='r+') as log_file:

            log_file_pointer: int = getsize(self._log_file_name + '.' + self._log_file_format)

            if self._log_file_format == 'csv' or self._log_file_format == 'txt':
                log_file.seek(log_file_pointer)
                log_file.write(from_ip_address + ',' + to_ip_address + ',' +
                               query_type + ',' + query_name + ',' + answer_address + '\n')

            if self._log_file_format == 'json':
                if log_file_pointer > 20:
                    log_file.seek(log_file_pointer - 4, 0)
                    log_file.write(',')
                else:
                    log_file.seek(log_file_pointer)
                dump({'from_ip_address': from_ip_address,
                      'to_ip_address': to_ip_address,
                      'query_type': query_type,
                      'query_name': query_name,
                      'answer_address': answer_address}, log_file, indent=4)
                log_file.write(']\n}\n')

            if self._log_file_format == 'xml':
                log_file.seek(log_file_pointer - 15, 0)
                log_file.write('\t<dns_query>\n' +
                               '\t\t<from_ip_address>' + from_ip_address + '</from_ip_address>\n' +
                               '\t\t<to_ip_address>' + to_ip_address + '</to_ip_address>\n' +
                               '\t\t<query_type>' + query_type + '</query_type>\n' +
                               '\t\t<query_name>' + query_name + '</query_name>\n' +
                               '\t\t<answer_address>' + answer_address + '</answer_address>\n' +
                               '\t</dns_query>\n' +
                               '</dns_queries>\n')
    # endregion

    # region DNS integer query type to string
    @staticmethod
    def _int_type_to_str_type(query_type: int = 1) -> str:
        if query_type == DnsServer._A_DNS_QUERY:
            return 'A'
        elif query_type == DnsServer._AAAA_DNS_QUERY:
            return 'AAAA'
        elif query_type == DnsServer._NS_DNS_QUERY:
            return 'NS'
        elif query_type == DnsServer._MX_DNS_QUERY:
            return 'MX'
        else:
            return 'A'
    # endregion

    # region DNS string query type to integer
    @staticmethod
    def _str_type_to_int_type(query_type: str = 'A') -> int:
        if query_type == 'A':
            return DnsServer._A_DNS_QUERY
        elif query_type == 'AAAA':
            return DnsServer._AAAA_DNS_QUERY
        elif query_type == 'NS':
            return DnsServer._NS_DNS_QUERY
        elif query_type == 'MX':
            return DnsServer._MX_DNS_QUERY
        else:
            return 1
    # endregion

    # region Get first IPv4 or IPv6 address of domain
    @staticmethod
    def _get_domain_address(query_name: str, query_type: int = 1) -> Union[List[str], None]:

        # region Check DNS query type and set proto
        if query_type == DnsServer._AAAA_DNS_QUERY:
            proto: int = AF_INET6
        elif query_type == DnsServer._A_DNS_QUERY:
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
                for fake_domain_regexp in self._config.keys():

                    if match(fake_domain_regexp, query['name']):

                        # region No such domain
                        if 'no such domain' in self._config[fake_domain_regexp].keys():
                            if self._config[fake_domain_regexp]['no such domain']:
                                addresses = ['no such domain']
                                break
                        # endregion

                        # region Success domain
                        if 'success' in self._config[fake_domain_regexp].keys():
                            if self._config[fake_domain_regexp]['success']:
                                success = True
                        # endregion

                        # region Fake addresses is set
                        query_type_string: str = self._int_type_to_str_type(query['type'])
                        if query_type_string in self._config[fake_domain_regexp].keys():
                            if type(self._config[fake_domain_regexp][query_type_string]) is str:
                                if self._config[fake_domain_regexp][query_type_string] == 'my ipv4 address':
                                    addresses = [self._your['ipv4-address']]
                                elif self._config[fake_domain_regexp][query_type_string] == 'my ipv6 address':
                                    addresses = [self._your['ipv6-link-address']]
                                else:
                                    addresses = [self._config[fake_domain_regexp][query_type_string]]
                            if type(self._config[fake_domain_regexp][query_type_string]) is list:
                                addresses = self._config[fake_domain_regexp][query_type_string]
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
                dns_answer_packet: Union[None, bytes] = self._dns.make_response_packet(
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
                    self._raw_send.send_packet(dns_answer_packet)
                # endregion

                # region Print info message
                if success and query['name'] != '':
                    self._base.print_success('DNS query from: ', ip_dst, ' to ', ip_src, ' type: ',
                                             self._int_type_to_str_type(query['type']), ' domain: ', query['name'],
                                             ' answer: ', (', '.join(addresses)))
                if not success and query['name'] != '':
                    self._base.print_info('DNS query from: ', ip_dst, ' to ', ip_src, ' type: ',
                                          self._int_type_to_str_type(query['type']), ' domain: ', query['name'],
                                          ' answer: ', (', '.join(addresses)))
                self._write_to_log(from_ip_address=ip_dst,
                                   to_ip_address=ip_src,
                                   query_type=self._int_type_to_str_type(query['type']),
                                   query_name=query['name'],
                                   answer_address=(' '.join(addresses)))
                # endregion

                # endregion

            # endregion

        except AssertionError:
            pass
    # endregion

# endregion
