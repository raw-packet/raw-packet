# region Description
"""
dns_server.py: DNS server
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Sniff_raw, DNS_raw
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, getaddrinfo, AF_INET, AF_INET6, gaierror
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


# region Class DNS server
class DnsServer:

    # region Set variables
    base = None
    sniff = None
    dns = None

    rawSocket = None

    network_interface = None
    port = 0
    your_mac_address = None
    your_ip_address = None
    your_ipv6_addresses = None

    target_ip_address = None
    target_ipv6_address = None

    fake_answers = False
    fake_domains = []
    fake_addresses = {}
    no_such_names = []

    DNS_QUERY_TYPES = []
    A_DNS_QUERY = 0
    AAAA_DNS_QUERY = 0
    # endregion

    # region Init
    def __init__(self):
        self.base = Base()
        self.sniff = Sniff_raw()
        self.dns = DNS_raw()

        self.rawSocket = socket(AF_PACKET, SOCK_RAW)

        self.port = 53
        self.A_DNS_QUERY = 1
        self.AAAA_DNS_QUERY = 28
    # endregion

    # region Get first IPv4 or IPv6 address of domain
    @staticmethod
    def _get_domain_address(query_name, query_type=1):

        # Set proto
        if query_type == 28:
            proto = AF_INET6
        else:
            proto = AF_INET

        try:
            # Get list of addresses
            addresses = getaddrinfo(query_name, None, proto)

            # Return first address from list
            return [addresses[0][4][0]]

        except gaierror:

            # Could not resolve name
            return None
    # endregion

    # region DNS reply function
    def _reply(self, request):

        # region This request is DNS query
        if 'DNS' in request.keys():

            for request_query in request['DNS']['queries']:

                # region Get DNS query type
                query_type = request_query['type']
                # endregion

                # region Type of DNS query type: A or AAAA
                if query_type in self.DNS_QUERY_TYPES:

                    try:

                        # region Local variables
                        query_class = request_query['class']
                        answer = []
                        addresses = None
                        # endregion

                        # region Create query list
                        if request_query['name'].endswith("."):
                            query_name = request_query['name'][:-1]
                        else:
                            query_name = request_query['name']

                        query = [{
                            "type": query_type,
                            "class": query_class,
                            "name": query_name
                        }]
                        # endregion

                        # region Script arguments condition check

                        # region Variable fake_answers is True
                        if self.fake_answers:
                            addresses = self.fake_addresses[query_type]
                        # endregion

                        # region Variable fake_answers is False
                        else:

                            # region Fake domains list is set
                            if len(self.fake_domains) > 0:

                                # region Fake domains list is set and DNS query name in fake domains list
                                if query_name in self.fake_domains:

                                    # region A DNS query
                                    if query_type == self.A_DNS_QUERY:

                                        # Fake IPv4 is set
                                        if self.A_DNS_QUERY in self.fake_addresses.keys():
                                            if len(self.fake_addresses[self.A_DNS_QUERY]) > 0:
                                                addresses = self.fake_addresses[self.A_DNS_QUERY]

                                        # Fake IPv4 is NOT set
                                        else:
                                            addresses = self._get_domain_address(query_name, query_type)

                                    # endregion

                                    # region AAAA DNS query
                                    if query_type == self.AAAA_DNS_QUERY:

                                        # Fake IPv6 is set
                                        if self.AAAA_DNS_QUERY in self.fake_addresses.keys():
                                            if len(self.fake_addresses[self.AAAA_DNS_QUERY]) > 0:
                                                addresses = self.fake_addresses[self.AAAA_DNS_QUERY]

                                        # Fake IPv6 is NOT set
                                        else:
                                            addresses = self._get_domain_address(query_name, query_type)

                                    # endregion

                                # endregion

                                # region Fake domains list is set and DNS query name NOT in fake domains list
                                else:
                                    addresses = self._get_domain_address(query_name, query_type)
                                # endregion

                            # endregion

                            # region Fake domains list is NOT set
                            else:

                                # region A DNS query
                                if query_type == self.A_DNS_QUERY:

                                    # Fake IPv4 is set
                                    if self.A_DNS_QUERY in self.fake_addresses.keys():
                                        if len(self.fake_addresses[self.A_DNS_QUERY]) > 0:
                                            addresses = self.fake_addresses[self.A_DNS_QUERY]

                                    # Fake IPv4 is NOT set
                                    else:
                                        addresses = self._get_domain_address(query_name, query_type)

                                # endregion

                                # region AAAA DNS query
                                if query_type == self.AAAA_DNS_QUERY:

                                    # Fake IPv6 is set
                                    if self.AAAA_DNS_QUERY in self.fake_addresses.keys():
                                        if len(self.fake_addresses[self.AAAA_DNS_QUERY]) > 0:
                                            addresses = self.fake_addresses[self.AAAA_DNS_QUERY]

                                    # Fake IPv6 is NOT set
                                    else:
                                        addresses = self._get_domain_address(query_name, query_type)

                                # endregion

                            # endregion

                        # endregion

                        # endregion

                        # region Query name in no_such_names list
                        if query_name in self.no_such_names:
                            addresses = ['no such name']
                        # endregion

                        # region Answer addresses is set

                        if addresses is not None:

                            # region Create answer list
                            dns_answer_flags = 0x8580

                            for address in addresses:
                                if address == 'no such name':
                                    dns_answer_flags = 0x8183
                                    answer = []
                                    break
                                else:
                                    answer.append({"name": query_name,
                                                   "type": query_type,
                                                   "class": query_class,
                                                   "ttl": 0xffff,
                                                   "address": address})

                            # endregion

                            # region Make dns answer packet
                            if 'IP' in request.keys():
                                dns_answer_packet = self.dns.make_response_packet(
                                    src_mac=request['Ethernet']['destination'],
                                    dst_mac=request['Ethernet']['source'],
                                    src_ip=request['IP']['destination-ip'],
                                    dst_ip=request['IP']['source-ip'],
                                    src_port=53,
                                    dst_port=request['UDP']['source-port'],
                                    tid=request['DNS']['transaction-id'],
                                    flags=dns_answer_flags,
                                    queries=query,
                                    answers_address=answer)

                            elif 'IPv6' in request.keys():
                                dns_answer_packet = self.dns.make_response_packet(
                                    src_mac=request['Ethernet']['destination'],
                                    dst_mac=request['Ethernet']['source'],
                                    src_ip=request['IPv6']['destination-ip'],
                                    dst_ip=request['IPv6']['source-ip'],
                                    src_port=53,
                                    dst_port=request['UDP']['source-port'],
                                    tid=request['DNS']['transaction-id'],
                                    flags=dns_answer_flags,
                                    queries=query,
                                    answers_address=answer)

                            else:
                                dns_answer_packet = None
                            # endregion

                            # region Send DNS answer packet
                            if dns_answer_packet is not None:
                                self.rawSocket.send(dns_answer_packet)
                            # endregion

                            # region Print info message
                            if 'IP' in request.keys():
                                if query_type == 1:
                                    self.base.print_info("DNS query from: ", request['IP']['source-ip'],
                                                         " to ", request['IP']['destination-ip'], " type: ", "A",
                                                         " domain: ", query_name, " answer: ", (", ".join(addresses)))
                                if query_type == 28:
                                    self.base.print_info("DNS query from: ", request['IP']['source-ip'],
                                                         " to ", request['IP']['destination-ip'], " type: ", "AAAA",
                                                         " domain: ", query_name, " answer: ", (", ".join(addresses)))

                            if 'IPv6' in request.keys():
                                if query_type == 1:
                                    self.base.print_info("DNS query from: ", request['IPv6']['source-ip'],
                                                         " to ", request['IPv6']['destination-ip'], " type: ", "A",
                                                         " domain: ", query_name, " answer: ", (", ".join(addresses)))
                                if query_type == 28:
                                    self.base.print_info("DNS query from: ", request['IPv6']['source-ip'],
                                                         " to ", request['IPv6']['destination-ip'], " type: ", "AAAA",
                                                         " domain: ", query_name, " answer: ", (", ".join(addresses)))
                            # endregion

                        # endregion

                    except:
                        pass
                # endregion

        # endregion

    # endregion

    # region Start server
    def listen(self, listen_network_interface, listen_port=53, target_mac_address=None,
               target_ip_address=None, target_ipv6_address=None, fake_answers=False,
               fake_ip_addresses=[], fake_ipv6_addresses=[], fake_domains=[],
               no_such_names=[], listen_ipv6=False, disable_ipv4=False):

        # region Set fake answers
        self.fake_answers = fake_answers
        # endregion

        # region Set DNS_QUERY_TYPES
        if listen_ipv6:
            if disable_ipv4:
                self.DNS_QUERY_TYPES = [28]
            else:
                self.DNS_QUERY_TYPES = [1, 28]
        else:
            self.DNS_QUERY_TYPES = [1]
        # endregion

        # region Set listen network interface
        self.network_interface = listen_network_interface
        # endregion

        # region Set listen UDP port
        if listen_port != 53:
            if 0 < listen_port < 65535:
                self.port = listen_port
            else:
                self.base.print_error("Bad value in `listen_port`: ", str(listen_port),
                                      "; listen UDP port must be in range: ", "1 - 65534")
                exit(1)
        # endregion

        # region Get your MAC, IP and IPv6 addresses
        self.your_mac_address = self.base.get_netiface_mac_address(self.network_interface)
        if self.your_mac_address is None:
            self.base.print_error("Network interface: ", self.network_interface, " do not have MAC address!")
            exit(1)

        self.your_ip_address = self.base.get_netiface_ip_address(self.network_interface)
        if self.your_ip_address is None:
            self.base.print_error("Network interface: ", self.network_interface, " do not have IP address!")
            exit(1)

        if listen_ipv6:
            self.your_ipv6_addresses = self.base.get_netiface_ipv6_link_address(self.network_interface)
            if len(self.your_ipv6_addresses) == 0:
                self.base.print_error("Network interface: ", self.network_interface,
                                      " do not have IPv6 link local address!")
                exit(1)
            else:
                self.fake_addresses[self.AAAA_DNS_QUERY] = [self.your_ipv6_addresses]
        else:
            self.fake_addresses[self.AAAA_DNS_QUERY] = None
        # endregion

        # region Bind raw socket
        self.rawSocket.bind((self.network_interface, 0))
        # endregion

        # region Set fake addresses
        if len(fake_ip_addresses) > 0:
            self.fake_addresses[self.A_DNS_QUERY] = fake_ip_addresses
        else:
            if not disable_ipv4:
                self.fake_addresses[self.A_DNS_QUERY] = [self.your_ip_address]

        if len(fake_ipv6_addresses) > 0:
            self.fake_addresses[self.AAAA_DNS_QUERY] = fake_ipv6_addresses
            if disable_ipv4:
                self.DNS_QUERY_TYPES = [self.AAAA_DNS_QUERY]
            else:
                self.DNS_QUERY_TYPES = [self.A_DNS_QUERY, self.AAAA_DNS_QUERY]
        else:
            if self.fake_answers:
                if listen_ipv6:
                    self.fake_addresses[self.AAAA_DNS_QUERY] = [self.your_ipv6_addresses]
        # endregion

        # region Set fake domains and "no such names" lists
        self.fake_domains = fake_domains
        self.no_such_names = no_such_names
        # endregion

        # region Check target IPv4 address
        if target_ip_address is not None:
            if not self.base.ip_address_validation(target_ip_address):
                self.base.print_error("Bad target IPv4 address: ", target_ip_address)
                exit(1)
            else:
                self.target_ip_address = target_ip_address
        # endregion

        # region Check target IPv6 address
        if target_ipv6_address is not None:
            if not self.base.ipv6_address_validation(target_ipv6_address):
                self.base.print_error("Bad target IPv6 address: ", target_ipv6_address)
                exit(1)
            else:
                self.target_ipv6_address = target_ipv6_address
        # endregion

        # region Sniffing DNS requests

        # region Set network filter
        network_filters = {}

        if target_mac_address is not None:
            network_filters['Ethernet'] = {'source': target_mac_address}
        else:
            network_filters['Ethernet'] = {'not-source': self.your_mac_address}

        if self.target_ip_address is not None:
            network_filters['IP'] = {'source-ip': self.target_ip_address}

        if self.target_ipv6_address is not None:
            network_filters['IPv6'] = {'source-ip': self.target_ipv6_address}

        network_filters['IP'] = {'not-source-ip': '127.0.0.1'}
        network_filters['UDP'] = {'destination-port': self.port}
        # endregion

        # region Clear fake_answers list
        if not self.fake_answers:
            if len(fake_ipv6_addresses) == 0:
                del self.fake_addresses[self.AAAA_DNS_QUERY]
            if len(fake_ip_addresses) == 0:
                del self.fake_addresses[self.A_DNS_QUERY]
        # endregion

        # region Start sniffer
        if listen_ipv6:
            if disable_ipv4:
                self.sniff.start(protocols=['IPv6', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
            else:
                self.sniff.start(protocols=['IP', 'IPv6', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
        else:
            self.sniff.start(protocols=['IP', 'UDP', 'DNS'], prn=self._reply, filters=network_filters)
        # endregion

        # endregion

    # endregion

# endregion
