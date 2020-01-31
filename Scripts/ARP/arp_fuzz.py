#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_fuzz.py: ARP fuzzing script
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
from struct import pack
from socket import inet_aton
from time import sleep
from typing import Union, List, Dict
from json import dumps
from paramiko import RSAKey, SSHClient, AutoAddPolicy
from pathlib import Path
from os.path import isfile
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


# region Get MAC address of IPv4 gateway over ssh
def get_ipv4_gateway_mac_address_over_ssh(connected_ssh_client: SSHClient,
                                          target_os: str = 'MacOS',
                                          gateway_ipv4_address: str = '192.168.0.254') -> Union[None, str]:
    """
    Get MAC address of IPv4 gateway in target host over SSH
    :param connected_ssh_client: Already connected SSH client
    :param target_os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
    :param gateway_ipv4_address: IPv4 address of gateway
    :return: None if error or MAC address string
    """
    gateway_mac_address: Union[None, str] = None
    try:
        if target_os == 'Windows':
            arp_table_command: str = 'arp -a ' + gateway_ipv4_address + ' | findstr ' + gateway_ipv4_address
        else:
            arp_table_command: str = 'arp -an ' + gateway_ipv4_address

        stdin, stdout, stderr = connected_ssh_client.exec_command(arp_table_command)
        arp_table: bytes = stdout.read()
        arp_table: str = arp_table.decode('utf-8')

        assert 'No route to host' not in arp_table, \
            'No route to host' + base.error_text(args.target_ip)
        assert arp_table != '', \
            'Not found host: ' + base.error_text(gateway_ipv4_address) + \
            ' in ARP table in host: ' + base.error_text(args.target_ip)

        if target_os == 'Windows':
            assert base.windows_mac_address_regex.search(arp_table), \
                'Not found host: ' + base.error_text(gateway_ipv4_address) + \
                ' in ARP table in host: ' + base.error_text(args.target_ip)
            mac_address = base.windows_mac_address_regex.search(arp_table)
            return mac_address.group(1).replace('-', ':').lower()

        else:
            target_arp_table: List[str] = arp_table.split(' ')
            if target_os == 'Linux':
                assert base.mac_address_validation(target_arp_table[3]), \
                    'Invalid MAC address: ' + base.error_text(target_arp_table[3])
            return target_arp_table[3]

    except AssertionError as Error:
        base.print_error(Error.args[0])
        return gateway_mac_address

    except IndexError:
        return gateway_mac_address
# endregion


# region Update ARP table over ssh
def update_ipv4_gateway_mac_address_over_ssh(connected_ssh_client: SSHClient,
                                             target_os: str = 'MacOS',
                                             gateway_ipv4_address: str = '192.168.0.254',
                                             real_gateway_mac_address: str = '12:34:56:78:90:ab') -> bool:
    """
    Update ARP table on target host over SSH after spoofing
    :param connected_ssh_client: Already connected SSH client
    :param target_os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
    :param gateway_ipv4_address: IPv4 address of gateway
    :param real_gateway_mac_address: Real IPv4 gateway MAC address
    :return: True if MAC address is changed or False if error
    """
    connected_ssh_client.exec_command('arp -d ' + gateway_ipv4_address)
    if target_os == 'MacOS' or target_os == 'Linux':
        connected_ssh_client.exec_command('ping -c 1 ' + gateway_ipv4_address)
    else:
        connected_ssh_client.exec_command('ping -n 1 ' + gateway_ipv4_address)
    current_gateway_mac_address = get_ipv4_gateway_mac_address_over_ssh(
        connected_ssh_client=ssh_client,
        target_os=target_os,
        gateway_ipv4_address=gateway_ipv4_address)
    if target_os == 'MacOS':
        real_gateway_mac_address = base.macos_encode_mac_address(real_gateway_mac_address)
    if current_gateway_mac_address == real_gateway_mac_address:
        return True
    else:
        return False
# endregion


# region Check MAC address of IPv4 gateway over ssh
def check_ipv4_gateway_mac_address_over_ssh(connected_ssh_client: SSHClient,
                                            target_os: str = 'MacOS',
                                            gateway_ipv4_address: str = '192.168.0.254',
                                            real_gateway_mac_address: str = '12:34:56:78:90:ab',
                                            test_parameters: Union[None, Dict[str, Dict[str, Union[int, str]]]] = None,
                                            test_parameters_index: int = 0) -> None:
    """
    Check MAC address of IPv4 gateway in target host over SSH
    :param connected_ssh_client: Already connected SSH client
    :param target_os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
    :param gateway_ipv4_address: IPv4 address of gateway
    :param real_gateway_mac_address: Real IPv4 gateway MAC address
    :param test_parameters: Dictionary of tested parameters
    :param test_parameters_index: Index of current test
    :return: None
    """
    current_gateway_mac_address: str = get_ipv4_gateway_mac_address_over_ssh(
        connected_ssh_client=connected_ssh_client,
        target_os=target_os,
        gateway_ipv4_address=gateway_ipv4_address)

    if current_gateway_mac_address is None:
        if test_parameters is not None:
            base.print_warning('index: ', str(test_parameters_index), ' parameters: ', dumps(test_parameters))
            with open('arp_fuzz_disconnect.txt', 'a') as result_file:
                result_file.write('index: ' + str(test_parameters_index) +
                                  ' parameters: ' + dumps(test_parameters) + '\n')
        sleep(5)
        check_ipv4_gateway_mac_address_over_ssh(connected_ssh_client,
                                                target_os,
                                                gateway_ipv4_address,
                                                real_gateway_mac_address,
                                                test_parameters,
                                                test_parameters_index)

    if target_os == 'MacOS':
        real_gateway_mac_address = base.macos_encode_mac_address(real_gateway_mac_address)

    if current_gateway_mac_address == real_gateway_mac_address:
        if test_parameters is not None:
            base.print_info('index: ', str(test_parameters_index), ' gateway: ', current_gateway_mac_address,
                            ' parameters: ', dumps(test_parameters))

    else:
        if test_parameters is not None:
            base.print_success('index: ', str(test_parameters_index), ' gateway: ', current_gateway_mac_address,
                               ' parameters: ', dumps(test_parameters))
            with open('arp_fuzz_success.txt', 'a') as result_file:
                result_file.write('index: ' + str(test_parameters_index) +
                                  ' gateway: ' + current_gateway_mac_address +
                                  ' parameters: ' + dumps(test_parameters) + '\n')

        while True:
            if update_ipv4_gateway_mac_address_over_ssh(connected_ssh_client=connected_ssh_client,
                                                        target_os=target_os,
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
        parser: ArgumentParser = ArgumentParser(description='ARP fuzzing script')
        parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
        parser.add_argument('-T', '--target_ip', help='Set target IP address', required=True)
        parser.add_argument('-t', '--target_mac', help='Set target MAC address', required=True)
        parser.add_argument('-o', '--target_os', help='Set target OS (MacOS, Linux, Windows)', default='MacOS')
        parser.add_argument('-u', '--target_ssh_user', help='Set target user name for ssh', default='root')
        parser.add_argument('-p', '--target_ssh_pass', help='Set target password for ssh', default=None)
        parser.add_argument('-k', '--target_ssh_pkey', help='Set target private key for ssh', default=None)
        parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', required=True)
        parser.add_argument('-g', '--gateway_mac', help='Set gateway IP address', required=True)
        parser.add_argument('-A', '--all_tests', action='store_true', help='Test all fields')
        parser.add_argument('-R', '--only_requests', action='store_true', help='Send only ARP requests')
        parser.add_argument('-B', '--only_broadcast', action='store_true', help='Send only Broadcast packets')
        parser.add_argument('-M', '--only_multicast', action='store_true', help='Send only Multicast packets')
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

        # region SSH client
        private_key: Union[None, RSAKey] = None
        ssh_client: SSHClient = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy)

        if args.target_ssh_pkey is None and args.target_ssh_pass is None:
            default_private_key_file: str = str(Path.home()) + '/.ssh/id_rsa'
            assert isfile(default_private_key_file), \
                'Could not found private SSH key: ' + base.error_text(default_private_key_file)
            private_key = RSAKey.from_private_key_file(default_private_key_file)

        if args.target_ssh_pkey is not None:
            private_key = RSAKey.from_private_key_file(args.target_ssh_pkey)

        assert private_key is not None or args.target_ssh_pass is not None, \
            'Password and private key file for SSH is None!' + \
            ' Please set SSH password: ' + base.info_text('--target_ssh_pass <ssh_password>') + \
            ' or SSH private key file: ' + base.info_text('--target_ssh_pkey <ssh_pkey_path>')

        if args.target_ssh_pass is not None:
            ssh_client.connect(hostname=args.target_ip, username=args.target_ssh_user, password=args.target_ssh_pass)
        if private_key is not None:
            ssh_client.connect(hostname=args.target_ip, username=args.target_ssh_user, pkey=private_key)

        test = get_ipv4_gateway_mac_address_over_ssh(
            connected_ssh_client=ssh_client,
            target_os=args.target_os,
            gateway_ipv4_address=args.gateway_ip)
        # endregion

        # region Variables
        number_of_arp_packets: int = 5
        interval_between_sending_arp_packets: float = 0.2

        default_network_type: int = 0x0806   # ARP protocol
        default_hardware_type: int = 0x0001  # Ethernet
        default_protocol_type: int = 0x0800  # IPv4
        default_hardware_size: int = 0x06    # Length of MAC address
        default_protocol_size: int = 0x04    # Length of IP address
        default_opcode: int = 0x0002         # ARP response

        if args.all_tests:
            # Long list
            test_hardware_types: List[int] = [
                0,  # reserved.	RFC 5494
                1,  # Ethernet.
                2,  # Experimental Ethernet.
                3,  # Amateur Radio AX.25.
                4,  # Proteon ProNET Token Ring.
                5,  # Chaos.
                6,  # IEEE 802.
                7,  # ARCNET.	RFC 1201
                8,  # Hyperchannel.
                9,  # Lanstar.
                10,  # Autonet Short Address.
                11,  # LocalTalk.
                12,  # LocalNet (IBM PCNet or SYTEK LocalNET).
                13,  # Ultra link.
                14,  # SMDS.
                15,  # Frame Relay.
                16,  # ATM, Asynchronous Transmission Mode.
                17,  # HDLC.
                18,  # Fibre Channel.	RFC 4338
                19,  # ATM, Asynchronous Transmission Mode.	RFC 2225
                20,  # Serial Line.
                21,  # ATM, Asynchronous Transmission Mode.
                22,  # MIL-STD-188-220.
                23,  # Metricom.
                24,  # IEEE 1394.1995.
                25,  # MAPOS.
                26,  # Twinaxial.
                27,  # EUI-64.
                28,  # HIPARP.	RFC 2834, RFC 2835
                29,  # IP and ARP over ISO 7816-3.
                30,  # ARPSec.
                31,  # IPsec tunnel.	RFC 3456
                32,  # Infiniband.	RFC 4391
                33,  # CAI, TIA-102 Project 25 Common Air Interface.
                34,  # Wiegand Interface.
                35,  # Pure IP.
                36,  # HW_EXP1	RFC 5494
                256  # HW_EXP2
            ]
        else:
            # Short list
            test_hardware_types: List[int] = [
                1,  # Ethernet.
            ]

        test_protocol_types: List[int] = [
            0x0800  # IPv4
        ]

        test_hardware_sizes: List[int] = [
            0x06  # Length of MAC address
        ]

        test_protocol_sizes: List[int] = [
            0x04  # Length of IP address
        ]

        if args.all_tests:
            # Long list
            test_opcodes: List[int] = [
                0,  # reserved.	RFC 5494
                1,  # Request.	RFC 826, RFC 5227
                2,  # Reply.	RFC 826, RFC 1868, RFC 5227
                3,  # Request Reverse.	RFC 903
                4,  # Reply Reverse.	RFC 903
                5,  # DRARP Request.	RFC 1931
                6,  # DRARP Reply.	RFC 1931
                7,  # DRARP Error.	RFC 1931
                8,  # InARP Request.	RFC 1293
                9,  # InARP Reply.	RFC 1293
                10,  # ARP NAK.	RFC 1577
                11,  # MARS Request.
                12,  # MARS Multi.
                13,  # MARS MServ.
                14,  # MARS Join.
                15,  # MARS Leave.
                16,  # MARS NAK.
                17,  # MARS Unserv.
                18,  # MARS SJoin.
                19,  # MARS SLeave.
                20,  # MARS Grouplist Request.
                21,  # MARS Grouplist Reply.
                22,  # MARS Redirect Map.
                23,  # MAPOS UNARP.	RFC 2176
                24,  # OP_EXP1.	RFC 5494
                25  # OP_EXP2.	RFC 5494
            ]
        elif args.only_requests:
            # Only ARP requests
            test_opcodes: List[int] = [
                1,  # Request.	RFC 826, RFC 5227
            ]
        else:
            # Short list
            test_opcodes: List[int] = [
                1,  # Request.	RFC 826, RFC 5227
                2,  # Reply.	RFC 826, RFC 1868, RFC 5227
            ]

        if args.all_tests:
            # Long list
            sender_mac_addresses: List[str] = [
                your_mac_address,  # Your MAC address
                args.gateway_mac,  # Gateway MAC address
                args.target_mac,  # Target MAC address
                '00:00:00:00:00:00'  # Empty MAC address
            ]
            sender_ip_addresses: List[str] = [
                your_ip_address,  # Your IP address
                args.gateway_ip,  # Gateway IP address
                args.target_ip,  # Target IP address
                '0.0.0.0'  # Empty IP address
            ]
            target_mac_addresses: List[str] = [
                your_mac_address,  # Your MAC address
                args.gateway_mac,  # Gateway MAC address
                args.target_mac,  # Target MAC address
                '00:00:00:00:00:00'  # Empty MAC address
            ]
            target_ip_addresses: List[str] = [
                your_ip_address,  # Your IP address
                args.gateway_ip,  # Gateway IP address
                args.target_ip,  # Target IP address
                '0.0.0.0'  # Empty IP address
            ]
        else:
            # Short list
            sender_mac_addresses: List[str] = [
                your_mac_address,  # Your MAC address
            ]
            sender_ip_addresses: List[str] = [
                args.gateway_ip,  # Gateway IP address
            ]
            target_mac_addresses: List[str] = [
                args.target_mac,  # Target MAC address
                '00:00:00:00:00:00'  # Empty MAC address
            ]
            target_ip_addresses: List[str] = [
                args.target_ip,  # Target IP address
                '0.0.0.0'  # Empty IP address
            ]

        if args.all_tests:
            # Long list
            destination_mac_addresses: List[str] = [
                args.target_mac,  # Target MAC address
                'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
                '33:33:00:00:00:01',  # IPv6 multicast MAC address
                '01:00:5e:00:00:01',  # IPv4 multicast MAC address
            ]
        elif args.only_broadcast:
            # Only Broadcast packets
            destination_mac_addresses: List[str] = [
                'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
            ]
        elif args.only_multicast:
            # Only Multicast packets
            destination_mac_addresses: List[str] = [
                '33:33:00:00:00:01',  # IPv6 multicast MAC address
                '01:00:5e:00:00:01',  # IPv4 multicast MAC address
            ]
        else:
            # Short list
            destination_mac_addresses: List[str] = [
                args.target_mac,  # Target MAC address
                'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
            ]

        source_mac_addresses: List[str] = [
            your_mac_address  # Your MAC address
        ]
        network_types: List[int] = [
            0x0806  # ARP protocol
        ]

        base.print_info('Destination MAC address: ', str(destination_mac_addresses))
        base.print_info('Source MAC address: ', str(source_mac_addresses))
        base.print_info('Network type: ', str(network_types))

        base.print_info('ARP hardware type: ', str(test_hardware_types))
        base.print_info('ARP protocol type: ', str(test_protocol_types))
        base.print_info('ARP hardware size: ', str(test_hardware_sizes))
        base.print_info('ARP protocol size: ', str(test_protocol_sizes))
        base.print_info('ARP opcode: ', str(test_opcodes))
        base.print_info('ARP sender MAC address: ', str(sender_mac_addresses))
        base.print_info('ARP sender IP address: ', str(sender_ip_addresses))
        base.print_info('ARP target MAC address: ', str(target_mac_addresses))
        base.print_info('ARP target IP address: ', str(target_ip_addresses))

        base.print_info('Make all permutations of tested parameters ...')

        tested_parameters: List[Dict[str, Dict[str, Union[int, str]]]] = list()
        for test_hardware_type in test_hardware_types:
            for test_protocol_type in test_protocol_types:
                for test_hardware_size in test_hardware_sizes:
                    for test_protocol_size in test_protocol_sizes:
                        for test_opcode in test_opcodes:
                            for sender_mac_address in sender_mac_addresses:
                                for sender_ip_address in sender_ip_addresses:
                                    for target_mac_address in target_mac_addresses:
                                        for target_ip_address in target_ip_addresses:
                                            for destination_mac_address in destination_mac_addresses:
                                                for source_mac_address in source_mac_addresses:
                                                    for network_type in network_types:
                                                        tested_parameters.append({
                                                            'ARP': {
                                                                'hardware_type': test_hardware_type,
                                                                'protocol_type': test_protocol_type,
                                                                'hardware_size': test_hardware_size,
                                                                'protocol_size': test_protocol_size,
                                                                'opcode': test_opcode,
                                                                'sender_mac_address': sender_mac_address,
                                                                'sender_ip_address': sender_ip_address,
                                                                'target_mac_address': target_mac_address,
                                                                'target_ip_address': target_ip_address,
                                                            },
                                                            'Ethernet': {
                                                                'destination_mac_address': destination_mac_address,
                                                                'source_mac_address': source_mac_address,
                                                                'network_type': network_type
                                                            }
                                                        })
        base.print_info('All permutations are created, length of fuzzing packets: ',
                        str(len(tested_parameters)))
        # endregion

        # region Check ARP
        for index in range(0, len(tested_parameters)):

            sender_mac: bytes = eth.convert_mac(mac_address=tested_parameters[index]['ARP']['sender_mac_address'])
            sender_ip: bytes = inet_aton(tested_parameters[index]['ARP']['sender_ip_address'])
            target_mac: bytes = eth.convert_mac(mac_address=tested_parameters[index]['ARP']['target_mac_address'])
            target_ip: bytes = inet_aton(tested_parameters[index]['ARP']['target_ip_address'])

            arp_packet: bytes = pack('!H', tested_parameters[index]['ARP']['hardware_type'])
            arp_packet += pack('!H', tested_parameters[index]['ARP']['protocol_type'])
            arp_packet += pack('!B', tested_parameters[index]['ARP']['hardware_size'])
            arp_packet += pack('!B', tested_parameters[index]['ARP']['protocol_size'])
            arp_packet += pack('!H', tested_parameters[index]['ARP']['opcode'])

            arp_packet += sender_mac + pack('!' '4s', sender_ip)
            arp_packet += target_mac + pack('!' '4s', target_ip)

            eth_header: bytes = eth.make_header(
                source_mac=tested_parameters[index]['Ethernet']['source_mac_address'],
                destination_mac=tested_parameters[index]['Ethernet']['destination_mac_address'],
                network_type=tested_parameters[index]['Ethernet']['network_type'])

            packet: bytes = eth_header + arp_packet

            for _ in range(number_of_arp_packets):
                raw_socket.send(packet)
                sleep(interval_between_sending_arp_packets)

            check_ipv4_gateway_mac_address_over_ssh(ssh_client,
                                                    args.target_os,
                                                    args.gateway_ip,
                                                    args.gateway_mac,
                                                    tested_parameters[index],
                                                    index)
        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        base.print_error(Error.args[0])
        exit(1)
