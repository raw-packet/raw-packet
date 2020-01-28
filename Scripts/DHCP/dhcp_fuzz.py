#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcp_fuzz.py: DHCPv4 fuzzing script
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
from re import sub
from paramiko import RSAKey, SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError, AuthenticationException
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


tested_index: int = 0
transactions: List[int] = list()


# region Get address of IPv4 gateway over ssh
def get_ipv4_gateway_over_ssh(ssh_user: str = 'root',
                              ssh_password: Union[None, str] = None,
                              ssh_pkey: Union[None, RSAKey] = None,
                              ssh_host: str = '192.168.0.1',
                              os: str = 'MacOS',
                              network_interface: str = 'en0') -> Union[None, str]:
    """
    Get IPv4 gateway address over SSH
    :param ssh_user: SSH Username
    :param ssh_password: SSH Password
    :param ssh_pkey: SSH Private key
    :param ssh_host: SSH Host
    :param os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
    :param network_interface: Network interface
    :return: IPv4 gateway address or None if error
    """
    gateway_ipv4_address: Union[None, str] = None
    try:
        assert not (ssh_password is None and ssh_pkey is None), \
            'SSH password and private key is None'

        ssh_client: SSHClient = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        if ssh_password is not None:
            ssh_client.connect(hostname=ssh_host, username=ssh_user, password=ssh_password)
        if ssh_pkey is not None:
            ssh_client.connect(hostname=ssh_host, username=ssh_user, pkey=ssh_pkey)

        if os == 'MacOS':
            route_table_command: str = 'netstat -nr | grep default | grep ' + network_interface + \
                                       ' | awk \'{print $2}\''
        elif os == 'Linux':
            # route_table_command: str = 'ip route | grep default | grep ' + network_interface + \
            #                            ' | awk \'{print $3}\''
            route_table_command: str = 'route -n | grep UG | grep ' + network_interface + \
                                       ' | awk \'{print $2}\''
        else:
            route_table_command: str = 'ipconfig | findstr /i "Gateway"'

        stdin, stdout, stderr = ssh_client.exec_command(route_table_command)
        route_table_result: str = stdout.read().decode('utf-8')
        route_table_result: List[str] = route_table_result.splitlines()
        route_table_result: str = route_table_result[0]

        if os == 'Windows':
            route_table_result: str = route_table_result.replace(' .', '').replace(' :', '')
            route_table_result: str = sub(r' +', ' ', route_table_result)
            route_table_result: List[str] = route_table_result.split()
            route_table_result: str = route_table_result[2]

        assert base.ip_address_validation(route_table_result), \
            'Bad IPv4 address: ' + base.error_text(route_table_result)
        assert base.ip_address_in_range(route_table_result, first_ip_address, last_ip_address), \
            'Router IPv4 address: ' + base.error_text(route_table_result) + \
            ' not in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
        return route_table_result

    except AssertionError as Error:
        base.print_error(Error.args[0])
        return gateway_ipv4_address

    except IndexError:
        return gateway_ipv4_address

    except NoValidConnectionsError:
        base.print_error('Could not connect to SSH host: ', ssh_host)
        return gateway_ipv4_address

    except AuthenticationException:
        base.print_error('SSH authentication error: ', ssh_user + '@' + ssh_host)
        return gateway_ipv4_address
# endregion


# region Start DHCPv4 client over ssh
def dhclient_over_ssh(ssh_user: str = 'root',
                      ssh_password: Union[None, str] = None,
                      ssh_pkey: Union[None, RSAKey] = None,
                      ssh_host: str = '192.168.0.1',
                      os: str = 'MacOS',
                      network_interface: str = 'en0') -> bool:
    """
    Start DHCPv4 client over ssh
    :param ssh_user: SSH Username
    :param ssh_password: SSH Password
    :param ssh_pkey: SSH Private key
    :param ssh_host: SSH Host
    :param os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
    :param network_interface: Network interface
    :return: True if success or False if error
    """
    try:
        assert not (ssh_password is None and ssh_pkey is None), \
            'SSH password and private key is None'

        ssh_client: SSHClient = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        if ssh_password is not None:
            ssh_client.connect(hostname=ssh_host, username=ssh_user, password=ssh_password)
        if ssh_pkey is not None:
            ssh_client.connect(hostname=ssh_host, username=ssh_user, pkey=ssh_pkey)

        if os == 'MacOS':
            dhclient_command: str = 'ipconfig set ' + network_interface + ' DHCP'
        elif os == 'Linux':
            dhclient_command: str = 'rm -f /var/lib/dhcp/dhclient.leases; dhclient ' + network_interface
        else:
            dhclient_command: str = 'ipconfig /release && ipconfig /renew'

        ssh_client.exec_command(dhclient_command)
        ssh_client.close()
        return True

    except AssertionError as Error:
        base.print_error(Error.args[0])
        return False

    except IndexError:
        return False

    except NoValidConnectionsError:
        base.print_error('Could not connect to SSH host: ', ssh_host)
        return False

    except AuthenticationException:
        base.print_error('SSH authentication error: ', ssh_user + '@' + ssh_host)
        return False
# endregion


# region Make DHCPv4 reply packet
def make_reply(bootp_transaction_id: int = 1,
               dhcpv4_message_type: int = 2) -> bytes:

    if tested_index == len(tested_parameters) - 1:
        base.info_text('Exit ...')
        exit(0)

    bootp_packet: bytes = pack('!B', tested_parameters[tested_index]['BOOTP']['message_type'])  # Message type
    bootp_packet += pack('!B', tested_parameters[tested_index]['BOOTP']['hardware_type'])  # Hardware type: 1 - Ethernet
    bootp_packet += pack('!B', tested_parameters[tested_index]['BOOTP']['hardware_length'])  # Hardware address length: 6 - Ethernet header length
    bootp_packet += pack('!B', tested_parameters[tested_index]['BOOTP']['hops'])  # Number of hops
    bootp_packet += pack('!L', bootp_transaction_id)  # Transaction ID
    bootp_packet += pack('!H', 0)  # Seconds elapsed
    bootp_packet += pack('!H', tested_parameters[tested_index]['BOOTP']['flags'])  # Flags
    bootp_packet += pack('!4s', inet_aton(tested_parameters[tested_index]['BOOTP']['client_ip']))  # CIADDR - Client IP address
    bootp_packet += pack('!4s', inet_aton(tested_parameters[tested_index]['BOOTP']['your_ip']))  # YIADDR - Your client IP address
    bootp_packet += pack('!4s', inet_aton(tested_parameters[tested_index]['BOOTP']['next_server_ip']))  # SIADDR - Next server IP address
    bootp_packet += pack('!4s', inet_aton(tested_parameters[tested_index]['BOOTP']['relay_agent_ip']))  # GIADDR - Relay agent IP address
    bootp_packet += eth.convert_mac(mac_address=tested_parameters[tested_index]['BOOTP']['client_mac'])  # CHADDR - Client hardware address

    bootp_packet += b''.join(pack('B', 0) for _ in range(10))  # Client hardware address padding
    bootp_packet += b''.join(pack('B', 0) for _ in range(64))  # Server host name
    bootp_packet += b''.join(pack('B', 0) for _ in range(128))  # Boot file name
    bootp_packet += dhcpv4.dhcp_magic_cookie  # DHCPv4 magic cookie

    dhcpv4_packet: bytes = pack('!3B', 53, 1, dhcpv4_message_type)  # 53 DHCPv4 message type
    dhcpv4_packet += pack('!' '2B' '4s', 54, 4, inet_aton(tested_parameters[tested_index]['DHCP']['server_identifier']))  # 54 DHCPv4 server identifier
    dhcpv4_packet += pack('!' '2B' 'L', 51, 4, tested_parameters[tested_index]['DHCP']['lease_time'])  # 51 - DHCPv4 IP address lease time option
    dhcpv4_packet += pack('!' '2B' '4s', 1, 4, inet_aton(tested_parameters[tested_index]['DHCP']['subnet_mask']))  # 1 - DHCPv4 Subnet mask option
    dhcpv4_packet += pack('!' '2B' '4s', 3, 4, inet_aton(tested_parameters[tested_index]['DHCP']['router']))  # 3 - DHCPv4 Router option (Router IPv4 address)
    dhcpv4_packet += pack('!' '2B' '4s', 6, 4, inet_aton(tested_parameters[tested_index]['DHCP']['dns_server']))  # 6 - DHCPv4 DNS option (Domain name server IPv4 address)
    dhcpv4_packet += pack('!' '2B', 15, len(tested_parameters[tested_index]['DHCP']['domain'])) + \
                     tested_parameters[tested_index]['DHCP']['domain']  # 15 - DHCPv4 Domain name option
    dhcpv4_packet += pack('B', 255)  # 255 - End of DHCPv4 options

    eth_header: bytes = eth.make_header(source_mac=tested_parameters[tested_index]['Ethernet']['source_mac_address'],
                                        destination_mac=tested_parameters[tested_index]['Ethernet']['destination_mac_address'],
                                        network_type=tested_parameters[tested_index]['Ethernet']['network_type'])

    ip_header: bytes = ipv4.make_header(source_ip=tested_parameters[tested_index]['Network']['source_ip_address'],
                                        destination_ip=tested_parameters[tested_index]['Network']['source_ip_address'],
                                        data_len=len(bootp_packet + dhcpv4_packet),
                                        transport_protocol_len=udp.header_length,
                                        transport_protocol_type=udp.header_type)

    udp_header: bytes = udp.make_header(source_port=tested_parameters[tested_index]['Transport']['source_port'],
                                        destination_port=tested_parameters[tested_index]['Transport']['destination_port'],
                                        data_length=len(bootp_packet + dhcpv4_packet))

    return eth_header + ip_header + udp_header + bootp_packet + dhcpv4_packet
# endregion


# region DHCPv4 reply
def reply(packet: Dict):
    global tested_index
    if 'DHCPv4' in packet.keys():

        # DHCPv4 Discover
        if packet['DHCPv4'][53] == 1:
            base.print_info('Index of tested parameters: ', str(tested_index))
            if packet['BOOTP']['transaction-id'] not in transactions:
                transactions.append(packet['BOOTP']['transaction-id'])
            else:
                tested_index += 1
            reply_packet = make_reply(bootp_transaction_id=packet['BOOTP']['transaction-id'], dhcpv4_message_type=2)
            raw_socket.send(reply_packet)
            base.print_info('DHCPv4 Discover from: ', packet['Ethernet']['source'])

        # DHCPv4 Request
        if packet['DHCPv4'][53] == 3:
            reply_packet = make_reply(bootp_transaction_id=packet['BOOTP']['transaction-id'], dhcpv4_message_type=5)
            raw_socket.send(reply_packet)
            base.print_info('DHCPv4 Request from: ', packet['Ethernet']['source'])
            sleep(2)
            current_gateway_ipv4_address = get_ipv4_gateway_over_ssh(ssh_user=args.target_ssh_user,
                                                                     ssh_password=args.target_ssh_pass,
                                                                     ssh_pkey=private_key,
                                                                     ssh_host=args.target_ip,
                                                                     os=args.target_os,
                                                                     network_interface=args.target_interface)
            if current_gateway_ipv4_address is not None:
                base.print_success('Index: ', str(tested_index),
                                   ' Gateway: ', current_gateway_ipv4_address,
                                   ' Parameters: ', str(tested_parameters[tested_index]))
            else:
                base.print_error('Index: ', str(tested_index),
                                 ' Gateway: ', 'None',
                                 ' Parameters: ', str(tested_parameters[tested_index]))
            tested_index += 1
            dhclient_over_ssh(ssh_user=args.target_ssh_user,
                              ssh_password=args.target_ssh_pass,
                              ssh_pkey=private_key,
                              ssh_host=args.target_ip,
                              os=args.target_os,
                              network_interface=args.target_interface)

# endregion


# # region Update gateway
# def update_ipv4_gateway_over_ssh(connected_ssh_client: SSHClient,
#                                  target_os: str = 'MacOS',
#                                  gateway_ipv4_address: str = '192.168.0.254',
#                                  real_gateway_mac_address: str = '12:34:56:78:90:ab') -> bool:
#     """
#     Update ARP table on target host over SSH after spoofing
#     :param connected_ssh_client: Already connected SSH client
#     :param target_os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
#     :param gateway_ipv4_address: IPv4 address of gateway
#     :param real_gateway_mac_address: Real IPv4 gateway MAC address
#     :return: True if MAC address is changed or False if error
#     """
#     connected_ssh_client.exec_command('arp -d ' + gateway_ipv4_address)
#     if target_os == 'MacOS' or target_os == 'Linux':
#         connected_ssh_client.exec_command('ping -c 1 ' + gateway_ipv4_address)
#     else:
#         connected_ssh_client.exec_command('ping -n 1 ' + gateway_ipv4_address)
#     current_gateway_mac_address = get_ipv4_gateway_mac_address_over_ssh(
#         connected_ssh_client=ssh_client,
#         target_os=target_os,
#         gateway_ipv4_address=gateway_ipv4_address)
#     if target_os == 'MacOS':
#         real_gateway_mac_address = base.macos_encode_mac_address(real_gateway_mac_address)
#     if current_gateway_mac_address == real_gateway_mac_address:
#         return True
#     else:
#         return False
#
#
# # endregion
#
#
# # region Check MAC address of IPv4 gateway over ssh
# def check_ipv4_gateway_over_ssh(connected_ssh_client: SSHClient,
#                                 target_os: str = 'MacOS',
#                                 gateway_ipv4_address: str = '192.168.0.254',
#                                 real_gateway_mac_address: str = '12:34:56:78:90:ab',
#                                 test_parameters: Union[None, Dict[str, Dict[str, Union[int, str]]]] = None,
#                                 test_parameters_index: int = 0) -> None:
#     """
#     Check MAC address of IPv4 gateway in target host over SSH
#     :param connected_ssh_client: Already connected SSH client
#     :param target_os: MacOS, Linux or Windows (Installation of OpenSSH For Windows: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
#     :param gateway_ipv4_address: IPv4 address of gateway
#     :param real_gateway_mac_address: Real IPv4 gateway MAC address
#     :param test_parameters: Dictionary of tested parameters
#     :param test_parameters_index: Index of current test
#     :return: None
#     """
#     current_gateway_mac_address: str = get_ipv4_gateway_mac_address_over_ssh(
#         connected_ssh_client=connected_ssh_client,
#         target_os=target_os,
#         gateway_ipv4_address=gateway_ipv4_address)
#
#     if current_gateway_mac_address is None:
#         if test_parameters is not None:
#             base.print_warning('index: ', str(test_parameters_index), ' parameters: ', dumps(test_parameters))
#             with open('arp_fuzz_disconnect.txt', 'a') as result_file:
#                 result_file.write('index: ' + str(test_parameters_index) +
#                                   ' parameters: ' + dumps(test_parameters) + '\n')
#         sleep(5)
#         check_ipv4_gateway_mac_address_over_ssh(connected_ssh_client,
#                                                 target_os,
#                                                 gateway_ipv4_address,
#                                                 real_gateway_mac_address,
#                                                 test_parameters,
#                                                 test_parameters_index)
#
#     if target_os == 'MacOS':
#         real_gateway_mac_address = base.macos_encode_mac_address(real_gateway_mac_address)
#
#     if current_gateway_mac_address == real_gateway_mac_address:
#         if test_parameters is not None:
#             base.print_info('index: ', str(test_parameters_index), ' gateway: ', current_gateway_mac_address,
#                             ' parameters: ', dumps(test_parameters))
#
#     else:
#         if test_parameters is not None:
#             base.print_success('index: ', str(test_parameters_index), ' gateway: ', current_gateway_mac_address,
#                                ' parameters: ', dumps(test_parameters))
#             with open('arp_fuzz_success.txt', 'a') as result_file:
#                 result_file.write('index: ' + str(test_parameters_index) +
#                                   ' gateway: ' + current_gateway_mac_address +
#                                   ' parameters: ' + dumps(test_parameters) + '\n')
#
#         while True:
#             if update_ipv4_gateway_mac_address_over_ssh(connected_ssh_client=connected_ssh_client,
#                                                         target_os=target_os,
#                                                         gateway_ipv4_address=gateway_ipv4_address,
#                                                         real_gateway_mac_address=real_gateway_mac_address):
#                 break
#             else:
#                 sleep(1)
#
#
# # endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawIPv4, RawUDP, RawDHCPv4, RawSniff
    from raw_packet.Utils.tm import ThreadManager

    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ipv4: RawIPv4 = RawIPv4()
    udp: RawUDP = RawUDP()
    sniff: RawSniff = RawSniff()
    dhcpv4: RawDHCPv4 = RawDHCPv4()
    thread_manager: ThreadManager = ThreadManager(2)
    # endregion

    # region Raw socket
    raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='DHCPv4 fuzzing script')
    parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
    parser.add_argument('-m', '--target_mac', help='Set target MAC address', required=True)
    parser.add_argument('-t', '--target_ip', help='Set target IPv4 address', required=True)
    parser.add_argument('-o', '--target_os', help='Set target OS (MacOS, Linux, Windows)', default='MacOS')
    parser.add_argument('-e', '--target_interface', help='Set target OS network interface', default='en0')
    parser.add_argument('-u', '--target_ssh_user', help='Set target user name for ssh', default='root')
    parser.add_argument('-p', '--target_ssh_pass', help='Set target password for ssh', default=None)
    parser.add_argument('-k', '--target_ssh_pkey', help='Set target private key for ssh', default=None)
    parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', required=True)
    parser.add_argument('-A', '--all_tests', action='store_true', help='Test all fields')
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

    try:
        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region SSH and current gateway address
        private_key: Union[None, RSAKey] = None

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
        # endregion

        # region Variables
        number_of_arp_packets: int = 5
        interval_between_sending_packets: float = 0.2

        tested_parameters: List[Dict[str, Dict[str, Union[int, str]]]] = list()

        link_layer_fields: List[Dict[str, Union[int, str]]] = list()
        network_layer_fields: List[Dict[str, Union[int, str]]] = list()
        transport_layer_fields: List[Dict[str, Union[int, str]]] = list()
        bootp_fields: List[Dict[str, Union[int, str]]] = list()
        dhcp_options: List[Dict[str, Union[int, str]]] = list()

        # region Ethernet
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
            ipv4.header_type  # IPv4 protocol
        ]
        # endregion

        # region IPv4
        if args.all_tests:
            # Long list
            destination_ip_addresses: List[str] = [
                args.target_ip,  # Target IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            source_ip_addresses: List[str] = [
                your_ip_address,  # Your IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
        elif args.only_broadcast:
            # Only Broadcast packets
            destination_ip_addresses: List[str] = [
                '255.255.255.255',  # Broadcast IPv4 address
            ]
            source_ip_addresses: List[str] = [
                '255.255.255.255',  # Broadcast IPv4 address
            ]
        elif args.only_multicast:
            # Only Multicast packets
            destination_ip_addresses: List[str] = [
                '224.0.0.1',  # IPv4 multicast IPv4 address
            ]
            source_ip_addresses: List[str] = [
                '224.0.0.1',  # IPv4 multicast IPv4 address
            ]
        else:
            # Short list
            destination_ip_addresses: List[str] = [
                args.target_ip,  # Target IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
            ]
            source_ip_addresses: List[str] = [
                your_ip_address,  # Your IPv4 address
                '0.0.0.0',  # Zeros
            ]
        transport_types: List[int] = [
            udp.header_type
        ]
        # endregion

        # region UDP
        if args.all_tests:
            # Long list
            destination_ports: List[int] = [
                68,  # DHCPv4 response destination port
                67,  # DHCPv4 response source port
                546,  # DHCPv6 response destination port
                547,  # DHCPv6 response source port
            ]
            source_ports: List[int] = [
                68,  # DHCPv4 response destination port
                67,  # DHCPv4 response source port
                546,  # DHCPv6 response destination port
                547,  # DHCPv6 response source port
            ]
        else:
            # Short list
            destination_ports: List[int] = [
                68,  # DHCPv4 response destination port
                67,  # DHCPv4 response source port
            ]
            source_ports: List[int] = [
                67,  # DHCPv4 response source port
                5353,  # MDNS port
            ]
        # endregion

        # region BOOTP
        if args.all_tests:
            # Long list
            bootp_message_types: List[int] = [
                1,  # BOOTP Request
                2,  # BOOTP Reply
                3,  # BOOTP Unknown message type
            ]
            bootp_hardware_types: List[int] = [
                1,  # Ethernet
            ]
            bootp_hardware_lengths: List[int] = [
                6,  # Ethernet hardware address length
            ]
            bootp_hops: List[int] = [
                0,
                254
            ]
            bootp_flags: List[int] = [
                0,
                65535,
            ]
            bootp_client_ips: List[str] = [
                your_ip_address,  # Your IPv4 address
                args.target_ip,  # Target IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            bootp_your_ips: List[str] = [
                args.target_ip,  # Target IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            bootp_next_server_ips: List[str] = [
                your_ip_address,  # Your IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            bootp_relay_agent_ips: List[str] = [
                your_ip_address,  # Your IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            bootp_client_macs: List[str] = [
                args.target_mac,  # Target MAC address
                your_mac_address,  # Your MAC address
                'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
                '33:33:00:00:00:01',  # IPv6 multicast MAC address
                '01:00:5e:00:00:01',  # IPv4 multicast MAC address
            ]
        else:
            # Short list
            bootp_message_types: List[int] = [
                1,  # BOOTP Request
                2,  # BOOTP Reply
                3,  # BOOTP Unknown message type
            ]
            bootp_hardware_types: List[int] = [
                1,  # Ethernet
            ]
            bootp_hardware_lengths: List[int] = [
                6,  # Ethernet hardware address length
            ]
            bootp_hops: List[int] = [
                0,
            ]
            bootp_flags: List[int] = [
                0,
            ]
            bootp_client_ips: List[str] = [
                '0.0.0.0',  # Zeros
            ]
            bootp_your_ips: List[str] = [
                args.target_ip,  # Target IPv4 address
            ]
            bootp_next_server_ips: List[str] = [
                '0.0.0.0',  # Zeros
            ]
            bootp_relay_agent_ips: List[str] = [
                '0.0.0.0',  # Zeros
            ]
            bootp_client_macs: List[str] = [
                args.target_mac,  # Target MAC address
            ]
        # endregion

        # region DHCPv4
        if args.all_tests:
            # Long list
            dhcp_server_identifiers: List[str] = [
                your_ip_address,  # Your IPv4 address
                args.target_ip,  # Target IPv4 address
                '255.255.255.255',  # Broadcast IPv4 address
                '224.0.0.1',  # IPv4 multicast IPv4 address
                '0.0.0.0',  # Zeros
            ]
            dhcp_lease_times: List[int] = [
                0x0001,
                0xffff,  # Infinity
            ]
            dhcp_subnet_masks: List[str] = [
                '255.255.255.0'
            ]
            dhcp_routers: List[str] = [
                your_ip_address,  # Your IPv4 address
            ]
            dhcp_dns_servers: List[str] = [
                your_ip_address,  # Your IPv4 address
            ]
            dhcp_domains: List[bytes] = [
                b'local',
            ]
        else:
            # Short list
            dhcp_server_identifiers: List[str] = [
                your_ip_address,  # Your IPv4 address
            ]
            dhcp_lease_times: List[int] = [
                0xffff,  # Infinity
            ]
            dhcp_subnet_masks: List[str] = [
                '255.255.255.0'
            ]
            dhcp_routers: List[str] = [
                your_ip_address,  # Your IPv4 address
            ]
            dhcp_dns_servers: List[str] = [
                your_ip_address,  # Your IPv4 address
            ]
            dhcp_domains: List[bytes] = [
                b'local',
            ]
        # endregion

        # region Make tested parameters

        # region Link layer
        for destination_mac_address in destination_mac_addresses:
            for source_mac_address in source_mac_addresses:
                for network_type in network_types:
                    link_layer_fields.append({
                        'destination_mac_address': destination_mac_address,
                        'source_mac_address': source_mac_address,
                        'network_type': network_type
                    })
        # endregion

        # region Network layer
        for destination_ip_address in destination_ip_addresses:
            for source_ip_address in source_ip_addresses:
                for transport_type in transport_types:
                    network_layer_fields.append({
                        'destination_ip_address': destination_ip_address,
                        'source_ip_address': source_ip_address,
                        'transport_type': transport_type
                    })
        # endregion

        # region Transport layer
        for destination_port in destination_ports:
            for source_port in source_ports:
                transport_layer_fields.append({
                    'destination_port': destination_port,
                    'source_port': source_port
                })
        # endregion

        # region BOOTP
        for bootp_message_type in bootp_message_types:
            for bootp_hardware_type in bootp_hardware_types:
                for bootp_hardware_length in bootp_hardware_lengths:
                    for bootp_hop in bootp_hops:
                        for bootp_flag in bootp_flags:
                            for bootp_client_ip in bootp_client_ips:
                                for bootp_your_ip in bootp_your_ips:
                                    for bootp_next_server_ip in bootp_next_server_ips:
                                        for bootp_relay_agent_ip in bootp_relay_agent_ips:
                                            for bootp_client_mac in bootp_client_macs:
                                                bootp_fields.append({
                                                    'message_type': bootp_message_type,
                                                    'hardware_type': bootp_hardware_type,
                                                    'hardware_length': bootp_hardware_length,
                                                    'hops': bootp_hop,
                                                    'flags': bootp_flag,
                                                    'client_ip': bootp_client_ip,
                                                    'your_ip': bootp_your_ip,
                                                    'next_server_ip': bootp_next_server_ip,
                                                    'relay_agent_ip': bootp_relay_agent_ip,
                                                    'client_mac': bootp_client_mac
                                                })
        # endregion

        # region DHCP
        for dhcp_server_identifier in dhcp_server_identifiers:
            for dhcp_lease_time in dhcp_lease_times:
                for dhcp_subnet_mask in dhcp_subnet_masks:
                    for dhcp_router in dhcp_routers:
                        for dhcp_dns_server in dhcp_dns_servers:
                            for dhcp_domain in dhcp_domains:
                                dhcp_options.append({
                                    'server_identifier': dhcp_server_identifier,
                                    'lease_time': dhcp_lease_time,
                                    'subnet_mask': dhcp_subnet_mask,
                                    'router': dhcp_router,
                                    'dns_server': dhcp_dns_server,
                                    'domain': dhcp_domain
                                })
        # endregion

        # region Make all tested parameters
        for link_layer in link_layer_fields:
            for network_layer in network_layer_fields:
                for transport_layer in transport_layer_fields:
                    for bootp in bootp_fields:
                        for dhcp in dhcp_options:
                            tested_parameters.append({
                                'Ethernet': link_layer,
                                'Network': network_layer,
                                'Transport': transport_layer,
                                'BOOTP': bootp,
                                'DHCP': dhcp
                            })
        # endregion
        
        # endregion

        # endregion

        # region Sniffer
        network_filters = {
            'Ethernet': {'source': args.target_mac, 'destination': 'ff:ff:ff:ff:ff:ff'},
            'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
            'UDP': {'source-port': 68, 'destination-port': 67}
        }
        dhclient_over_ssh(ssh_user=args.target_ssh_user,
                          ssh_password=args.target_ssh_pass,
                          ssh_pkey=private_key,
                          ssh_host=args.target_ip,
                          os=args.target_os,
                          network_interface=args.target_interface)
        sniff.start(protocols=['IPv4', 'UDP', 'DHCPv4'], prn=reply, filters=network_filters)
        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        base.print_error(Error.args[0])
        exit(1)
