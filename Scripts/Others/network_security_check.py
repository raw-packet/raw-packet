#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
network_security_check.py: Checking network security mechanisms such as: Dynamic ARP Inspection, DHCP snooping, etc.
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
from typing import Union, Dict, List
from paramiko import RSAKey
from pathlib import Path
from os.path import isfile
from os import remove
from subprocess import run, Popen
from scapy.all import rdpcap, Ether, ARP, IP, UDP, BOOTP, DHCP, ICMP, IPv6
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.all import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
from time import sleep
from random import randint
from re import findall, MULTILINE
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


if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Scanners.arp_scanner import ArpScan
    from raw_packet.Scanners.scanner import Scanner
    from raw_packet.Utils.network import RawARP, RawICMPv4, RawDHCPv4, RawICMPv6, RawDHCPv6

    base: Base = Base()
    arp_scan: ArpScan = ArpScan()
    scanner: Scanner = Scanner()
    arp: RawARP = RawARP()
    icmpv4: RawICMPv4 = RawICMPv4()
    dhcpv4: RawDHCPv4 = RawDHCPv4()
    icmpv6: RawICMPv6 = RawICMPv6()
    dhcpv6: RawDHCPv6 = RawDHCPv6()
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
        parser: ArgumentParser = ArgumentParser(description='Checking network security mechanisms')
        parser.add_argument('-s', '--send_interface', help='Set interface name for send packets', default=None)
        parser.add_argument('-l', '--listen_interface', help='Set interface name for listen packets', default=None)
        parser.add_argument('-n', '--test_host_interface', help='Set test host network interface for listen packets',
                            default=None)
        parser.add_argument('-t', '--test_host', help='Set test host IP address for ssh connection', default=None)
        parser.add_argument('-m', '--test_mac', help='Set test host MAC address for ssh connection', default=None)
        parser.add_argument('-o', '--test_os', help='Set test host OS (MacOS, Linux, Windows)', default='Linux')
        parser.add_argument('-u', '--test_ssh_user', help='Set test host user name for ssh connection', default='root')
        parser.add_argument('-p', '--test_ssh_pass', help='Set test host password for ssh connection', default=None)
        parser.add_argument('-k', '--test_ssh_pkey', help='Set test host private key for ssh connection', default=None)
        parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', default=None)
        parser.add_argument('-g', '--gateway_mac', help='Set gateway MAC address', default=None)
        parser.add_argument('-r', '--number_of_packets', type=int,
                            help='Set number of network packets for each test', default=10)
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get network interface, your IP and MAC address
        if args.send_interface is None:
            base.print_warning('Please set a network interface for send packets ...')
        send_network_interface: str = base.network_interface_selection(args.send_interface)
        your_mac_address: str = base.get_interface_mac_address(send_network_interface)
        your_ip_address: str = base.get_interface_ip_address(send_network_interface)
        your_ipv6_address: str = base.make_ipv6_link_address(your_mac_address)
        your_network: str = base.get_interface_network(send_network_interface)
        raw_socket.bind((send_network_interface, 0))
        # endregion

        # region Variables
        list_of_network_interfaces: List[str] = base.list_of_network_interfaces()
        list_of_network_interfaces.remove(send_network_interface)

        listen_network_interface: Union[None, str] = None
        test_interface_ip_address: Union[None, str] = None
        use_listen_interface: str = 'No'

        test_ip_address: Union[None, str] = None
        test_mac_address: Union[None, str] = None
        test_ipv6_address: Union[None, str] = None
        test_interface: Union[None, str] = None
        test_os: Union[None, str] = None

        ssh_user: Union[None, str] = None
        ssh_password: Union[None, str] = None
        ssh_private_key: Union[None, RSAKey] = None

        pcap_file: str = '/tmp/spoofing.pcap'
        windows_temp_directory: Union[None, str] = None
        # endregion

        # region Check gateway IP and MAC address
        if args.gateway_ip is not None:
            assert base.ip_address_in_network(args.gateway_ip, your_network), \
                'Gateway IP address: ' + base.error_text(args.gateway_ip) + \
                ' not in your network: ' + base.info_text(your_network)
            gateway_ip_address: str = str(args.gateway_ip)
        else:
            gateway_ip_address: str = base.get_interface_gateway(send_network_interface)
        scan_gateway_mac_address: str = arp_scan.get_mac_address(network_interface=send_network_interface,
                                                                 target_ip_address=gateway_ip_address,
                                                                 show_scan_percentage=False)
        if args.gateway_mac is not None:
            assert base.mac_address_validation(args.gateway_mac), \
                'Bad gateway MAC address: ' + base.error_text(args.gateway_mac)
            assert args.gateway_mac == scan_gateway_mac_address, \
                'Gateway MAC address in argument: ' + base.error_text(args.gateway_mac) + \
                ' is not real gateway MAC address: ' + base.info_text(scan_gateway_mac_address)
        gateway_mac_address: str = scan_gateway_mac_address
        gateway_ipv6_address: str = base.make_ipv6_link_address(gateway_mac_address)
        # endregion

        # region Set listen interface or test host
        if args.listen_interface is None and args.test_host is None:

            # region Make list of available network interfaces
            if len(list_of_network_interfaces) > 0:
                for test_interface in list_of_network_interfaces:
                    test_interface_ip_address = base.get_interface_ip_address(interface_name=test_interface,
                                                                              exit_on_failure=False, quiet=True)
                    if base.ip_address_in_network(test_interface_ip_address, your_network):
                        listen_network_interface = test_interface
                        break
            # endregion

            # region Found network interface with IP address in test network
            if listen_network_interface is not None:
                while test_ip_address is None:
                    use_listen_interface = \
                        input(base.c_info + 'Use network interface: ' +
                              base.info_text(listen_network_interface + ' (' + test_interface_ip_address + ')') +
                              ' for listen traffic [Yes|No]: ')
                    if use_listen_interface == 'No' or use_listen_interface == 'N':
                        while True:
                            test_ip_address = input(base.c_info + 'Please set test host IP address for SSH connect: ')
                            if base.ip_address_in_network(test_ip_address, your_network):
                                break
                            else:
                                base.print_error('Test host IP address: ', test_ip_address,
                                                 ' not in network: ' + base.info_text(your_network))
                    elif use_listen_interface == 'Yes' or use_listen_interface == 'Y':
                        break
                    else:
                        base.print_error('Unknown answer: ', use_listen_interface, ' please use answer "Yes" or "No"')
            # endregion

            # region Not found network interface with IP address in test network, set test host IP address for SSH conn
            else:
                if not args.quiet:
                    arp_scan_results = arp_scan.scan(network_interface=send_network_interface,
                                                     timeout=5, retry=5, show_scan_percentage=True,
                                                     exclude_ip_addresses=[gateway_ip_address])
                else:
                    arp_scan_results = arp_scan.scan(network_interface=send_network_interface,
                                                     timeout=5, retry=5, show_scan_percentage=False,
                                                     exclude_ip_addresses=[gateway_ip_address])
                target = scanner.ipv4_device_selection(arp_scan_results)
                test_ip_address = target['ip-address']
                test_mac_address = target['mac-address']
            # endregion

        # endregion

        # region Check test host
        if args.test_host is not None or test_ip_address is not None:

            # region Check test host IP and MAC address
            if test_ip_address is not None and test_mac_address is not None:
                test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            else:
                if args.test_host is not None:
                    assert base.ip_address_in_network(args.test_host, your_network), \
                        'Test host IP address: ' + base.error_text(args.test_host) + \
                        ' not in your network: ' + base.info_text(your_network)
                    test_ip_address = str(args.test_host)
                scan_test_mac_address: str = arp_scan.get_mac_address(network_interface=send_network_interface,
                                                                      target_ip_address=test_ip_address,
                                                                      show_scan_percentage=False)
                if args.test_mac is not None:
                    assert base.mac_address_validation(args.test_mac), \
                        'Bad test host MAC address: ' + base.error_text(args.test_mac)
                    assert args.test_mac == scan_test_mac_address, \
                        'Test host MAC address in argument: ' + base.error_text(args.test_mac) + \
                        ' is not real test host MAC address: ' + base.info_text(scan_test_mac_address)
                test_mac_address = scan_test_mac_address
                test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            # endregion

            # region Check test host SSH user, password and private key
            ssh_user = args.test_ssh_user
            ssh_password = args.test_ssh_pass
            ssh_private_key = None
            test_os = str(args.test_os).lower()

            if args.test_ssh_pkey is None and ssh_password is None:
                default_ssh_private_key_file: str = str(Path.home()) + '/.ssh/id_rsa'
                assert isfile(default_ssh_private_key_file), \
                    'Could not found private SSH key: ' + base.error_text(default_ssh_private_key_file)
                ssh_private_key = RSAKey.from_private_key_file(default_ssh_private_key_file)

            if args.test_ssh_pkey is not None:
                ssh_private_key = RSAKey.from_private_key_file(args.target_ssh_pkey)

            assert ssh_private_key is not None or ssh_password is not None, \
                'Password and private key file for SSH is None!' + \
                ' Please set SSH password: ' + base.info_text('--test_ssh_pass <ssh_password>') + \
                ' or SSH private key file: ' + base.info_text('--test_ssh_pkey <ssh_private_key_path>')

            if test_os == 'linux' or test_os == 'macos':
                command: str = 'ifconfig'
            else:
                command: str = 'netsh interface show interface'
            test_host_network_interfaces: str = base.exec_command_over_ssh(command=command,
                                                                           ssh_user=ssh_user,
                                                                           ssh_password=ssh_password,
                                                                           ssh_pkey=ssh_private_key,
                                                                           ssh_host=test_ip_address)

            if test_os == 'linux' or test_os == 'macos':
                test_host_network_interfaces_list = findall(r'^([a-zA-Z0-9]{2,32})\:\ ',
                                                            test_host_network_interfaces,
                                                            MULTILINE)
            else:
                test_host_network_interfaces_list = test_host_network_interfaces.split()

            if args.test_host_interface is None:
                base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)
                test_interface = input('Please set network interface on test host: ')
            else:
                test_interface = args.test_host_interface
                if test_interface not in test_host_network_interfaces_list:
                    base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)

            while True:
                if test_interface not in test_host_network_interfaces_list:
                    base.print_warning('Network interface: ', test_interface,
                                       ' not in network interfaces list on test host')
                    test_interface = input('Please set network interface on test host: ')
                else:
                    break
            # endregion

        # endregion

        # region Check listen network interface
        if (args.listen_interface is not None or listen_network_interface is not None) and test_ip_address is None:
            if args.listen_interface is not None:
                assert args.listen_interface in list_of_network_interfaces, \
                    'Network interface: ' + base.error_text(args.listen_interface) + \
                    ' not in available network interfaces list: ' + base.info_text(str(list_of_network_interfaces))
                listen_network_interface = args.listen_interface
            test_ip_address = base.get_interface_ip_address(listen_network_interface)
            test_mac_address = base.get_interface_mac_address(listen_network_interface)
            test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            test_interface = listen_network_interface
            test_os = 'linux'
        # endregion

        # region Output
        if not args.quiet:
            base.print_info('Send network interface: ', send_network_interface)
            base.print_info('Send network interface IP address: ', your_ip_address)
            base.print_info('Send network interface MAC address: ', your_mac_address)
            if listen_network_interface is not None:
                base.print_info('Listen network interface: ', listen_network_interface)
                base.print_info('Listen network interface IP address: ', test_ip_address)
                base.print_info('Listen network interface MAC address: ', test_mac_address)
            if ssh_user is not None:
                base.print_info('Test host IP address: ', test_ip_address)
                base.print_info('Test host MAC address: ', test_mac_address)
                base.print_info('Test host OS: ', test_os)
                base.print_info('Test host network interface: ', test_interface)
            base.print_info('Gateway IP address: ', gateway_ip_address)
            base.print_info('Gateway MAC address: ', gateway_mac_address)
        # endregion

        # region Start tshark
        if test_os == 'linux' or test_os == 'macos':
            start_tshark_command: str = 'rm -f /tmp/spoofing.pcap; tshark -i ' + test_interface + \
                                        ' -w /tmp/spoofing.pcap -f "ether src ' + your_mac_address + \
                                        '" >/dev/null 2>&1'
        else:
            start_tshark_command: str = 'cd %temp% & del /f spoofing.pcap &' \
                                        ' "C:\\Program Files\\Wireshark\\tshark.exe" -i ' + test_interface + \
                                        ' -w spoofing.pcap -f "ether src ' + your_mac_address + '"'
        if ssh_user is not None:
            if not args.quiet:
                base.print_info('Start tshark on test host: ', test_ip_address)
            base.exec_command_over_ssh(command=start_tshark_command,
                                       ssh_user=ssh_user,
                                       ssh_password=ssh_password,
                                       ssh_pkey=ssh_private_key,
                                       ssh_host=test_ip_address,
                                       need_output=False)

            if test_os == 'linux' or test_os == 'macos':
                start_tshark_retry: int = 1
                while base.exec_command_over_ssh(command='pgrep tshark',
                                                 ssh_user=ssh_user,
                                                 ssh_password=ssh_password,
                                                 ssh_pkey=ssh_private_key,
                                                 ssh_host=test_ip_address) == '':
                    base.exec_command_over_ssh(command=start_tshark_command,
                                               ssh_user=ssh_user,
                                               ssh_password=ssh_password,
                                               ssh_pkey=ssh_private_key,
                                               ssh_host=test_ip_address,
                                               need_output=False)
                    sleep(1)
                    start_tshark_retry += 1
                    if start_tshark_retry == 5:
                        base.print_error('Failed to start tshark on test host: ', test_ip_address)
                        exit(1)
            else:
                windows_temp_directory = base.exec_command_over_ssh(command='echo %temp%',
                                                                    ssh_user=ssh_user,
                                                                    ssh_password=ssh_password,
                                                                    ssh_pkey=ssh_private_key,
                                                                    ssh_host=test_ip_address)
                assert windows_temp_directory is not None or windows_temp_directory != '', \
                    'Can not get variable %temp% on Windows host: ' + base.error_text(test_ip_address)
                if windows_temp_directory.endswith('\n'):
                    windows_temp_directory = windows_temp_directory[:-1]
                if windows_temp_directory.endswith('\r'):
                    windows_temp_directory = windows_temp_directory[:-1]
        else:
            if isfile(pcap_file):
                remove(pcap_file)
            if not args.quiet:
                base.print_info('Start tshark on listen interface: ', listen_network_interface)
            Popen([start_tshark_command], shell=True)
        sleep(5)
        # endregion

        # region Send ARP packets
        base.print_info('Send ARP packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        arp_packet: bytes = arp.make_response(ethernet_src_mac=your_mac_address,
                                              ethernet_dst_mac=test_mac_address,
                                              sender_mac=your_mac_address,
                                              sender_ip=gateway_ip_address,
                                              target_mac=test_mac_address,
                                              target_ip=test_ip_address)
        for _ in range(args.number_of_packets):
            raw_socket.send(arp_packet)
            sleep(0.1)
        # endregion

        # region Send ICMPv4 packets
        base.print_info('Send ICMPv4 packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        icmpv4_packet: bytes = icmpv4.make_redirect_packet(ethernet_src_mac=your_mac_address,
                                                           ethernet_dst_mac=test_mac_address,
                                                           ip_src=gateway_ip_address,
                                                           ip_dst=test_ip_address,
                                                           gateway_address=your_ip_address,
                                                           payload_ip_src=test_ip_address,
                                                           payload_ip_dst='8.8.8.8')
        for _ in range(args.number_of_packets):
            raw_socket.send(icmpv4_packet)
            sleep(0.5)
        # endregion

        # region Send DHCPv4 packets
        base.print_info('Send DHCPv4 packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        dhcpv4_transactions: Dict[str, int] = {
            'discover': randint(0, 0xffffffff),
            'offer': randint(0, 0xffffffff),
            'request': randint(0, 0xffffffff),
            'ack': randint(0, 0xffffffff)
        }
        discover_packet: bytes = dhcpv4.make_discover_packet(ethernet_src_mac=your_mac_address,
                                                             client_mac=your_mac_address,
                                                             transaction_id=dhcpv4_transactions['discover'])
        offer_packet: bytes = dhcpv4.make_offer_packet(ethernet_src_mac=your_mac_address,
                                                       ethernet_dst_mac=test_mac_address,
                                                       ip_src=your_ip_address,
                                                       ip_dst=test_ip_address,
                                                       transaction_id=dhcpv4_transactions['offer'],
                                                       your_client_ip=test_ip_address,
                                                       client_mac=test_mac_address,
                                                       dhcp_server_id=your_ip_address,
                                                       router=your_ip_address,
                                                       dns=your_ip_address)
        request_packet: bytes = dhcpv4.make_request_packet(ethernet_src_mac=your_mac_address,
                                                           client_mac=your_mac_address,
                                                           transaction_id=dhcpv4_transactions['request'])
        ack_packet: bytes = dhcpv4.make_ack_packet(ethernet_src_mac=your_mac_address,
                                                   ethernet_dst_mac=test_mac_address,
                                                   ip_src=your_ip_address,
                                                   ip_dst=test_ip_address,
                                                   transaction_id=dhcpv4_transactions['ack'],
                                                   your_client_ip=test_ip_address,
                                                   client_mac=test_mac_address,
                                                   dhcp_server_id=your_ip_address,
                                                   router=your_ip_address,
                                                   dns=your_ip_address)
        for _ in range(args.number_of_packets):
            raw_socket.send(discover_packet)
            raw_socket.send(offer_packet)
            raw_socket.send(request_packet)
            raw_socket.send(ack_packet)
            sleep(0.1)
        # endregion

        # region Send ICMPv6 packets
        base.print_info('Send ICMPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')
        rs_packet: bytes = icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                             ethernet_dst_mac='33:33:00:00:00:02',
                                                             ipv6_src=gateway_ipv6_address,
                                                             ipv6_dst='ff02::2')
        ra_packet: bytes = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                   ethernet_dst_mac='33:33:00:00:00:01',
                                                                   ipv6_src=gateway_ipv6_address,
                                                                   ipv6_dst='ff02::1',
                                                                   dns_address=your_ipv6_address,
                                                                   prefix='fd00::/64')
        ns_packet: bytes = icmpv6.make_neighbor_solicitation_packet(ethernet_src_mac=your_mac_address,
                                                                    ethernet_dst_mac=test_mac_address,
                                                                    ipv6_src=gateway_ipv6_address,
                                                                    ipv6_dst=test_ipv6_address,
                                                                    icmpv6_target_ipv6_address=test_ipv6_address,
                                                                    icmpv6_source_mac_address=your_mac_address)
        na_packet: bytes = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                     ethernet_dst_mac=test_mac_address,
                                                                     ipv6_src=gateway_ipv6_address,
                                                                     ipv6_dst=test_ipv6_address,
                                                                     target_ipv6_address=gateway_ipv6_address)
        for _ in range(args.number_of_packets):
            raw_socket.send(rs_packet)
            raw_socket.send(ra_packet)
            raw_socket.send(ns_packet)
            raw_socket.send(na_packet)
            sleep(0.1)
        # endregion

        # region Send DHCPv6 packets
        base.print_info('Send DHCPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')
        dhcpv6_transactions: Dict[str, int] = {
            'solicit': randint(0, 0xffffff),
            'advertise': randint(0, 0xffffff),
            'request': randint(0, 0xffffff),
            'reply': randint(0, 0xffffff)
        }
        solicit_packet: bytes = dhcpv6.make_solicit_packet(ethernet_src_mac=your_mac_address,
                                                           ipv6_src=your_ipv6_address,
                                                           transaction_id=dhcpv6_transactions['solicit'],
                                                           client_mac_address=your_mac_address)
        advertise_packet: bytes = dhcpv6.make_advertise_packet(ethernet_src_mac=your_mac_address,
                                                               ethernet_dst_mac=test_mac_address,
                                                               ipv6_src=your_ipv6_address,
                                                               ipv6_dst=test_ipv6_address,
                                                               transaction_id=dhcpv6_transactions['advertise'],
                                                               dns_address=your_ipv6_address,
                                                               ipv6_address='fd00::123',
                                                               client_duid_timeval=1)
        request_packet: bytes = dhcpv6.make_request_packet(ethernet_src_mac=your_mac_address,
                                                           ipv6_src=your_ipv6_address,
                                                           transaction_id=dhcpv6_transactions['request'],
                                                           client_mac_address=your_mac_address)
        reply_packet: bytes = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                       ethernet_dst_mac=test_mac_address,
                                                       ipv6_src=your_ipv6_address,
                                                       ipv6_dst=test_ipv6_address,
                                                       transaction_id=dhcpv6_transactions['reply'],
                                                       dns_address=your_ipv6_address,
                                                       ipv6_address='fd00::123',
                                                       client_duid_timeval=1)
        for _ in range(args.number_of_packets):
            raw_socket.send(solicit_packet)
            raw_socket.send(advertise_packet)
            raw_socket.send(request_packet)
            raw_socket.send(reply_packet)
            sleep(0.1)
        # endregion

        # region Stop tshark
        sleep(5)
        if test_os == 'linux' or test_os == 'macos':
            stop_tshark_command: str = 'pkill tshark >/dev/null 2>&1'
        else:
            stop_tshark_command: str = 'taskkill /IM "tshark.exe" /F'
        if ssh_user is not None:
            if not args.quiet:
                base.print_info('Stop tshark on test host: ', test_ip_address)
            base.exec_command_over_ssh(command=stop_tshark_command,
                                       ssh_user=ssh_user,
                                       ssh_password=ssh_password,
                                       ssh_pkey=ssh_private_key,
                                       ssh_host=test_ip_address,
                                       need_output=False)
        else:
            if not args.quiet:
                base.print_info('Stop tshark on listen interface: ', listen_network_interface)
            run([stop_tshark_command], shell=True)
        # endregion

        # region Download and analyze pcap file from test host
        if ssh_user is not None:
            if isfile(pcap_file):
                remove(pcap_file)
            if not args.quiet:
                base.print_info('Download pcap file with test traffic over SSH to: ', pcap_file)
            if test_os == 'windows':
                base.download_file_over_ssh(remote_path=windows_temp_directory + '\spoofing.pcap',
                                            local_path=pcap_file,
                                            ssh_user=ssh_user,
                                            ssh_password=ssh_password,
                                            ssh_pkey=ssh_private_key,
                                            ssh_host=test_ip_address)
            else:
                base.download_file_over_ssh(remote_path=pcap_file,
                                            local_path=pcap_file,
                                            ssh_user=ssh_user,
                                            ssh_password=ssh_password,
                                            ssh_pkey=ssh_private_key,
                                            ssh_host=test_ip_address)
            assert isfile(pcap_file), \
                'Can not download pcap file: ' + base.error_text(pcap_file) + ' with test traffic over SSH'
        else:
            assert isfile(pcap_file), \
                'Not found pcap file: ' + base.error_text(pcap_file) + ' with test traffic'
        # endregion

        # region Analyze pcap file from test host
        if not args.quiet:
            base.print_info('Analyze pcap file:')

        sniff_arp_spoof_packets: bool = False

        sniff_icmpv4_redirect_packets: bool = False

        sniff_dhcpv4_discover_packets: bool = False
        sniff_dhcpv4_offer_packets: bool = False
        sniff_dhcpv4_request_packets: bool = False
        sniff_dhcpv4_ack_packets: bool = False

        sniff_icmpv6_rs_packets: bool = False
        sniff_icmpv6_ra_packets: bool = False
        sniff_icmpv6_ns_packets: bool = False
        sniff_icmpv6_na_packets: bool = False

        sniff_dhcpv6_solicit_packets: bool = False
        sniff_dhcpv6_advertise_packets: bool = False
        sniff_dhcpv6_request_packets: bool = False
        sniff_dhcpv6_reply_packets: bool = False

        packets = rdpcap(pcap_file)
        for packet in packets:

            if packet.haslayer(ARP):
                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[ARP].hwsrc == your_mac_address and \
                        packet[ARP].psrc == gateway_ip_address and \
                        packet[ARP].hwdst == test_mac_address and \
                        packet[ARP].pdst == test_ip_address:
                    sniff_arp_spoof_packets = True

            if packet.haslayer(ICMP):
                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[IP].src == gateway_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[ICMP].code == 1 and \
                        packet[ICMP].gw == your_ip_address:
                    sniff_icmpv4_redirect_packets = True

            if packet.haslayer(DHCP):
                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and \
                        packet[IP].src == '0.0.0.0' and \
                        packet[IP].dst == '255.255.255.255' and \
                        packet[UDP].sport == 68 and \
                        packet[UDP].dport == 67 and \
                        packet[BOOTP].op == 1 and \
                        packet[BOOTP].xid == dhcpv4_transactions['discover']:
                    sniff_dhcpv4_discover_packets = True

                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[IP].src == your_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[UDP].sport == 67 and \
                        packet[UDP].dport == 68 and \
                        packet[BOOTP].op == 2 and \
                        packet[BOOTP].xid == dhcpv4_transactions['offer']:
                    sniff_dhcpv4_offer_packets = True

                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and \
                        packet[IP].src == '0.0.0.0' and \
                        packet[IP].dst == '255.255.255.255' and \
                        packet[UDP].sport == 68 and \
                        packet[UDP].dport == 67 and \
                        packet[BOOTP].op == 1 and \
                        packet[BOOTP].xid == dhcpv4_transactions['request']:
                    sniff_dhcpv4_request_packets = True

                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[IP].src == your_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[UDP].sport == 67 and \
                        packet[UDP].dport == 68 and \
                        packet[BOOTP].op == 2 and \
                        packet[BOOTP].xid == dhcpv4_transactions['ack']:
                    sniff_dhcpv4_ack_packets = True

            if packet.haslayer(IPv6):
                if packet.haslayer(ICMPv6ND_RS):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == '33:33:00:00:00:02' and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == 'ff02::2' and \
                            packet[ICMPv6ND_RS].type == 133:
                        sniff_icmpv6_rs_packets = True

                if packet.haslayer(ICMPv6ND_RA):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == '33:33:00:00:00:01' and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == 'ff02::1' and \
                            packet[ICMPv6ND_RA].type == 134:
                        sniff_icmpv6_ra_packets = True

                if packet.haslayer(ICMPv6ND_NS):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == test_ipv6_address and \
                            packet[ICMPv6ND_NS].type == 135 and \
                            packet[ICMPv6ND_NS].tgt == test_ipv6_address:
                        sniff_icmpv6_ns_packets = True

                if packet.haslayer(ICMPv6ND_NA):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == test_ipv6_address and \
                            packet[ICMPv6ND_NA].type == 136 and \
                            packet[ICMPv6ND_NA].tgt == gateway_ipv6_address:
                        sniff_icmpv6_na_packets = True

                if packet.haslayer(UDP):
                    if packet.haslayer(DHCP6_Solicit):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == '33:33:00:01:00:02' and \
                                packet[IPv6].src == your_ipv6_address and \
                                packet[IPv6].dst == 'ff02::1:2' and \
                                packet[UDP].sport == 546 and \
                                packet[UDP].dport == 547 and \
                                packet[DHCP6_Solicit].msgtype == 1 and \
                                packet[DHCP6_Solicit].trid == dhcpv6_transactions['solicit']:
                            sniff_dhcpv6_solicit_packets = True

                    if packet.haslayer(DHCP6_Advertise):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == your_ipv6_address and \
                                packet[IPv6].dst == test_ipv6_address and \
                                packet[UDP].sport == 547 and \
                                packet[UDP].dport == 546 and \
                                packet[DHCP6_Advertise].msgtype == 2 and \
                                packet[DHCP6_Advertise].trid == dhcpv6_transactions['advertise']:
                            sniff_dhcpv6_advertise_packets = True

                    if packet.haslayer(DHCP6_Request):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == '33:33:00:01:00:02' and \
                                packet[IPv6].src == your_ipv6_address and \
                                packet[IPv6].dst == 'ff02::1:2' and \
                                packet[UDP].sport == 546 and \
                                packet[UDP].dport == 547 and \
                                packet[DHCP6_Request].msgtype == 3 and \
                                packet[DHCP6_Request].trid == dhcpv6_transactions['request']:
                            sniff_dhcpv6_request_packets = True

                    if packet.haslayer(DHCP6_Reply):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == your_ipv6_address and \
                                packet[IPv6].dst == test_ipv6_address and \
                                packet[UDP].sport == 547 and \
                                packet[UDP].dport == 546 and \
                                packet[DHCP6_Reply].msgtype == 7 and \
                                packet[DHCP6_Reply].trid == dhcpv6_transactions['reply']:
                            sniff_dhcpv6_reply_packets = True

        # endregion

        # region Print analyze pcap file results
        if sniff_arp_spoof_packets:
            base.print_success('ARP protection disabled')
        else:
            base.print_error('ARP protection enabled')

        if sniff_icmpv4_redirect_packets:
            base.print_success('ICMPv4 Redirect protection disabled')
        else:
            base.print_error('ICMPv4 Redirect protection enabled')

        if sniff_dhcpv4_discover_packets and \
                sniff_dhcpv4_offer_packets and \
                sniff_dhcpv4_request_packets and \
                sniff_dhcpv4_ack_packets:
            base.print_success('DHCPv4 protection disabled')
        else:
            base.print_error('DHCPv4 protection enabled')

        if sniff_icmpv6_rs_packets and sniff_icmpv6_ra_packets:
            base.print_success('ICMPv6 Router Advertisement protection disabled')
        else:
            base.print_error('ICMPv6 Router Advertisement protection enabled')

        if sniff_icmpv6_ns_packets and sniff_icmpv6_na_packets:
            base.print_success('ICMPv6 Neighbor Advertisement protection disabled')
        else:
            base.print_error('ICMPv6 Neighbor Advertisement protection enabled')

        if sniff_dhcpv6_solicit_packets and \
                sniff_dhcpv6_advertise_packets and \
                sniff_dhcpv6_request_packets and \
                sniff_dhcpv6_reply_packets:
            base.print_success('DHCPv6 protection disabled')
        else:
            base.print_error('DHCPv6 protection enabled')
        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        base.print_error(Error.args[0])
        exit(1)
