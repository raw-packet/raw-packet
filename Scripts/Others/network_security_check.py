#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
network_security_check.py: Checking network security mechanisms such as: ARP protection, DHCP snooping, etc.
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
from typing import Union, Dict
from paramiko import RSAKey
from pathlib import Path
from os.path import isfile
from os import remove
from scapy.all import rdpcap, Ether, ARP, IP, UDP, BOOTP, DHCP, IPv6
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.all import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
from time import sleep
from random import randint
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
    from raw_packet.Utils.network import RawARP, RawDHCPv4, RawICMPv6, RawDHCPv6

    base: Base = Base()
    arp_scan: ArpScan = ArpScan()
    arp: RawARP = RawARP()
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
        parser.add_argument('-i', '--interface', help='Set interface name', default=None)
        parser.add_argument('-t', '--test_host', help='Set test host IP address for ssh connection', required=True)
        parser.add_argument('-m', '--test_mac', help='Set test host MAC address for ssh connection', default=None)
        parser.add_argument('-o', '--test_os', help='Set test host OS (MacOS, Linux, Windows)', default='Linux')
        parser.add_argument('-n', '--test_host_interface', help='Set test host network interface', default='eth0')
        parser.add_argument('-u', '--test_ssh_user', help='Set test host user name for ssh connection', default='root')
        parser.add_argument('-p', '--test_ssh_pass', help='Set test host password for ssh connection', default=None)
        parser.add_argument('-k', '--test_ssh_pkey', help='Set test host private key for ssh connection', default=None)
        parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', default=None)
        parser.add_argument('-g', '--gateway_mac', help='Set gateway MAC address', default=None)
        args = parser.parse_args()
        # endregion

        # region Get network interface, your IP and MAC address
        if args.interface is None:
            base.print_warning('Please set a network interface for send packets ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_ip_address: str = base.get_interface_ip_address(current_network_interface)
        your_ipv6_address: str = base.make_ipv6_link_address(your_mac_address)
        your_network: str = base.get_interface_network(current_network_interface)
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region Check test host IP and MAC address
        assert base.ip_address_in_network(args.test_host, your_network), \
            'Test host IP address: ' + base.error_text(args.test_host) + \
            ' not in your network: ' + base.info_text(your_network)
        test_ip_address: str = str(args.test_host)
        scan_test_mac_address: str = arp_scan.get_mac_address(network_interface=current_network_interface,
                                                              target_ip_address=test_ip_address,
                                                              show_scan_percentage=False)
        if args.test_mac is not None:
            assert base.mac_address_validation(args.test_mac), \
                'Bad test host MAC address: ' + base.error_text(args.test_mac)
            assert args.test_mac == scan_test_mac_address, \
                'Test host MAC address in argument: ' + base.error_text(args.test_mac) + \
                ' is not real test host MAC address: ' + base.info_text(scan_test_mac_address)
        test_mac_address: str = scan_test_mac_address
        test_ipv6_address: str = base.make_ipv6_link_address(test_mac_address)
        # endregion

        # region Check test host SSH user, password and private key
        ssh_user: str = args.test_ssh_user
        ssh_password: Union[None, str] = args.test_ssh_pass
        ssh_private_key: Union[None, RSAKey] = None
        test_interface: str = args.test_host_interface
        test_os: str = str(args.test_os).lower()

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
            command: str = 'ipconfig'
        test_host_network_interfaces: str = base.exec_command_over_ssh(command=command,
                                                                       ssh_user=ssh_user,
                                                                       ssh_password=ssh_password,
                                                                       ssh_pkey=ssh_private_key,
                                                                       ssh_host=test_ip_address)
        assert test_interface in test_host_network_interfaces, \
            'Not found network interface: ' + base.error_text(test_interface) + \
            ' in ' + base.info_text(command) + ' output: \n' + base.info_text(test_host_network_interfaces)
        # endregion

        # region Check gateway IP and MAC address
        if args.gateway_ip is not None:
            assert base.ip_address_in_network(args.gateway_ip, your_network), \
                'Gateway IP address: ' + base.error_text(args.test_host) + \
                ' not in your network: ' + base.info_text(your_network)
            gateway_ip_address: str = str(args.gateway_ip)
        else:
            gateway_ip_address: str = base.get_interface_gateway(current_network_interface)
        scan_gateway_mac_address: str = arp_scan.get_mac_address(network_interface=current_network_interface,
                                                                 target_ip_address=gateway_ip_address,
                                                                 show_scan_percentage=False)
        if args.gateway_mac is not None:
            assert base.mac_address_validation(args.gateway_mac), \
                'Bad gateway MAC address: ' + base.error_text(args.gateway_mac)
            assert args.gateway_mac == scan_gateway_mac_address, \
                'Gateway MAC address in argument: ' + base.error_text(args.gateway_mac) + \
                ' is not real gateway MAC address: ' + base.info_text(scan_gateway_mac_address)
        gateway_mac_address: str = scan_gateway_mac_address
        # endregion

        # region Output
        base.print_info('Network interface: ', current_network_interface)
        base.print_info('Your IP address: ', your_ip_address)
        base.print_info('Your MAC address: ', your_mac_address)
        base.print_info('Test host IP address: ', test_ip_address)
        base.print_info('Test host MAC address: ', test_mac_address)
        base.print_info('Test host OS: ', test_os)
        base.print_info('Test host network interface: ', test_interface)
        base.print_info('Gateway IP address: ', gateway_ip_address)
        base.print_info('Gateway MAC address: ', gateway_mac_address)
        # endregion

        # region Start tshark on test host
        if test_os == 'linux' or test_os == 'macos':
            start_tshark_command: str = 'rm -f /tmp/spoofing.pcap; tshark -i ' + test_interface + \
                                        ' -w /tmp/spoofing.pcap -f "ether src ' + your_mac_address + '"'
        else:
            start_tshark_command: str = 'cd C:\Windows\Temp && del /f spoofing.pcap && tshark -i ' + test_interface + \
                                        ' -w spoofing.pcap -f "ether src ' + your_mac_address + '"'
        base.print_info('Start tshark in test host')
        base.exec_command_over_ssh(command=start_tshark_command,
                                   ssh_user=ssh_user,
                                   ssh_password=ssh_password,
                                   ssh_pkey=ssh_private_key,
                                   ssh_host=test_ip_address,
                                   need_output=False)

        if test_os == 'linux':
            sleep(1)
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
        # endregion

        # region Send ARP packets
        base.print_info('Send ARP packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        sleep(1)
        arp_packet: bytes = arp.make_response(ethernet_src_mac=your_mac_address,
                                              ethernet_dst_mac=test_mac_address,
                                              sender_mac=your_mac_address,
                                              sender_ip=gateway_ip_address,
                                              target_mac=test_mac_address,
                                              target_ip=test_ip_address)
        for _ in range(10):
            raw_socket.send(arp_packet)
        # endregion

        # region Send DHCPv4 packets
        base.print_info('Send DHCPv4 packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        sleep(1)
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
        for _ in range(10):
            raw_socket.send(discover_packet)
            raw_socket.send(offer_packet)
            raw_socket.send(request_packet)
            raw_socket.send(ack_packet)
        # endregion

        # region Send ICMPv6 packets
        base.print_info('Send ICMPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')
        sleep(1)
        rs_packet: bytes = icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                             ethernet_dst_mac='33:33:00:00:00:02',
                                                             ipv6_src=your_ipv6_address,
                                                             ipv6_dst='ff02::2')
        ra_packet: bytes = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                   ethernet_dst_mac='33:33:00:00:00:01',
                                                                   ipv6_src=your_ipv6_address,
                                                                   ipv6_dst='ff02::1',
                                                                   dns_address=your_ipv6_address,
                                                                   prefix='fd00::/64')
        ns_packet: bytes = icmpv6.make_neighbor_solicitation_packet(ethernet_src_mac=your_mac_address,
                                                                    ethernet_dst_mac=test_mac_address,
                                                                    ipv6_src=your_ipv6_address,
                                                                    ipv6_dst=test_ipv6_address,
                                                                    icmpv6_target_ipv6_address=test_ipv6_address,
                                                                    icmpv6_source_mac_address=your_mac_address)
        na_packet: bytes = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                     ethernet_dst_mac=test_mac_address,
                                                                     ipv6_src=your_ipv6_address,
                                                                     ipv6_dst=test_ipv6_address,
                                                                     target_ipv6_address=your_ipv6_address)
        for _ in range(10):
            raw_socket.send(rs_packet)
            raw_socket.send(ra_packet)
            raw_socket.send(ns_packet)
            raw_socket.send(na_packet)
        # endregion

        # region Send DHCPv6 packets
        base.print_info('Send DHCPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')
        sleep(1)
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
        for _ in range(10):
            raw_socket.send(solicit_packet)
            raw_socket.send(advertise_packet)
            raw_socket.send(request_packet)
            raw_socket.send(reply_packet)
        # endregion

        # region Stop tshark on test host
        if test_os == 'linux' or test_os == 'macos':
            stop_tshark_command: str = 'pkill tshark'
        else:
            stop_tshark_command: str = 'taskkill /IM "tshark.exe" /F'
        base.print_info('Stop tshark in test host')
        base.exec_command_over_ssh(command=stop_tshark_command,
                                   ssh_user=ssh_user,
                                   ssh_password=ssh_password,
                                   ssh_pkey=ssh_private_key,
                                   ssh_host=test_ip_address,
                                   need_output=False)
        # endregion

        # region Download and analyze pcap file from test host
        pcap_file: str = '/tmp/spoofing.pcap'
        if isfile(pcap_file):
            remove(pcap_file)
        base.print_info('Download pcap file with test traffic over SSH to: ', pcap_file)
        sleep(3)
        if test_os == 'windows':
            base.download_file_over_ssh(remote_path='C:\Windows\Temp\spoofing.pcap',
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
        assert isfile(pcap_file), 'Can not download pcap file with test traffic over SSH'
        # endregion

        # region Analyze pcap file from test host
        base.print_info('Analyze pcap file:')

        sniff_arp_spoof_packets: bool = False

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
                            packet[IPv6].src == your_ipv6_address and \
                            packet[IPv6].dst == 'ff02::2' and \
                            packet[ICMPv6ND_RS].type == 133:
                        sniff_icmpv6_rs_packets = True

                if packet.haslayer(ICMPv6ND_RA):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == '33:33:00:00:00:01' and \
                            packet[IPv6].src == your_ipv6_address and \
                            packet[IPv6].dst == 'ff02::1' and \
                            packet[ICMPv6ND_RA].type == 134:
                        sniff_icmpv6_ra_packets = True

                if packet.haslayer(ICMPv6ND_NS):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[IPv6].src == your_ipv6_address and \
                            packet[IPv6].dst == test_ipv6_address and \
                            packet[ICMPv6ND_NS].type == 135 and \
                            packet[ICMPv6ND_NS].tgt == test_ipv6_address:
                        sniff_icmpv6_ns_packets = True

                if packet.haslayer(ICMPv6ND_NA):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[IPv6].src == your_ipv6_address and \
                            packet[IPv6].dst == test_ipv6_address and \
                            packet[ICMPv6ND_NA].type == 136 and \
                            packet[ICMPv6ND_NA].tgt == your_ipv6_address:
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
