#!/usr/bin/env python

from raw_packet.Utils.base import Base
from argparse import ArgumentParser
from raw_packet.Utils.network import ICMPv6_raw, Ethernet_raw
from socket import socket, AF_PACKET, SOCK_RAW
from sys import exit


Base = Base()
Base.check_platform()
Base.check_user()
Base.print_banner()

if __name__ == "__main__":

    parser = ArgumentParser(description='ICMPv6 router solicit packets sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send TCP packets')

    parser.add_argument('-m', '--src_mac', type=str, help='Set src mac address (not required)', default=None)
    parser.add_argument('-a', '--src_ipv6', type=str, help='Set src ipv6 address (not required)', default=None)
    parser.add_argument('-p', '--number_of_packets', type=int, help='Set number of packets (default=100000)', default=100000)
    parser.add_argument('-t', '--number_of_iterations', type=int, help='Set number of iteration (default=100)', default=100)

    args = parser.parse_args()
    icmpv6 = ICMPv6_raw()
    eth = Ethernet_raw()
    rs_packets = []

    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    if args.src_mac is None:
        src_mac_address = Base.get_netiface_mac_address(current_network_interface)
    else:
        src_mac_address = args.src_mac

    if args.src_ipv6 is None:
        src_ipv6_address = Base.get_netiface_ipv6_link_address(current_network_interface)
    else:
        src_ipv6_address = args.src_ipv6

    print Base.c_info + "Interface: " + current_network_interface
    print Base.c_info + "Src IPv6 address: " + src_ipv6_address
    print Base.c_info + "Src MAC address: " + src_mac_address
    print Base.c_info + "Sending ICMPv6 router solicit packets ..."

    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))
    try:
        for _ in range(args.number_of_packets):
            rs_packet = icmpv6.make_router_solicit_packet(src_mac_address, src_ipv6_address, True, eth.get_random_mac())
            rs_packets.append(rs_packet)

        for iteration in range(args.number_of_iterations):
            print Base.c_info + "Iteration: " + str(iteration)
            index = 0
            while index < args.number_of_packets:
                SOCK.send(rs_packets[index])
                index += 1
    except:
        print Base.c_error + "Do not send ICMPv6 router solicit packets!"
        SOCK.close()
        exit(1)
    print Base.c_success + "Send all ICMPv6 router solicit packets!"
    SOCK.close()

