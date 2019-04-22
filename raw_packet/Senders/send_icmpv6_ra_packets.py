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

    parser = ArgumentParser(description='ICMPv6 router advertisement packets sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send TCP packets')

    parser.add_argument('-m', '--src_mac', type=str, help='Set src mac address (not required)', default=None)
    parser.add_argument('-M', '--dst_mac', type=str, help='Set dst mac address (not required)', default=None)
    parser.add_argument('-a', '--src_ipv6', type=str, help='Set src ipv6 address (not required)', default=None)
    parser.add_argument('-A', '--dst_ipv6', type=str, help='Set dst ipv6 address (not required)', default=None)

    parser.add_argument('-d', '--dns', type=str, help='Set DNS IPv6 address (not required)', default=None)
    parser.add_argument('-D', '--domain', type=str, help='Set domain search (default: test.com)', default="test.com")
    parser.add_argument('-P', '--prefix', type=str, help='Set network prefix (default: fd00::/64)', default="fd00::/64")

    parser.add_argument('-p', '--number_of_packets', type=int, help='Set number of packets (default=100000)', default=100000)
    parser.add_argument('-t', '--number_of_iterations', type=int, help='Set number of iteration (default=100)', default=100)

    args = parser.parse_args()
    icmpv6 = ICMPv6_raw()
    eth = Ethernet_raw()
    ra_packets = []

    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    if args.src_mac is None:
        src_mac_address = Base.get_netiface_mac_address(current_network_interface)
        if src_mac_address is None:
            print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
            exit(1)
    else:
        src_mac_address = args.src_mac

    if args.dst_mac is None:
        dst_mac_address = "33:33:00:00:00:01"  # IPv6mcast
    else:
        dst_mac_address = args.dst_mac

    if args.src_ipv6 is None:
        src_ipv6_address = Base.get_netiface_ipv6_link_address(current_network_interface)
        if src_ipv6_address is None:
            print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 link local address!"
            exit(1)
    else:
        src_ipv6_address = args.src_ipv6

    if args.dst_ipv6 is None:
        dst_ipv6_address = "ff02::1"
    else:
        dst_ipv6_address = args.dst_ipv6

    if args.dns is None:
        dns_ipv6_address = Base.get_netiface_ipv6_glob_address(current_network_interface)
        if dns_ipv6_address is None:
            print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 global address!"
            exit(1)

    else:
        dns_ipv6_address = args.dns

    print Base.c_info + "Interface: " + current_network_interface
    print Base.c_info + "Src IPv6 address: " + src_ipv6_address
    print Base.c_info + "Dst IPv6 address: " + dst_ipv6_address
    print Base.c_info + "Src MAC address: " + src_mac_address
    print Base.c_info + "Dst MAC address: " + dst_mac_address
    print Base.c_info + "Prefix: " + args.domain
    print Base.c_info + "DNS IPv6 address: " + dns_ipv6_address
    print Base.c_info + "Domain search: " + args.domain
    print Base.c_info + "Sending ICMPv6 router advertisement packets ..."

    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))
    try:
        for _ in range(args.number_of_packets):
            ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=src_mac_address,
                                                                ethernet_dst_mac=dst_mac_address,
                                                                ipv6_src=src_ipv6_address,
                                                                ipv6_dst=dst_ipv6_address,
                                                                dns_address=dns_ipv6_address,
                                                                domain_search=args.domain,
                                                                prefix=args.prefix)
            ra_packets.append(ra_packet)

        for iteration in range(args.number_of_iterations):
            print Base.c_info + "Iteration: " + str(iteration)
            index = 0
            while index < args.number_of_packets:
                SOCK.send(ra_packets[index])
                index += 1
    except:
        print Base.c_error + "Do not send ICMPv6 router advertisement packets!"
        SOCK.close()
        exit(1)
    print Base.c_success + "Send all ICMPv6 router advertisement packets!"
    SOCK.close()

