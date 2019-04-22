#!/usr/bin/env python

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Ethernet_raw, ARP_raw
from argparse import ArgumentParser
from time import sleep
from socket import socket, AF_PACKET, SOCK_RAW
from ipaddress import IPv4Address
# endregion

# region Check user, platform and print banner
Base = Base()
Base.check_platform()
Base.check_user()
Base.print_banner()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='ARP reply sender')

parser.add_argument('-i', '--interface', type=str, help='Set interface name for send reply packets')
parser.add_argument('-c', '--count', type=int, help='Set count of ARP replies', default=None)
parser.add_argument('-d', '--delay', type=float, help='Set delay between packets (default: 0.5)', default=0.5)

parser.add_argument('-t', '--target_mac', type=str, help='Set target client mac address')
parser.add_argument('-T', '--target_ip', type=str, required=True, help='Set target client ip address (required)')
parser.add_argument('-s', '--sender_mac', type=str, help='Set sender mac address, if not set use random mac')
parser.add_argument('-S', '--sender_ip', type=str, required=True, help='Set sender IP address (required)')

args = parser.parse_args()
# endregion

# region Set global variables
current_network_interface = None
sender_mac_address = None
target_mac_address = None

eth = Ethernet_raw()
arp = ARP_raw()
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for send ARP reply packets ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
    exit(1)
# endregion

# region Set target and sender MAC address
if args.target_mac is None:
    target_mac_address = Base.get_mac(current_network_interface, args.target_ip)
else:
    target_mac_address = args.target_mac

if args.sender_mac is None:
    sender_mac_address = your_mac_address
else:
    sender_mac_address = args.sender_mac
# endregion

# region Validate target and sender IP address
first_ip_address = str(IPv4Address(unicode(Base.get_netiface_first_ip(current_network_interface))) - 1)
last_ip_address = str(IPv4Address(unicode(Base.get_netiface_last_ip(current_network_interface))) + 1)

if not Base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address):
    Base.print_error("Bad value `-T, --target_ip`: ", args.target_ip,
                     "; Target IP address must be in range: ", first_ip_address + " - " + last_ip_address)
    exit(1)

if not Base.ip_address_in_range(args.sender_ip, first_ip_address, last_ip_address):
    Base.print_error("Bad value `-S, --sender_ip`: ", args.target_ip,
                     "; Sender IP address must be in range: ", first_ip_address + " - " + last_ip_address)
    exit(1)
# endregion


# region Main function
if __name__ == "__main__":

    # region Create Raw socket
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))
    # endregion

    # region Send ARP reply packets
    try:

        # region Make ARP reply packet
        arp_reply_packet = arp.make_response(ethernet_src_mac=sender_mac_address,
                                             ethernet_dst_mac=target_mac_address,
                                             sender_mac=sender_mac_address,
                                             sender_ip=args.sender_ip,
                                             target_mac=target_mac_address,
                                             target_ip=args.target_ip)
        # endregion

        # region Set count of packets
        if args.count is None:
            count_of_packets = 1000000000
        else:
            count_of_packets = int(args.count)
        # endregion

        # region General output
        Base.print_info("Network interface: ", current_network_interface)
        Base.print_info("Target mac address: ", target_mac_address)
        Base.print_info("Target IP address: ", args.target_ip)
        Base.print_info("Sender mac address: ", sender_mac_address)
        Base.print_info("Sender IP address: ", args.sender_ip)
        Base.print_info("Count of packets: ", str(count_of_packets))
        Base.print_info("Delay between packets: ", str(args.delay))
        # endregion

        # region Sending ARP reply packets
        Base.print_info("Sending ARP reply packets ...")
        for _ in range(count_of_packets):
            SOCK.send(arp_reply_packet)
            sleep(float(args.delay))
        # endregion

        # region Close socket end exit
        SOCK.close()
        Base.print_info("All ARP reply packets have been sent.")
        exit(0)
        # endregion

    except KeyboardInterrupt:

        # region Close socket end exit
        if SOCK is not None:
            SOCK.close()
        Base.print_info("Exit")
        exit(0)
        # endregion

    # endregion

# endregion
