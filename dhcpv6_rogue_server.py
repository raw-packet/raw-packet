#!/usr/bin/env python

from base import Base
from network import DHCPv6_raw
from sys import exit
from argparse import ArgumentParser
from ipaddress import IPv6Address
from scapy.all import sniff, ICMPv6, DHCPv6
from socket import socket, AF_PACKET, SOCK_RAW, inet_aton
from base64 import b64encode
from struct import pack
from netaddr import IPAddress
from tm import ThreadManager
from time import sleep

current_network_interface = None
target_mac_address = None
target_ip_address = None
recursive_dns_address = None

Base = Base()
Base.check_user()
Base.check_platform()

tm = ThreadManager(3)

parser = ArgumentParser(description='DHCPv6 Rogue server')

parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
parser.add_argument('-p', '--prefix', type=str, help='Set network prefix', default='fd00::/64')
parser.add_argument('-f', '--first_suffix_ip', type=str, help='Set first suffix client ip for offering', default='2')
parser.add_argument('-l', '--last_suffix_ip', type=str, help='Set last suffix client ip for offering', default='ff')
parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
parser.add_argument('-I', '--target_ip', type=str, help='Set client IPv6 address with MAC in --target_mac', default=None)
parser.add_argument('-d', '--dns', type=str, help='Set recursive DNS IPv6 address', default=None)
parser.add_argument('-s', '--dns_search', type=str, help='Set DNS search list', default="test.com")
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
parser.add_argument('--apple', action='store_true', help='Apple devices MiTM')
args = parser.parse_args()

if not args.quiet:
    Base.print_banner()

dhcpv6 = DHCPv6_raw()

if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

if args.target_mac is not None:
    target_mac_address = str(args.target_mac).lower()

if args.target_ip is not None:
    target_ip_address = args.target_ip

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_ipv6_link_address = Base.get_netiface_ipv6_link_address(current_network_interface)
if your_ipv6_link_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IPv6 link local address!"
    exit(1)

if args.dns is None:
    recursive_dns_address = your_ipv6_link_address
else:
    recursive_dns_address = args.dns

if not args.quiet:
    print Base.c_info + "Network interface: " + Base.cINFO + current_network_interface + Base.cEND
    if args.target_mac is not None:
        print Base.c_info + "Target MAC: " + Base.cINFO + args.target_mac + Base.cEND
    if args.target_ip is not None:
        print Base.c_info + "Target IP: " + Base.cINFO + args.target_ip + Base.cEND
    else:
        print Base.c_info + "First suffix offer IP: " + Base.cINFO + args.first_suffix_ip + Base.cEND
        print Base.c_info + "Last suffix offer IP: " + Base.cINFO + args.last_suffix_ip + Base.cEND
    print Base.c_info + "Prefix: " + Base.cINFO + args.prefix + Base.cEND
    print Base.c_info + "Router IPv6 address: " + Base.cINFO + your_ipv6_link_address + Base.cEND
    print Base.c_info + "DNS IPv6 address: " + Base.cINFO + recursive_dns_address + Base.cEND


def reply(request):

    # ICMPv6 REQUESTS
    if request.haslayer(ICMPv6):
        print "ICMPv6 request!"

    # DHCPv6 REQUESTS
    if request.haslayer(DHCPv6):
        print "DHCPv6 request!"


if __name__ == "__main__":
    if args.target_ip is not None:
        if args.target_mac is None:
            print Base.c_error + "Please set target MAC address (--target_mac 00:AA:BB:CC:DD:FF) for target IPv6!"
            exit(1)
    else:
        if args.target_mac is None:
            print Base.c_info + "Waiting for a ICMPv6 or DHCPv6 requests ..."
            sniff(lfilter=lambda d: d.src != your_mac_address,
                  filter="icmpv6 or dhcpv6",
                  prn=reply, iface=current_network_interface)
        else:
            print Base.c_info + "Waiting for a ICMPv6 or DHCPv6 requests from: " + args.target_mac + " ..."
            sniff(lfilter=lambda d: d.src == args.target_mac,
                  filter="icmpv6 or dhcpv6",
                  prn=reply, iface=current_network_interface)
