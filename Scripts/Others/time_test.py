#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
time_test.py:
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
from raw_packet.Utils.network import ARP_raw, DHCP_raw, DNS_raw
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP, DNS, DNSQR, sendp
from socket import socket, AF_PACKET, SOCK_RAW
from time import time
from prettytable import PrettyTable
from random import randint
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
__status__ = 'Development'
# endregion

# region Global variables
arp = ARP_raw()
dhcp = DHCP_raw()
dns = DNS_raw()

network_interface = "eth0"
ethernet_src = "00:0c:29:4f:e6:9c"
ethernet_dst = "00:50:56:c0:00:01"
ip_src = "192.168.119.139"
ip_dst = "192.168.119.1"

global_socket = socket(AF_PACKET, SOCK_RAW)
global_socket.bind((network_interface, 0))

execution_time = {}
# endregion


# region Send ARP packets in raw-packet
def raw_packet_send_arp_requests(number_of_packets):
    for _ in range(number_of_packets):
        arp_request = arp.make_request(ethernet_src_mac=ethernet_src,
                                       ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                                       sender_mac=ethernet_src,
                                       sender_ip=ip_src,
                                       target_mac="00:00:00:00:00:00",
                                       target_ip=ip_dst)
        global_socket.send(arp_request)
# endregion


# region Send ARP packets in scapy
def scapy_send_arp_requests(number_of_packets):
    arp_request = Ether(src=ethernet_src, dst='ff:ff:ff:ff:ff:ff') /\
                  ARP(op=1, hwsrc=ethernet_src, hwdst='00:00:00:00:00:00', psrc=ip_src, pdst=ip_dst)
    sendp(arp_request, count=number_of_packets, verbose=False)
# endregion


# region Send DHCP Discover packets in raw-packet
def raw_packet_send_dhcp_discover_requests(number_of_packets):
    for _ in range(number_of_packets):
        dhcp_discover_request = dhcp.make_discover_packet(ethernet_src_mac=ethernet_src,
                                                          ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                                                          ip_src="0.0.0.0", ip_dst="255.255.255.255",
                                                          udp_src_port=68, udp_dst_port=67,
                                                          transaction_id=randint(1, 4294967295),
                                                          client_mac=ethernet_src,
                                                          host_name="time_test")
        global_socket.send(dhcp_discover_request)
# endregion


# region Send DHCP Discover packets in scapy
def scapy_send_dhcp_discover_requests(number_of_packets):
    for _ in range(number_of_packets):
        dhcp_discover_request = Ether(src=ethernet_src, dst='ff:ff:ff:ff:ff:ff') /\
                                IP(src='0.0.0.0', dst='255.255.255.255') /\
                                UDP(dport=67, sport=68) /\
                                BOOTP(chaddr=ethernet_src, xid=randint(1, 4294967295)) /\
                                DHCP(options=[('message-type', 'discover'), 'end'])
        sendp(dhcp_discover_request, verbose=False)
# endregion


# region Send DNS Request packets in raw-packet
def raw_packet_send_dns_requests(number_of_packets):
    for _ in range(number_of_packets):
        dns_request = dns.make_a_query(src_mac=ethernet_src, dst_mac=ethernet_dst,
                                       src_ip=ip_src, dst_ip=ip_dst,
                                       src_port=randint(1024, 65535), dst_port=53,
                                       tid=randint(1, 1000), names=['www.' + str(randint(1, 1000)) + '.com'])
        global_socket.send(dns_request)
# endregion


# region Send DNS Request packets in scapy
def scapy_send_dns_requests(number_of_packets):
    for _ in range(number_of_packets):
        dns_request = Ether(src=ethernet_src, dst=ethernet_dst) /\
                      IP(src=ip_src, dst=ip_dst) /\
                      UDP(dport=53, sport=randint(1024, 65535)) /\
                      DNS(id=randint(1, 1000), rd=1, qd=DNSQR(qname="www." + str(randint(1, 1000)) + ".com"))
        sendp(dns_request, verbose=False)
# endregion


# region Main function
if __name__ == "__main__":
    Base = Base()

    execution_time['ARP requests'] = {}
    execution_time['ARP requests']['Scapy'] = {}
    execution_time['ARP requests']['Raw-packet'] = {}

    execution_time['DHCP discover requests'] = {}
    execution_time['DHCP discover requests']['Scapy'] = {}
    execution_time['DHCP discover requests']['Raw-packet'] = {}

    execution_time['DNS requests'] = {}
    execution_time['DNS requests']['Scapy'] = {}
    execution_time['DNS requests']['Raw-packet'] = {}

    for number_of_packets in 10, 100, 1000, 10000:

        scapy_start_time = time()
        scapy_send_arp_requests(number_of_packets)
        scapy_execution_time = (time() - scapy_start_time)

        raw_packet_start_time = time()
        raw_packet_send_arp_requests(number_of_packets)
        raw_packet_execution_time = (time() - raw_packet_start_time)

        execution_time['ARP requests']['Scapy'][number_of_packets] = scapy_execution_time
        execution_time['ARP requests']['Raw-packet'][number_of_packets] = raw_packet_execution_time

        if number_of_packets <= 1000:
            scapy_start_time = time()
            scapy_send_dhcp_discover_requests(number_of_packets)
            scapy_execution_time = (time() - scapy_start_time)

            raw_packet_start_time = time()
            raw_packet_send_dhcp_discover_requests(number_of_packets)
            raw_packet_execution_time = (time() - raw_packet_start_time)

            execution_time['DHCP discover requests']['Scapy'][number_of_packets] = scapy_execution_time
            execution_time['DHCP discover requests']['Raw-packet'][number_of_packets] = raw_packet_execution_time

            scapy_start_time = time()
            scapy_send_dns_requests(number_of_packets)
            scapy_execution_time = (time() - scapy_start_time)

            raw_packet_start_time = time()
            raw_packet_send_dns_requests(number_of_packets)
            raw_packet_execution_time = (time() - raw_packet_start_time)

            execution_time['DNS requests']['Scapy'][number_of_packets] = scapy_execution_time
            execution_time['DNS requests']['Raw-packet'][number_of_packets] = raw_packet_execution_time

        else:
            execution_time['DHCP discover requests']['Scapy'][number_of_packets] = "-"
            execution_time['DHCP discover requests']['Raw-packet'][number_of_packets] = "-"

            execution_time['DNS requests']['Scapy'][number_of_packets] = "-"
            execution_time['DNS requests']['Raw-packet'][number_of_packets] = "-"

    pretty_table = PrettyTable([Base.cINFO + 'Number of packets' + Base.cEND,
                                Base.cINFO + '10' + Base.cEND,
                                Base.cINFO + '100' + Base.cEND,
                                Base.cINFO + '1000' + Base.cEND,
                                Base.cINFO + '10000' + Base.cEND])

    for test_name in execution_time:
        for program_name in execution_time[test_name]:
            pretty_table.add_row(
                    [Base.cINFO + test_name + ' in ' + program_name + Base.cEND,
                     execution_time[test_name][program_name][10],
                     execution_time[test_name][program_name][100],
                     execution_time[test_name][program_name][1000],
                     execution_time[test_name][program_name][10000]])

    print(pretty_table)
    global_socket.close()
# endregion
