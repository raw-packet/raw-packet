#!/usr/bin/env python

from raw_packet.Utils.base import Base
from raw_packet.Utils.network import IP_raw, TCP_raw, Ethernet_raw, ARP_raw
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from random import randint
from time import sleep
from raw_packet.Utils.tm import ThreadManager
from scapy.all import sniff, TCP, ARP

Base = Base()
Base.check_platform()
Base.check_user()

current_network_interface = None

src_mac_address = None
src_ip_address = None
src_port = None

dst_mac_address = None
dst_ip_address = None
dst_port = None

data = None

tm = ThreadManager(3)

response_sequence_number = 0
response_acknowledgement_number = 0
response_timestamp = 0
response_payload_len = 0


def sender():
    sleep(5)

    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    sequence = randint(1, 1000000)

    syn_header = tcp.make_syn_header(src_ip_address, dst_ip_address, src_port, dst_port, sequence)
    ip_header = ip.make_header(src_ip_address, dst_ip_address, 0, len(syn_header), 6)
    eth_header = eth.make_header(src_mac_address, dst_mac_address, 2048)
    syn_packet = eth_header + ip_header + syn_header

    SOCK.send(syn_packet)

    while True:
        if response_sequence_number == 0:
            sleep(1)
        else:
            if response_acknowledgement_number == sequence + 1:
                break
            else:
                sleep(1)

    sequence += 1
    acknowledgment = response_sequence_number + 1
    ack_header = tcp.make_ack_header(src_ip_address, dst_ip_address, src_port, dst_port,
                                     sequence, acknowledgment, response_timestamp)
    ip_header = ip.make_header(src_ip_address, dst_ip_address, 0, len(ack_header), 6)
    eth_header = eth.make_header(src_mac_address, dst_mac_address, 2048)
    ack_packet = eth_header + ip_header + ack_header
    SOCK.send(ack_packet)

    psh_header = tcp.make_psh_header(src_ip_address, dst_ip_address, src_port, dst_port,
                                     sequence, acknowledgment, response_timestamp, data)
    ip_header = ip.make_header(src_ip_address, dst_ip_address, len(data), len(psh_header), 6)
    eth_header = eth.make_header(src_mac_address, dst_mac_address, 2048)
    psh_packet = eth_header + ip_header + psh_header + data
    SOCK.send(psh_packet)

    SOCK.close()


def arp_reply(your_mac_address, your_ip_address, target_mac_address, target_ip_address):
    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))
    arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                  ethernet_dst_mac=target_mac_address,
                                  sender_mac=your_mac_address, sender_ip=your_ip_address,
                                  target_mac=target_mac_address, target_ip=target_ip_address)
    SOCK.send(arp_reply)
    SOCK.close()


def get_syn_and_ack_numbers(request):
    global src_ip_address
    global response_sequence_number
    global response_acknowledgement_number
    global response_timestamp
    global response_payload_len

    if request.haslayer(TCP):
        response_sequence_number = request[TCP].seq
        response_acknowledgement_number = request[TCP].ack
        response_timestamp = request[TCP].time
        response_payload_len += len(request[TCP].payload)

        print Base.c_success + "Response seq: " + str(response_sequence_number) + " ack: " + \
              str(response_acknowledgement_number) + " timestamp: " + str(response_timestamp) + " len: " + \
              str(len(request[TCP].payload))

    if request.haslayer(ARP):
        if request[ARP].op == 1:
            if request[ARP].pdst == src_ip_address:
                arp_reply(src_mac_address, request[ARP].pdst, request[ARP].hwsrc, request[ARP].psrc)


if __name__ == "__main__":

    parser = ArgumentParser(description='TCP packets sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send TCP packets')

    parser.add_argument('-m', '--src_mac', type=str, help='Set src mac address (not required)', default=None)
    parser.add_argument('-a', '--src_ip', type=str, help='Set src ip address (not required)', default=None)
    parser.add_argument('-p', '--src_port', type=int, help='Set src port (not required)', default=None)

    parser.add_argument('-M', '--target_mac', type=str, help='Set dst mac address (not required)', default=None)
    parser.add_argument('-A', '--target_ip', type=str, required=True, help='Set target IP address')
    parser.add_argument('-P', '--target_port', type=int, required=True, help='Set target port')

    parser.add_argument('-d', '--data', type=str, help='Set TCP payload data (default="GET / HTTP/1.1\\r\\n\\r\\n")',
                        default="GET / HTTP/1.0\r\n\r\n")

    args = parser.parse_args()

    ip = IP_raw()
    tcp = TCP_raw()
    eth = Ethernet_raw()
    arp = ARP_raw()

    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    if args.src_mac is None:
        src_mac_address = Base.get_netiface_mac_address(current_network_interface)
    else:
        src_mac_address = args.src_mac

    if args.src_ip is None:
        src_ip_address = Base.get_netiface_ip_address(current_network_interface)
    else:
        src_ip_address = args.src_ip

    if args.src_port is None:
        src_port = randint(1024, 65535)
    else:
        src_port = args.src_port

    dst_ip_address = args.target_ip

    if args.target_mac is None:
        dst_mac_address = Base.get_mac(current_network_interface, dst_ip_address)

    dst_port = args.target_port

    data = args.data

    print Base.c_info + "Interface: " + current_network_interface
    print Base.c_info + "Src MAC:   " + src_mac_address
    print Base.c_info + "Src IP:    " + src_ip_address
    print Base.c_info + "Src PORT:  " + str(src_port)
    print Base.c_info + "Dst MAC:   " + dst_mac_address
    print Base.c_info + "Dst IP:    " + dst_ip_address
    print Base.c_info + "Dst PORT:  " + str(dst_port)

    tm.add_task(sender)

    print Base.c_info + "Waiting for TCP connection from " + dst_ip_address + " or ARP ... "
    sniff(filter="(tcp and src host " + dst_ip_address + " and src port " + str(dst_port) +
                 " and dst host " + src_ip_address + " and dst port " + str(src_port) + ") or arp",
          prn=get_syn_and_ack_numbers, iface=current_network_interface)

