#!/usr/bin/env python

from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(abspath(__file__))))

from base import Base
from network import IP_raw, TCP_raw
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL
from random import randint
from time import sleep
from tm import ThreadManager
from scapy.all import sniff, TCP

Base.check_platform()
Base.check_user()

current_network_interface = None
your_ip_address = None
your_port = None
target_ip_address = ""
target_port = None
tm = ThreadManager(3)

response_sequence_number = 0
response_acknowledgement_number = 0
response_timestamp = 0
response_payload_len = 0


def sender():
    sleep(2)

    SOCK = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    SOCK.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    sequence = randint(1, 1000000)

    syn_header = tcp.make_syn_header(your_ip_address, target_ip_address, your_port, target_port, sequence)
    ip_header = ip.make_header(your_ip_address, target_ip_address, 0, len(syn_header), 6)
    syn_packet = ip_header + syn_header

    SOCK.sendto(syn_packet, (target_ip_address, target_port))

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
    ack_header = tcp.make_ack_header(your_ip_address, target_ip_address, your_port, target_port,
                                     sequence, acknowledgment, response_timestamp)
    ip_header = ip.make_header(your_ip_address, target_ip_address, 0, len(ack_header), 6)
    ack_packet = ip_header + ack_header
    SOCK.sendto(ack_packet, (target_ip_address, target_port))

    data = "GET / HTTP/1.1\r\nHost: 192.168.0.154\r\nConnection: Keep-Alive\r\n\r\n"
    psh_header = tcp.make_psh_header(your_ip_address, target_ip_address, your_port, target_port,
                                     sequence, acknowledgment, response_timestamp, data)
    ip_header = ip.make_header(your_ip_address, target_ip_address, len(data), len(psh_header), 6)
    psh_packet = ip_header + psh_header + data
    SOCK.sendto(psh_packet, (target_ip_address, target_port))

    SOCK.close()


def get_syn_and_ack_numbers(request):
    global response_sequence_number
    global response_acknowledgement_number
    global response_timestamp
    global response_payload_len

    if request.haslayer(TCP):
        response_sequence_number = request[TCP].seq
        response_acknowledgement_number = request[TCP].ack
        response_timestamp = request[TCP].time
        response_payload_len += len(request[TCP].payload)

        print "Response TCP sequence number: " + str(response_sequence_number)
        print "Response TCP acknowledgement number: " + str(response_acknowledgement_number)
        print "Response TCP option timestamp: " + str(response_timestamp)
        print "Response TCP payload length: " + str(len(request[TCP].payload))


if __name__ == "__main__":

    parser = ArgumentParser(description='TCP packets sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send TCP packets')
    parser.add_argument('-t', '--target_ip', type=str, required=True, help='Set target IP address')
    parser.add_argument('-p', '--target_port', type=int, required=True, help='Set target port')

    args = parser.parse_args()

    ip = IP_raw()
    tcp = TCP_raw()

    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    your_ip_address = Base.get_netiface_ip_address(current_network_interface)
    your_port = randint(2048, 65535)

    target_ip_address = args.target_ip
    target_port = args.target_port

    tm.add_task(sender)

    print "Waiting for TCP connection from " + target_ip_address + " ..."
    sniff(filter="tcp and src host " + target_ip_address + " and src port " + str(target_port) +
                 " and dst host " + your_ip_address + " and dst port " + str(your_port),
          prn=get_syn_and_ack_numbers, iface=current_network_interface)

