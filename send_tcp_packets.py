from base import Base
from network import IP_raw, TCP_raw
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL
from random import randint
from os import system
from struct import unpack


if __name__ == "__main__":

    Base.check_platform()
    Base.check_user()

    NAMES = []
    PACKETS = []

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

    drop_rst_packets_command = "iptables -I OUTPUT -p tcp --tcp-flags RST RST -d " + \
                               target_ip_address + " --dport " + str(target_port) + " -j DROP"
    system(drop_rst_packets_command)

    SOCK = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    SOCK.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    sequence = randint(1, 4294967295)
    syn_header = tcp.make_syn_header(your_ip_address, target_ip_address, your_port, target_port, sequence)
    ip_header = ip.make_header(your_ip_address, target_ip_address, 0, len(syn_header), 6)
    syn_packet = ip_header + syn_header

    SOCK.sendto(syn_packet, (target_ip_address, target_port))

    response = SOCK.recv(60)
    response_sequence = response[24:28]
    response_options = response[40:]
    response_tsecr = 0

    print "Response TCP sequence: " + str(response_sequence)
    print "Response TCP options: " + str(response_options)

    sequence += 1
    acknowledgment = unpack(">L", response_sequence)[0]
    acknowledgment += 1

    if len(response_options) > 10:
        timestamp_position = response_options.find('\x08\x0a')
        if timestamp_position > 0:
            response_tsecr_str = response_options[timestamp_position+2:timestamp_position+6]
            response_tsecr = unpack(">L", response_tsecr_str)[0]

    ack_header = tcp.make_ack_header(your_ip_address, target_ip_address, your_port, target_port,
                                     sequence, acknowledgment, response_tsecr)
    ip_header = ip.make_header(your_ip_address, target_ip_address, 0, len(ack_header), 6)
    ack_packet = ip_header + ack_header
    SOCK.sendto(ack_packet, (target_ip_address, target_port))

    data = "GET / HTTP/1.1\r\n\r\n"

    psh_header = tcp.make_psh_header(your_ip_address, target_ip_address, your_port, target_port,
                                     sequence, acknowledgment, response_tsecr)
    ip_header = ip.make_header(your_ip_address, target_ip_address, len(data), len(psh_header), 6)
    psh_packet = ip_header + psh_header + data
    SOCK.sendto(psh_packet, (target_ip_address, target_port))

    # sequence += len(data)
    # psh_packet = ip_header + tcp.make_psh_packet(your_ip_address, target_ip_address, your_port, target_port,
    #                                              sequence, acknowledgment, "")
    # SOCK.sendto(psh_packet, (target_ip_address, target_port))

    SOCK.close()

    iptables_flush_rules = "iptables -F; iptables -X;"
    system(iptables_flush_rules)

