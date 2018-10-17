#!/usr/bin/env python

# region Import
from json import dumps
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from network import Ethernet_raw, ARP_raw, IP_raw, IPv6_raw, UDP_raw, DHCP_raw, DNS_raw
from socket import socket, AF_PACKET, SOCK_RAW, htons
# endregion

# region Main function
if __name__ == "__main__":

    # region Local variables
    Base = Base()

    eth = Ethernet_raw()
    arp = ARP_raw()

    ip = IP_raw()
    ipv6 = IPv6_raw()

    udp = UDP_raw()

    dhcp = DHCP_raw()
    dns = DNS_raw()

    ethernet_header_length = 14
    arp_packet_length = 28
    udp_header_length = 8
    # endregion

    # region Create RAW socket for sniffing
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    # endregion

    # region Print info message
    Base.print_info("Available protocols: ", "Ethernet ARP IP UDP DHCP DNS")
    Base.print_info("Start test sniffing ...")
    # endregion

    # region Start sniffing
    while True:

        # region Try
        try:
            # region Sniff packets from RAW socket
            packets = raw_socket.recvfrom(2048)

            for packet in packets:

                # region Parse Ethernet header
                ethernet_header = packet[0:ethernet_header_length]
                ethernet_header_dict = eth.parse_header(ethernet_header)
                # endregion

                # region Could not parse Ethernet header - break
                if ethernet_header_dict is None:
                    break
                # endregion

                # region ARP packet

                # 2054 - Type of ARP packet (0x0806)
                if ethernet_header_dict['type'] == 2054:

                    # region Parse ARP packet
                    arp_header = packet[ethernet_header_length:ethernet_header_length + arp_packet_length]
                    arp_packet_dict = arp.parse_packet(arp_header)
                    # endregion

                    # region Could not parse ARP packet - break
                    if arp_packet_dict is None:
                        break
                    # endregion

                    # region Make full ARP packet
                    full_arp_packet = {
                        'Ethernet': ethernet_header_dict,
                        'ARP': arp_packet_dict
                    }
                    # endregion

                    # region Print full ARP packet
                    print("\n")
                    Base.print_info("ARP packet from: ", ethernet_header_dict['source'])
                    print(dumps(full_arp_packet, indent=4))
                    # endregion

                # endregion

                # region IP packet

                # 2048 - Type of IP packet (0x0800)
                if ethernet_header_dict['type'] == 2048:

                    # region Parse IP header
                    ip_header = packet[ethernet_header_length:]
                    ip_header_dict = ip.parse_header(ip_header)
                    # endregion

                    # region Could not parse IP header - break
                    if ip_header_dict is None:
                        break
                    # endregion

                    # region UDP
                    if ip_header_dict['protocol'] == 17:

                        # region Parse UDP header
                        udp_header_offset = ethernet_header_length + (ip_header_dict['length'] * 4)
                        udp_header = packet[udp_header_offset:udp_header_offset + udp_header_length]
                        udp_header_dict = udp.parse_header(udp_header)
                        # endregion

                        # region Could not parse UDP header - break
                        if udp_header is None:
                            break
                        # endregion

                        # region DHCP packet
                        if udp_header_dict['source-port'] == 68 and udp_header_dict['destination-port'] == 67:

                            # region Parse DHCP packet
                            dhcp_packet_offset = udp_header_offset + udp_header_length
                            dhcp_packet = packet[dhcp_packet_offset:]
                            dhcp_packet_dict = dhcp.parse_packet(dhcp_packet)
                            # endregion

                            # region Could not parse DHCP packet - break
                            if dhcp_packet_dict is None:
                                break
                            # endregion

                            # region Make full DHCP packet
                            full_dhcp_packet = {
                                'Ethernet': ethernet_header_dict,
                                'IP': ip_header_dict,
                                'UDP': udp_header_dict
                            }
                            full_dhcp_packet.update(dhcp_packet_dict)
                            # endregion

                            # region Print full DHCP packet
                            print("\n")
                            Base.print_info("DHCP packet from: ", ethernet_header_dict['source'])
                            print(dumps(full_dhcp_packet, indent=4))
                            # endregion

                        # endregion

                        # region DNS packet
                        if udp_header_dict['destination-port'] == 53:

                            # region Parse DNS request packet
                            dns_packet_offset = udp_header_offset + udp_header_length
                            dns_packet = packet[dns_packet_offset:]
                            dns_packet_dict = dns.parse_request_packet(dns_packet)
                            # endregion

                            # region Could not parse DNS request packet - break
                            if dns_packet_dict is None:
                                break
                            # endregion

                            # region Make full DHCP packet
                            full_dns_packet = {
                                "Ethernet": ethernet_header_dict,
                                "IP": ip_header_dict,
                                "UDP": udp_header_dict,
                                "DNS": dns_packet_dict
                            }
                            # endregion

                            # region Print full DNS packet
                            print("\n")
                            Base.print_info("DNS packet from: ", ethernet_header_dict['source'])
                            print(dumps(full_dns_packet, indent=4))
                            # endregion

                        # endregion

                    # endregion

                # endregion

            # endregion

        # endregion

        # region Exception - KeyboardInterrupt
        except KeyboardInterrupt:
            Base.print_info("Exit")
            exit(0)
        # endregion

    # endregion

# endregion
