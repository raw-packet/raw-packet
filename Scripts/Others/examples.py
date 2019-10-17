#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
examples.py: Raw-packet examples
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4, RawIPv6, RawUDP, RawDNS, RawDHCPv4
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Main function
if __name__ == "__main__":

    # region Init Raw-packet classes
    base = Base()
    eth = RawEthernet()
    arp = RawARP()
    ipv4 = RawIPv4()
    ipv6 = RawIPv6()
    udp = RawUDP()
    dns = RawDNS()
    dhcpv4 = RawDHCPv4()
    # endregion

    # region Check user, platform and print banner
    base.check_user()
    base.check_platform()
    base.print_banner()
    # endregion

    try:

        # region Create raw socket
        raw_socket = socket(AF_PACKET, SOCK_RAW)
        raw_socket.bind(('eth0', 0))
        # endregion

        # region Base functions
        print('\n')
        base.print_info('Network functions:')

        print('\nNetwork interface settings:')
        print(base.get_interface_settings('eth0'))

        print('\nMac address:')
        print(base.get_interface_mac_address('eth0', False))

        print('\nipv4 address:')
        print(base.get_interface_ip_address('eth0', False))

        print('\nipv6 link local address:')
        print(base.get_interface_ipv6_link_address('eth0', False))

        print('\nipv6 link local address by mac address:')
        print(base.make_ipv6_link_address('12:34:56:78:90:ab'))

        print('\nipv6 link global address:')
        print(base.get_interface_ipv6_glob_address('eth0'))

        print('\nipv6 global addresses:')
        print(base.get_interface_ipv6_glob_addresses('eth0'))

        print('\nNetwork mask:')
        print(base.get_interface_netmask('eth0', False))

        print('\nFirst ipv4:')
        print(base.get_first_ip_on_interface('eth0', False))

        print('\nSecond ipv4:')
        print(base.get_second_ip_on_interface('eth0', False))

        print('\nPenultimate ipv4:')
        print(base.get_penultimate_ip_on_interface('eth0', False))

        print('\nLast ipv4:')
        print(base.get_last_ip_on_interface('eth0', False))

        print('\nRandom ipv4:')
        print(base.get_random_ip_on_interface('eth0', False))

        print('\nipv4 network:')
        print(base.get_interface_network('eth0', False))

        print('\nipv4 broadcast:')
        print(base.get_interface_broadcast('eth0', False))

        print('\nipv4 gateway:')
        print(base.get_interface_ipv4_gateway('eth0', False))

        print('\nipv6 gateway:')
        print(base.get_interface_ipv6_gateway('eth0', False))

        print('\n')
        base.print_info('Software functions:')

        print('\nApt list installed software:')
        print(base.apt_list_installed_packages())

        print('\nCheck installed software: apache2')
        print(base.check_installed_software('apache2', False))

        print('\n')
        base.print_info('Process functions:')

        print('\nProcess apache2 pid:')
        print(base.get_process_pid('apache2'))

        print('\nProcess pid by listen port 80:')
        print(base.get_process_pid_by_listen_port(80))
        # endregion

        # region RawEthernet functions
        print('\n')
        base.print_info('Test network Ethernet functions:')

        print('\nConvert MAC address string to bytes:')
        print(eth.convert_mac('30:31:32:33:34:35', True))

        print('\nConvert bad MAC address string to bytes:')
        print(eth.convert_mac('01123:45:67:89:0a', False))

        print('\nConvert MAC address bytes to string:')
        print(eth.convert_mac(b'\x01#Eg\x89\n', True))

        print('\nConvert bad MAC address bytes to string:')
        print(eth.convert_mac(b'\x01#Eg\x89', False))

        print('\nGet MAC address prefix string:')
        print(eth.get_mac_prefix('ab:c3:45:67:89:0a', 3, True))

        print('\nGet MAC address prefix bytes:')
        print(eth.get_mac_prefix(b'\x01#Eg\x89\n', 3, True))

        print('\nMake Ethernet header:')
        print(eth.make_header('30:31:32:33:34:35', '36:37:38:39:40:41', 2048))

        print('\nMake Ethernet header bad input:')
        print(eth.make_header('01:23:45:67:89:0', '01:23:45:67:89:0a', 2048))

        print('\nParse Ethernet header:')
        print(eth.parse_header(b'6789@A012345\x08\x00'))
        # endregion

        # region RawARP functions
        print('\n')
        base.print_info('Test network ARP functions:')

        print('\nMake ARP packet')
        print(arp.make_packet())

        print('\nMake ARP packet bad input')
        print(arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b',
                              '01:23:45:67:89:0aa', '1111', '01:23:45:67:89:b', '2222'))

        print('\nParse ARP packet')
        print(arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n' +
                               b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02'))

        print('\nMake ARP request')
        print(arp.make_request())

        print('\nParse ARP request')
        print(arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n' +
                               b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02'))

        print('\nMake ARP response')
        print(arp.make_response())

        print('\nParse ARP response')
        print(arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x02\x01#Eg\x89\n' +
                               b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02'))
        # endregion

        # region RawIPv4 functions
        print('\n')
        base.print_info('Test network IPv4 functions:')

        print('\nGet random IPv4 address:')
        print(ipv4.make_random_ip())

        print('\nMake IPv4 header:')
        print(ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 0, 8, 17, 64))

        print('\nMake IPv4 header bad input:')
        print(ipv4.make_header('1234', '1234', 65537))

        print('\nParse IPv4 header:')
        print(ipv4.parse_header(b'E\x00\x00\x1c\x8d/\x00\x00@\x11jN\xc0\xa8\x01\x01\xc0\xa8\x01\x02'))

        print('\nParse IPv4 header bad input:')
        print(ipv4.parse_header(b'\x61\x00\x00\x1c\x8d/\x00\x00@\x11jN\xc0\xa8\x01\x01\xc0\xa8\x01\x02'))
        # endregion

        # region RawIPv6 functions
        print('\n')
        base.print_info('Test network ipv6 functions:')

        print('\nGet random ipv6 address:')
        print(ipv6.make_random_ip())

        print('\nPack ipv6 address:')
        print(ipv6.pack_addr('3132:3334::1'))

        print('\nPack ipv6 address bad input:')
        print(ipv6.pack_addr('fd12:::1', False))

        print('\nMake ipv6 header:')
        print(ipv6.make_header())

        print('\nMake ipv6 header bad input:')
        print(ipv6.make_header('fd00:::1', 'fd00:2', 1, 1, 1, 1))

        print('\nParse ipv6 header:')
        print(ipv6.parse_header(b'`\x00\x00\x00\x00\x08\x11@\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                                b'\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'))
        # endregion

        # region RawUDP functions
        print('\n')
        base.print_info('Test network UDP functions:')

        print('\nMake UDP header:')
        print(udp.make_header())

        print('\nMake UDP header bad input:')
        print(udp.make_header(123123, 123123))

        print('\nMake UDP header with checksum for ipv6:')
        print(udp.make_header_with_ipv6_checksum())

        print('\nMake UDP header with checksum for ipv6 bad input:')
        print(udp.make_header_with_ipv6_checksum('fd00:::1', 'fd00:2'))

        print('\nParse UDP header')
        print(udp.parse_header(b'\x14\xe9\x14\xe9\x00\x08\xdc\x07'))
        # endregion

        # region RawDNS functions
        print('\n')
        base.print_info('Test network DNS functions:')

        print('\nMake DNS name:')
        print(dns.make_dns_name())

        print('\nMake IPv4 DNS request packet:')
        print(dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                           ip_src='192.168.1.1', ip_dst='192.168.1.2', ip_ident=1,
                                           udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                           queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                           flags=0))

        print('\nMake IPv6 DNS request packet:')
        print(dns.make_ipv6_request_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                           ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64,
                                           udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                           queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                           flags=0))

        print('\nMake IPv4 DNS response packet:')
        print(dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                       ip_src='192.168.1.1', ip_dst='192.168.1.2', ip_ttl=64, ip_ident=1,
                                       udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                       queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                       answers_address=[{'name': 'test.com', 'type': 1, 'class': 1, 'ttl': 65535,
                                                         'address': '192.168.1.1'}], name_servers={},
                                       exit_on_failure=True))

        print('\nMake IPv6 DNS response packet:')
        print(dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                       ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                       udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                       queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                       answers_address=[{'name': 'test.com', 'type': 28, 'class': 1, 'ttl': 65535,
                                                         'address': 'fd00::1'}], name_servers={},
                                       exit_on_failure=True))

        print('\nParse DNS packet:')
        print(dns.parse_packet(
            b'\x00\x01\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04test\x03com\x00\x00\x01\x00\x01\x04test\x03com\x00' +
            b'\x00\x01\x00\x01\x00\x00\xff\xff\x00\x04\xc0\xa8\x01\x01'))
        # endregion

        # region RawDHCPv4 functions
        print('\n')
        base.print_info('Test network DHCPv4 functions:')

        print('\nMake and send DHCPv4 discover packet:')
        dhcpv4_discover = dhcpv4.make_discover_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                      client_mac='01:23:45:67:89:0a',
                                                      ip_ident=1, transaction_id=1, host_name='dhcp.discover.test')
        print(dhcpv4_discover)
        raw_socket.send(dhcpv4_discover)

        print('\nMake and send DHCPv4 request packet:')
        dhcpv4_request = dhcpv4.make_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                    client_mac='01:23:45:67:89:0a',
                                                    ip_ident=1, transaction_id=1, requested_ip='192.168.1.1',
                                                    host_name='dhcp.request.test')
        print(dhcpv4_request)
        raw_socket.send(dhcpv4_request)

        print('\nMake and send DHCPv4 offer packet:')
        dhcpv4_offer = dhcpv4.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                   ethernet_dst_mac='01:23:45:67:89:0b',
                                                   ip_src='192.168.1.1', ip_ident=1, transaction_id=1,
                                                   dhcp_message_type=2, your_client_ip='192.168.1.2')
        print(dhcpv4_offer)
        raw_socket.send(dhcpv4_offer)

        print('\nMake and send DHCPv4 ack packet:')
        dhcpv4_ack = dhcpv4.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                 ethernet_dst_mac='01:23:45:67:89:0b',
                                                 ip_src='192.168.1.1', ip_ident=1, transaction_id=1,
                                                 dhcp_message_type=5, your_client_ip='192.168.1.2')
        print(dhcpv4_ack)
        raw_socket.send(dhcpv4_ack)

        # endregion

    except KeyboardInterrupt:
        base.print_info("Exit")
        exit(0)

# endregion
