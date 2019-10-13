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
from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4, RawIPv6, RawUDP
# endregion

# region Import libraries
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
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

    # region Check user, platform and print banner
    Base = Base()
    Base.check_user()
    Base.check_platform()
    Base.print_banner()
    # endregion

    # region Init Raw-packet classes
    eth = RawEthernet()
    arp = RawARP()
    ipv4 = RawIPv4()
    ipv6 = RawIPv6()
    udp = RawUDP()
    # endregion

    try:
        # region Base functions
        print('\n')
        Base.print_info('Network functions:')

        print('\nNetwork interface settings:')
        print(Base.get_interface_settings('eth0'))

        print('\nMac address:')
        print(Base.get_interface_mac_address('eth0', False))

        print('\nipv4 address:')
        print(Base.get_interface_ip_address('eth0', False))

        print('\nipv6 link local address:')
        print(Base.get_interface_ipv6_link_address('eth0', False))

        print('\nipv6 link local address by mac address:')
        print(Base.make_ipv6_link_address('12:34:56:78:90:ab'))

        print('\nipv6 link global address:')
        print(Base.get_interface_ipv6_glob_address('eth0'))

        print('\nipv6 global addresses:')
        print(Base.get_interface_ipv6_glob_addresses('eth0'))

        print('\nNetwork mask:')
        print(Base.get_interface_netmask('eth0', False))

        print('\nFirst ipv4:')
        print(Base.get_first_ip_on_interface('eth0', False))

        print('\nSecond ipv4:')
        print(Base.get_second_ip_on_interface('eth0', False))

        print('\nPenultimate ipv4:')
        print(Base.get_penultimate_ip_on_interface('eth0', False))

        print('\nLast ipv4:')
        print(Base.get_last_ip_on_interface('eth0', False))

        print('\nRandom ipv4:')
        print(Base.get_random_ip_on_interface('eth0', False))

        print('\nipv4 network:')
        print(Base.get_interface_network('eth0', False))

        print('\nipv4 broadcast:')
        print(Base.get_interface_broadcast('eth0', False))

        print('\nipv4 gateway:')
        print(Base.get_interface_ipv4_gateway('eth0', False))

        print('\nipv6 gateway:')
        print(Base.get_interface_ipv6_gateway('eth0', False))

        print('\n')
        Base.print_info('Software functions:')

        print('\nApt list installed software:')
        print(Base.apt_list_installed_packages())

        print('\nCheck installed software: apache2')
        print(Base.check_installed_software('apache2', False))

        print('\n')
        Base.print_info('Process functions:')

        print('\nProcess apache2 pid:')
        print(Base.get_process_pid('apache2'))

        print('\nProcess pid by listen port 80:')
        print(Base.get_process_pid_by_listen_port(80))
        # endregion

        # region RawEthernet functions
        print('\n')
        Base.print_info('Test network Ethernet functions:')

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
        Base.print_info('Test network ARP functions:')

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
        Base.print_info('Test network IPv4 functions:')

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
        Base.print_info('Test network ipv6 functions:')

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
        Base.print_info('Test network udp functions:')

        print('\nMake udp header:')
        print(udp.make_header())

        print('\nMake udp header bad input:')
        print(udp.make_header(123123, 123123))

        print('\nMake udp header with checksum for ipv6:')
        print(udp.make_header_with_ipv6_checksum())

        print('\nMake udp header with checksum for ipv6 bad input:')
        print(udp.make_header_with_ipv6_checksum('fd00:::1', 'fd00:2'))

        print('\nParse UDP header')
        print(udp.parse_header(b'\x14\xe9\x14\xe9\x00\x08\xdc\x07'))
        # endregion

    except KeyboardInterrupt:
        Base.print_info("Exit")
        exit(0)

# endregion
