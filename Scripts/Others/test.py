#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
test.py: Test new technique
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
from raw_packet.Utils.network import MDNS_raw, ICMPv6_raw, RawEthernet
from raw_packet.Utils.network import Sniff_raw
# endregion

# region Import libraries
from time import sleep
from json import dumps
from socket import socket, AF_PACKET, SOCK_RAW
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

# region Check user, platform and print banner
Ethernet = RawEthernet()
Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()
# endregion


# region Main function
if __name__ == "__main__":

    try:
        print('\n')
        Base.print_info('Network functions:')

        print('\nMac address:')
        print(Base.get_interface_mac_address('eth0', False))

        print('\nIPv4 address:')
        print(Base.get_interface_ip_address('eth0', False))

        print('\nIPv6 link local address:')
        print(Base.get_interface_ipv6_link_address('eth0', False))

        print('\nIPv6 link local address by mac address:')
        print(Base.make_ipv6_link_address(Base.get_interface_mac_address('eth0', False)))

        print('\nIPv6 link global address:')
        print(Base.get_interface_ipv6_glob_address('eth0', False))

        print('\nIPv6 global addresses:')
        print(Base.get_interface_ipv6_glob_addresses('eth0'))

        print('\nNetwork mask:')
        print(Base.get_interface_netmask('eth0', False))

        print('\nFirst IPv4:')
        print(Base.get_first_ip_on_interface('eth0', False))

        print('\nSecond IPv4:')
        print(Base.get_second_ip_on_interface('eth0', False))

        print('\nPenultimate IPv4:')
        print(Base.get_penultimate_ip_on_interface('eth0', False))

        print('\nLast IPv4:')
        print(Base.get_last_ip_on_interface('eth0', False))

        print('\nRandom IPv4:')
        print(Base.get_random_ip_on_interface('eth0', False))

        print('\nIPv4 network:')
        print(Base.get_interface_network('eth0', False))

        print('\nIPv4 broadcast:')
        print(Base.get_interface_broadcast('eth0', False))

        print('\nIPv4 gateway:')
        print(Base.get_interface_ipv4_gateway('eth0', False))

        print('\nIPv6 gateway:')
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

        print('\n')
        Base.print_info('Ethernet functions:')

        print('\nConvert MAC address string to bytes:')
        print(Ethernet.convert_mac('01:23:45:67:89:0a', True))

        print('\nConvert MAC address bytes to string:')
        print(Ethernet.convert_mac(b'01234567890a', True))

        print('\nGet MAC address prefix:')
        print(Ethernet.get_mac_prefix('ab:c3:45:67:89:0a', 3, True))

        print('\nGet MAC address prefix:')
        print(Ethernet.get_mac_prefix(b'abc34567890a', 3, True))

        print('\nMake Ethernet header:')
        print(Ethernet.make_header('01:23:45:67:89:0a', '01:23:45:67:89:0a', 2048))

        print('\nParse Ethernet header:')
        print(Ethernet.parse_header(b'\x01#Eg\x89\n\x01#Eg\x89\n\x08\x00'))

    except KeyboardInterrupt:
        Base.print_info("Exit")
        exit(0)

# endregion
