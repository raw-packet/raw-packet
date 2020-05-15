# region Description
"""
variables.py: Variables for unit tests
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from collections import namedtuple
from tempfile import gettempdir
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Main class - Variables
class Variables:

    base: Base = Base(admin_only=False, available_platforms=['Linux', 'Darwin', 'Windows'])

    Settings = namedtuple('Settings', 'network_interface, vendor, platform, mac_address, ipv4_address, '
                                      'ipv6_link_address, ipv6_global_address, port')

    IPv4 = namedtuple('IPv4', 'network_mask, broadcast, network, first_address, '
                              'second_address, penultimate_address, last_address')

    kali: Settings = Settings(network_interface='eth0',
                              vendor='Dell',
                              platform='Linux Kali GNU/Linux 2019.4',
                              mac_address='00:06:5b:00:00:00',
                              ipv4_address='192.168.1.100',
                              ipv6_link_address='fe80::1e52:e6c2:78fc:82a7',
                              ipv6_global_address='fd06:46b2:4912::100',
                              port=22)

    macos: Settings = Settings(network_interface='en0',
                               vendor='Apple',
                               platform='Darwin 19.0.0',
                               mac_address='00:03:93:11:11:11',
                               ipv4_address='192.168.1.101',
                               ipv6_link_address='fe80::8a5:f12c:742d:df5f',
                               ipv6_global_address='fd06:46b2:4912::101',
                               port=22)

    windows: Settings = Settings(network_interface='Internal',
                                 vendor='Intel',
                                 platform='Windows 10',
                                 mac_address='00:02:b3:22:22:22',
                                 ipv4_address='192.168.1.102',
                                 ipv6_link_address='fe80::981:d7f:38d7:91a2',
                                 ipv6_global_address='fd06:46b2:4912::102',
                                 port=22)

    ubuntu: Settings = Settings(network_interface='enp0s3',
                                vendor='Next',
                                platform='Linux Ubuntu 18.04',
                                mac_address='00:00:0f:33:33:33',
                                ipv4_address='192.168.1.103',
                                ipv6_link_address='fe80::d208:c1a7:c669:4788',
                                ipv6_global_address='fd06:46b2:4912::103',
                                port=22)

    router: Settings = Settings(network_interface='br-lan',
                                vendor='Cisco Systems',
                                platform='Openwrt',
                                mac_address='00:00:0c:ff:ff:ff',
                                ipv4_address='192.168.1.254',
                                ipv6_link_address='fe80::200:cff:feff:ffff',
                                ipv6_global_address='fd06:46b2:4912::1',
                                port=22)

    bad: Settings = Settings(network_interface='wlan123',
                             vendor='Unknown vendor',
                             platform='Unknown platform',
                             mac_address='12:34:56:78:90:abc',
                             ipv4_address='192.168.0.1234',
                             ipv6_link_address='fe80:::123',
                             ipv6_global_address='fd06:46b2:4912:::123',
                             port=123456)

    ipv4: IPv4 = IPv4(network_mask='255.255.255.0',
                      broadcast='192.168.1.255',
                      network='192.168.1.0/24',
                      first_address='192.168.1.1',
                      second_address='192.168.1.2',
                      penultimate_address='192.168.1.253',
                      last_address='192.168.1.254')

    target: Settings = ubuntu

    if base.get_platform().startswith('Linux'):
        tshark_executable: str = 'tshark'
        temp_directory: str = gettempdir()
        if 'Kali' in base.get_platform():
            your: Settings = kali
        elif 'Ubuntu' in base.get_platform():
            your: Settings = ubuntu
            target: Settings = macos

    elif base.get_platform().startswith('Darwin'):
        tshark_executable: str = 'tshark'
        temp_directory: str = '/tmp/'
        your: Settings = macos

    elif base.get_platform().startswith('Windows'):
        tshark_executable: str = '"C:\\Program Files\\Wireshark\\tshark.exe"'
        temp_directory: str = gettempdir()
        your: Settings = windows

# endregion
