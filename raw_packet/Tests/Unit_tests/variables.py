# region Description
"""
variables.py: Variables for unit tests
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
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

    test_network_interface: str = 'eth1'

    ipv4_network_mask: str = '255.255.255.0'
    ipv4_broadcast: str = '192.168.1.255'
    ipv4_network: str = '192.168.1.0/24'
    ipv4_first_address: str = '192.168.1.1'
    ipv4_second_address: str = '192.168.1.2'
    ipv4_penultimate_address: str = '192.168.1.253'
    ipv4_last_address: str = '192.168.1.254'

    router_vendor: str = 'VMware'
    router_mac_address: str = '00:0c:29:87:d3:5d'
    router_ipv4_address: str = '192.168.1.254'
    router_ipv6_link_address: str = 'fe80::20c:29ff:fe87:d35d'
    router_ipv6_glob_address: str = 'fd3d:3be1:e8b2:fd00::1'

    your_mac_address: str = '00:0c:29:70:75:4b'
    your_ipv4_address: str = '192.168.1.2'
    your_ipv6_link_address: str = 'fe80::20c:29ff:fe70:754b'
    your_ipv6_glob_address: str = 'fd3d:3be1:e8b2:fd00::b3c'

    apple_device_mac_address: str = '00:03:93:ce:12:7d'
    apple_device_ipv4_address: str = '192.168.1.3'
    apple_device_ipv6_link_address: str = 'fe80::203:93ff:fece:127d'
    apple_device_username: str = 'admin'

    bad_network_interface: str = 'wlan123'
    bad_mac_address: str = '12:34:56:78:90:abc'
    bad_ipv4_address: str = '192.168.0.1234'
    bad_ipv6_address: str = 'fd00:::123'
    bad_port: str = '1234567'

# endregion
