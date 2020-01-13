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

    test_network_interface: str = 'wlan0'
    bad_network_interface: str = 'wlan123'

    ipv4_network_mask: str = '255.255.255.0'
    ipv4_broadcast: str = '192.168.1.255'
    ipv4_network: str = '192.168.1.0/24'
    ipv4_first_address: str = '192.168.1.1'
    ipv4_second_address: str = '192.168.1.2'
    ipv4_penultimate_address: str = '192.168.1.253'
    ipv4_last_address: str = '192.168.1.254'

    router_mac_address: str = '3c:46:d8:82:7b:27'
    router_ipv4_address: str = '192.168.1.1'
    router_ipv6_link_address: str = 'fe80::3e46:d8ff:fe82:7b27'
    router_ipv6_glob_address: str = 'fd00::1'

    your_mac_address: str = '84:16:f9:19:ad:14'
    your_ipv4_address: str = '192.168.1.2'
    your_ipv6_link_address: str = 'fe80::74f7:7a74:d00:ffb'
    your_ipv6_glob_address: str = 'fd00::123'

    apple_device_mac_address: str = '8c:85:90:26:02:be'
    apple_device_ipv4_address: str = '192.168.1.3'
    apple_device_ipv6_link_address: str = 'fe80::444:83c5:5bb:58f3'
    apple_device_username: str = 'user'

# endregion
