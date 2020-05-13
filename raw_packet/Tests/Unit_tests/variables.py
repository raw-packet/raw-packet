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

    if base.get_platform().startswith('Linux'):
        test_network_interface: str = 'eth1'
        test_wireless_listen_interface: str = 'wlan0'
        test_wireless_deauth_interface: str = 'wlan1'

    elif base.get_platform().startswith('Windows'):
        test_network_interface: str = 'Wireless'
        test_wireless_listen_interface: str = 'Wireless'
        test_wireless_deauth_interface: str = 'Wi-Fi'

    elif base.get_platform().startswith('Darwin'):
        test_network_interface: str = 'en0'
        test_wireless_listen_interface: str = 'en0'
        test_wireless_deauth_interface: str = 'en0'

    ipv4_network_mask: str = '255.255.255.0'
    ipv4_broadcast: str = '192.168.0.255'
    ipv4_network: str = '192.168.0.0/24'
    ipv4_first_address: str = '192.168.0.1'
    ipv4_second_address: str = '192.168.0.2'
    ipv4_penultimate_address: str = '192.168.0.253'
    ipv4_last_address: str = '192.168.0.254'

    router_vendor: str = 'D-Link'
    router_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    router_ipv4_address: str = '192.168.0.254'

    your_mac_address: str = '08:00:27:af:c6:44'
    your_ipv4_address: str = '192.168.1.2'
    your_ipv6_link_address: str = 'fe80::a00:27ff:feaf:c644'
    your_ipv6_glob_address: str = 'fd06:46b2:4912::66f'

    apple_device_mac_address: str = '00:03:93:12:34:56'
    apple_device_ipv4_address: str = '192.168.1.3'
    apple_device_new_ipv4_address: str = '192.168.1.111'
    apple_device_ipv6_link_address: str = 'fe80::1016:45cc:5037:e16d'
    apple_device_ipv6_glob_address: str = 'fd00::123'
    apple_device_username: str = 'admin'
    apple_device_root_username: str = 'root'
    apple_device_network_interface: str = 'en0'

    bad_network_interface: str = 'wlan123'
    bad_mac_address: str = '12:34:56:78:90:abc'
    bad_ipv4_address: str = '192.168.0.1234'
    bad_ipv6_address: str = 'fd00:::123'
    bad_port: str = '1234567'

# endregion
