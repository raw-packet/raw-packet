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
    bad_network_interface: str = 'eth123'

    router_ipv4_address: str = '192.168.0.254'
    router_mac_address: str = 'c4:a8:1d:8a:f9:b0'

# endregion
