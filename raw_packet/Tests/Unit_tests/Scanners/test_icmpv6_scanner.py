# region Description
"""
test_icmpv6_scanner.py: Unit tests for Raw-packet ICMPv6 scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
import unittest
path.append(dirname(dirname(abspath(__file__))))
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


# region Main class - NetworkTest
class ICMPv6ScanTest(unittest.TestCase):

    # region Properties
    from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan()

    # region Must change this value for your test
    network_interface: str = 'wlan0'
    ipv6_router_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    # endregion

    # endregion

    def test_scan(self):
        scan_result = self.icmpv6_scan.scan(network_interface=self.network_interface)
        self.assertIsNotNone(scan_result)

    def test_search_router(self):
        ipv6_router_info = self.icmpv6_scan.search_router(network_interface=self.network_interface)
        self.assertTrue('router_mac_address' in ipv6_router_info.keys())
        self.assertEqual(ipv6_router_info['router_mac_address'], self.ipv6_router_mac_address)
# endregion
