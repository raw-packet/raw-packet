# region Description
"""
test_icmpv6_scanner.py: Unit tests for Raw-packet ICMPv6 scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
import unittest
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


# region Main class - NetworkTest
class ICMPv6ScanTest(unittest.TestCase):

    # region Properties
    path.append(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
    from raw_packet.Tests.Unit_tests.variables import Variables
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan()
    # endregion

    def test01_scan(self):
        scan_result = self.icmpv6_scan.scan(network_interface=ICMPv6ScanTest.Variables.test_network_interface)
        self.assertIsNotNone(scan_result)

    def test02_search_router(self):
        ipv6_router_info = \
            self.icmpv6_scan.search_router(network_interface=ICMPv6ScanTest.Variables.test_network_interface)
        self.assertTrue('router_mac_address' in ipv6_router_info.keys())
        self.assertEqual(ipv6_router_info['router_mac_address'], ICMPv6ScanTest.Variables.router_mac_address)

# endregion
