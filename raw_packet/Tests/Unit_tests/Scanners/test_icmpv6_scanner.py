# region Description
"""
test_icmpv6_scanner.py: Unit tests for Raw-packet ICMPv6 scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
from raw_packet.Tests.Unit_tests.variables import Variables
from unittest import TestCase
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
class ICMPv6ScanTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan(variables.test_network_interface)
    # endregion

    def test01_scan(self):
        icmpv6_scan_results = self.icmpv6_scan.scan(timeout=1, retry=1)
        self.assertIsNotNone(icmpv6_scan_results)
        self.assertTrue(len(icmpv6_scan_results) > 0)
        find_router_mac: bool = False
        find_router_ip: bool = False
        for icmpv6_scan_result in icmpv6_scan_results:
            if icmpv6_scan_result['mac-address'] == ICMPv6ScanTest.Variables.router_mac_address:
                find_router_mac = True
            if icmpv6_scan_result['ip-address'] == ICMPv6ScanTest.Variables.router_ipv6_link_address:
                find_router_ip = True
        self.assertTrue(find_router_mac)
        self.assertTrue(find_router_ip)

    def test02_search_router(self):
        ipv6_router_info = \
            self.icmpv6_scan.search_router(network_interface=ICMPv6ScanTest.Variables.test_network_interface)
        self.assertTrue('router_mac_address' in ipv6_router_info.keys())
        self.assertEqual(ipv6_router_info['router_mac_address'], ICMPv6ScanTest.Variables.router_mac_address)
        self.assertEqual(ipv6_router_info['router_ipv6_address'], ICMPv6ScanTest.Variables.router_ipv6_link_address)

# endregion
