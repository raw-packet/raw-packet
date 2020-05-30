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
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan(network_interface=variables.your.network_interface)
    # endregion

    def test01_scan(self):
        icmpv6_scan_results = self.icmpv6_scan.scan(timeout=3, retry=3, exit_on_failure=False)
        self.assertIsNotNone(icmpv6_scan_results)
        self.assertTrue(len(icmpv6_scan_results) > 0)
        find_router: bool = False
        find_target: bool = False
        for icmpv6_scan_result in icmpv6_scan_results:
            if icmpv6_scan_result['ip-address'] == self.variables.router.ipv6_link_address:
                self.assertEqual(icmpv6_scan_result['mac-address'], self.variables.router.mac_address)
                self.assertIn(self.variables.router.vendor, icmpv6_scan_result['vendor'])
                find_router = True
            if icmpv6_scan_result['ip-address'] == self.variables.target.ipv6_link_address:
                self.assertEqual(icmpv6_scan_result['mac-address'], self.variables.target.mac_address)
                self.assertIn(self.variables.target.vendor, icmpv6_scan_result['vendor'])
                find_target = True
        self.assertTrue(find_router)
        self.assertTrue(find_target)

    def test02_scan_with_exclude(self):
        icmpv6_scan_results = self.icmpv6_scan.scan(timeout=3, retry=3, exit_on_failure=False,
                                                    exclude_ipv6_addresses=[self.variables.router.ipv6_link_address])
        self.assertIsNotNone(icmpv6_scan_results)
        self.assertTrue(len(icmpv6_scan_results) > 0)
        find_router: bool = False
        find_target: bool = False
        for icmpv6_scan_result in icmpv6_scan_results:
            if icmpv6_scan_result['ip-address'] == self.variables.router.ipv6_link_address:
                find_router = True
            if icmpv6_scan_result['ip-address'] == self.variables.target.ipv6_link_address:
                self.assertEqual(icmpv6_scan_result['mac-address'], self.variables.target.mac_address)
                self.assertIn(self.variables.target.vendor, icmpv6_scan_result['vendor'])
                find_target = True
        self.assertFalse(find_router)
        self.assertTrue(find_target)

    def test03_scan_target_mac(self):
        icmpv6_scan_results = self.icmpv6_scan.scan(timeout=3, retry=3, exit_on_failure=False,
                                                    target_mac_address=self.variables.router.mac_address)
        self.assertEqual(icmpv6_scan_results[0]['ip-address'], self.variables.router.ipv6_link_address)
        self.assertIn(self.variables.router.vendor, icmpv6_scan_results[0]['vendor'])
        icmpv6_scan_results = self.icmpv6_scan.scan(timeout=3, retry=3, exit_on_failure=False,
                                                    target_mac_address=self.variables.target.mac_address)
        self.assertEqual(icmpv6_scan_results[0]['ip-address'], self.variables.target.ipv6_link_address)
        self.assertIn(self.variables.target.vendor, icmpv6_scan_results[0]['vendor'])

    # def test04_search_router(self):
    #     ipv6_router_info = self.icmpv6_scan.search_router(timeout=3, retry=3, exit_on_failure=False)
    #     self.assertIsNotNone(ipv6_router_info)
    #     self.assertIn('router_mac_address', ipv6_router_info)
    #     self.assertIn('router_ipv6_address', ipv6_router_info)
    #     self.assertIn('dns-server', ipv6_router_info)
    #     self.assertIn('vendor', ipv6_router_info)
    #     self.assertEqual(ipv6_router_info['router_mac_address'], self.variables.router.mac_address)
    #     self.assertEqual(ipv6_router_info['router_ipv6_address'], self.variables.router.ipv6_link_address)
    #     self.assertEqual(ipv6_router_info['dns-server'], self.variables.router.ipv6_link_address)
    #     self.assertIn(self.variables.router.vendor, ipv6_router_info['vendor'])

# endregion
