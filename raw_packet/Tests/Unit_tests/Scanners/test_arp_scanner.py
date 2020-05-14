# region Description
"""
test_arp_scanner.py: Unit tests for Raw-packet ARP scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scanners.arp_scanner import ArpScan
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
class ArpScanTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    arp_scan: ArpScan = ArpScan(network_interface=variables.your.network_interface)
    # endregion

    def test01_scan(self):
        arp_scan_results = self.arp_scan.scan(timeout=1, retry=1, show_scan_percentage=False,
                                              exit_on_failure=False)
        self.assertIsNotNone(arp_scan_results)
        find_router: bool = False
        find_target: bool = False
        for arp_scan_result in arp_scan_results:
            if arp_scan_result['ip-address'] == self.variables.router.ipv4_address:
                self.assertEqual(arp_scan_result['mac-address'], self.variables.router.mac_address)
                self.assertIn(self.variables.router.vendor, arp_scan_result['vendor'])
                find_router = True
            if arp_scan_result['ip-address'] == self.variables.target.ipv4_address:
                self.assertEqual(arp_scan_result['mac-address'], self.variables.target.mac_address)
                self.assertIn(self.variables.target.vendor, arp_scan_result['vendor'])
                find_target = True
        self.assertTrue(find_router)
        self.assertTrue(find_target)

    def test02_scan_with_exclude(self):
        arp_scan_results = self.arp_scan.scan(timeout=1, retry=1, show_scan_percentage=False,
                                              exclude_ip_addresses=[self.variables.router.ipv4_address],
                                              exit_on_failure=False)
        self.assertIsNotNone(arp_scan_results)
        find_router: bool = False
        find_target: bool = False
        for arp_scan_result in arp_scan_results:
            if arp_scan_result['ip-address'] == self.variables.router.ipv4_address:
                find_router = True
            if arp_scan_result['ip-address'] == self.variables.target.ipv4_address:
                self.assertEqual(arp_scan_result['mac-address'], self.variables.target.mac_address)
                self.assertIn(self.variables.target.vendor, arp_scan_result['vendor'])
                find_target = True
        self.assertFalse(find_router)
        self.assertTrue(find_target)

    def test03_get_mac_address(self):
        mac_address = self.arp_scan.get_mac_address(target_ip_address=self.variables.router.ipv4_address,
                                                    timeout=1, retry=1, show_scan_percentage=False,
                                                    exit_on_failure=False)
        self.assertEqual(mac_address, self.variables.router.mac_address)
        mac_address = self.arp_scan.get_mac_address(target_ip_address=self.variables.target.ipv4_address,
                                                    timeout=1, retry=1, show_scan_percentage=False,
                                                    exit_on_failure=False)
        self.assertEqual(mac_address, self.variables.target.mac_address)

# endregion
