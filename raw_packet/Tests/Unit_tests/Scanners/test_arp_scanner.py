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
    arp_scan: ArpScan = ArpScan(variables.test_network_interface)
    # endregion

    def test01_scan(self):
        for _ in range(1, 5, 1):
            arp_scan_results = self.arp_scan.scan(timeout=1, retry=1, show_scan_percentage=False,
                                                  exit_on_failure=False)
            self.assertIsNotNone(arp_scan_results)
            find_router: bool = False
            for arp_scan_result in arp_scan_results:
                if arp_scan_result['ip-address'] == self.variables.router_ipv4_address:
                    self.assertEqual(arp_scan_result['mac-address'], self.variables.router_mac_address)
                    self.assertIn(self.variables.router_vendor, arp_scan_result['vendor'])
                    find_router = True
            self.assertTrue(find_router)

    def test02_scan_with_exclude(self):
        for _ in range(1, 5, 1):
            arp_scan_results = self.arp_scan.scan(timeout=1, retry=1, show_scan_percentage=False,
                                                  exclude_ip_addresses=[self.variables.router_ipv4_address],
                                                  exit_on_failure=False)
            self.assertIsNotNone(arp_scan_results)
            find_router: bool = False
            for arp_scan_result in arp_scan_results:
                if arp_scan_result['ip-address'] == self.variables.router_ipv4_address:
                    find_router = True
            self.assertFalse(find_router)

    def test03_get_mac_address(self):
        for _ in range(1, 5, 1):
            mac_address = self.arp_scan.get_mac_address(target_ip_address=self.variables.router_ipv4_address,
                                                        timeout=1, retry=1, show_scan_percentage=False,
                                                        exit_on_failure=False)
            self.assertEqual(mac_address, self.variables.router_mac_address)

# endregion
