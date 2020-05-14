# region Description
"""
test_nmap_scanner.py: Unit tests for Raw-packet Nmap scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scanners.nmap_scanner import NmapScanner
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


# region Main class - NmapScannerTest
class NmapScannerTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    nmap_scanner: NmapScanner = NmapScanner(network_interface=variables.your.network_interface)
    # endregion

    def test01_scan(self):
        scan_results = self.nmap_scanner.scan()
        self.assertIsNotNone(scan_results)
        for scan_result in scan_results:
            if scan_result.ipv4_address == self.variables.router.ipv4_address:
                self.assertEqual(scan_result.mac_address, self.variables.router.mac_address)
                self.assertIn(scan_result.vendor.lower(), self.variables.router.vendor.lower())
            if scan_result.ipv4_address == self.variables.target.ipv4_address:
                self.assertEqual(scan_result.mac_address, self.variables.target.mac_address)
                self.assertIn(scan_result.vendor.lower(), self.variables.target.vendor.lower())
# endregion
