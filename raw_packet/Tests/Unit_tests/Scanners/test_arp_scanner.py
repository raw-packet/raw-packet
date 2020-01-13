# region Description
"""
test_arp_scanner.py: Unit tests for Raw-packet ARP scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
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
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Main class - NetworkTest
class ArpScanTest(unittest.TestCase):

    # region Properties
    from raw_packet.Scanners.arp_scanner import ArpScan
    from raw_packet.Tests.Unit_tests.variables import Variables
    arp_scan: ArpScan = ArpScan()

    # region Must change this value for your test
    network_interface: str = Variables.test_network_interface
    router_ipv4_address: str = Variables.router_ipv4_address
    router_mac_address: str = Variables.router_mac_address
    # endregion

    # endregion

    def test_scan(self):
        arp_scan_results = self.arp_scan.scan(network_interface=self.network_interface, timeout=1, retry=1,
                                              show_scan_percentage=False)
        find_router_mac: bool = False
        find_router_ip: bool = False
        for arp_scan_result in arp_scan_results:
            if arp_scan_result['mac-address'] == self.router_mac_address:
                find_router_mac = True
            if arp_scan_result['ip-address'] == self.router_ipv4_address:
                find_router_ip = True
        self.assertTrue(find_router_mac)
        self.assertTrue(find_router_ip)

    def test_scan_with_exclude(self):
        arp_scan_results = self.arp_scan.scan(network_interface=self.network_interface, timeout=1, retry=1,
                                              show_scan_percentage=False,
                                              exclude_ip_addresses=[self.router_ipv4_address])
        find_router_mac: bool = False
        find_router_ip: bool = False
        for arp_scan_result in arp_scan_results:
            if arp_scan_result['mac-address'] == self.router_mac_address:
                find_router_mac = True
            if arp_scan_result['ip-address'] == self.router_ipv4_address:
                find_router_ip = True
        self.assertFalse(find_router_mac)
        self.assertFalse(find_router_ip)

    def test_get_mac_address(self):
        mac_address = self.arp_scan.get_mac_address(network_interface=self.network_interface,
                                                    target_ip_address=self.router_ipv4_address,
                                                    timeout=1, retry=1, show_scan_percentage=False)
        self.assertEqual(mac_address, self.router_mac_address)

# endregion
