# region Description
"""
test_arp_scanner.py: Unit tests for Raw-packet ARP scanner
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(abspath(__file__))))
# endregion

# region Raw-packet modules
from raw_packet.Scanners.arp_scanner import ArpScan
# endregion

# region Import libraries
from typing import List, Dict
import unittest
# endregion

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
class ArpScanTest(unittest.TestCase):

    # region Properties
    arp_scan: ArpScan = ArpScan()
    current_arp_table: List[Dict[str, str]] = list()
    interfaces: List[str] = list()
    with open('/proc/net/arp', 'r') as arp_file:
        arp_file_content = arp_file.readlines()
        for arp_file_line in arp_file_content:
            arp_file_words = arp_file_line.split()
            if arp_file_words[0] != 'IP':
                current_arp_table.append({'ip-address': arp_file_words[0],
                                          'mac-address': arp_file_words[3],
                                          'interface': arp_file_words[5]})
    # endregion

    def test_scan(self):
        for arp_table_element in self.current_arp_table:
            arp_scan_results = self.arp_scan.scan(network_interface=arp_table_element['interface'], timeout=1, retry=1,
                                                  show_scan_percentage=False)
            find_mac_address = False
            find_ip_address = False
            find_arp_table_element = False
            for arp_scan_result in arp_scan_results:
                for key, value in arp_scan_result.items():
                    if arp_table_element['mac-address'] == value:
                        find_mac_address = True
                    if arp_table_element['ip-address'] == value:
                        find_ip_address = True
            if find_mac_address and find_ip_address:
                find_arp_table_element = True
            self.assertTrue(find_arp_table_element)

    def test_scan_with_exclude(self):
        for arp_table_element in self.current_arp_table:
            arp_scan_results = self.arp_scan.scan(network_interface=arp_table_element['interface'],
                                                  timeout=1, retry=1,
                                                  show_scan_percentage=False,
                                                  exclude_ip_addresses=[arp_table_element['ip-address']])
            find_mac_address = False
            find_ip_address = False
            for arp_scan_result in arp_scan_results:
                for key, value in arp_scan_result.items():
                    if arp_table_element['mac-address'] == value:
                        find_mac_address = True
                    if arp_table_element['ip-address'] == value:
                        find_ip_address = True
            self.assertFalse(find_mac_address)
            self.assertFalse(find_ip_address)

    def test_get_mac_address(self):
        for arp_table_element in self.current_arp_table:
            mac_address = self.arp_scan.get_mac_address(network_interface=arp_table_element['interface'],
                                                        target_ip_address=arp_table_element['ip-address'],
                                                        timeout=1, retry=1, show_scan_percentage=False)
            self.assertEqual(mac_address, arp_table_element['mac-address'])
