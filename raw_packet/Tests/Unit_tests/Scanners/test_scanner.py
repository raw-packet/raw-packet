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
from unittest.mock import patch
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
class ScannerTest(unittest.TestCase):

    # region Properties
    from raw_packet.Scanners.scanner import Scanner
    scanner: Scanner = Scanner()

    # region Must change this value for your test
    network_interface: str = 'wlan0'
    router_ipv4_address: str = '192.168.0.254'
    apple_device_mac_address: str = 'd8:96:95:f3:b4:67'
    # endregion

    # endregion

    def test_apple_device_selection(self):
        apple_devices = [['192.168.0.1', '12:34:56:78:90:ab', 'Apple, Inc.'],
                         ['192.168.0.2', '12:34:56:78:90:ac', 'Apple, Inc.']]
        bad_apple_devices = [['192.168.0.1', '12:34:56:78:90:ab', 'Apple, Inc.'],
                             ['192.168.0.2', '12:34:56:78:90:ac']]
        bad_apple_devices1 = [['192.168.0.1', '12:34:56:78:90:ab', 'Apple, Inc.'],
                              ['192.168.0.1234', '12:34:56:78:90:ac', 'Apple, Inc.']]
        bad_apple_devices2 = [['192.168.0.1', '12:34:56:78:90:ab', 'Apple, Inc.'],
                              ['192.168.0.2', '12:34:56:78:90:abc', 'Apple, Inc.']]

        self.assertIsNone(self.scanner.apple_device_selection(bad_apple_devices))
        self.assertIsNone(self.scanner.apple_device_selection(bad_apple_devices1))
        self.assertIsNone(self.scanner.apple_device_selection(bad_apple_devices2))
        self.assertIsNone(self.scanner.apple_device_selection(None))
        self.assertIsNone(self.scanner.apple_device_selection([]))

        selection_result = self.scanner.apple_device_selection([apple_devices[0]])
        self.assertEqual(apple_devices[0], selection_result)

        with patch('builtins.input', return_value='yes'):
            self.assertIsNone(self.scanner.apple_device_selection(apple_devices))

        with patch('builtins.input', return_value='3'):
            self.assertIsNone(self.scanner.apple_device_selection(apple_devices))

        with patch('builtins.input', return_value='1'):
            selection_result = self.scanner.apple_device_selection(apple_devices)
            self.assertEqual(apple_devices[0], selection_result)

        with patch('builtins.input', return_value='2'):
            selection_result = self.scanner.apple_device_selection(apple_devices)
            self.assertEqual(apple_devices[1], selection_result)

    def test_ipv6_device_selection(self):
        ipv6_devices = [{'ip-address': 'fd00::1', 'mac-address': '12:34:56:78:90:ab', 'vendor': 'Apple Inc.'},
                        {'ip-address': 'fd00::2', 'mac-address': '12:34:56:78:90:ac', 'vendor': 'Apple Inc.'}]
        bad_ipv6_devices1 = [{'ip-address': 'fd00::1', 'mac-address': '12:34:56:78:90:ab', 'vendor': 'Apple Inc.'},
                             {'ip-address': 'fd00::2', 'mac-address': '12:34:56:78:90:ac'}]
        bad_ipv6_devices2 = [{'ip-address': 'fd00::1', 'mac-address': '12:34:56:78:90:ab', 'vendor': 'Apple Inc.'},
                             {'ip-address': 'fd00::2', 'mac-address': '12:34:56:78:90:ac', 'test': 'Apple Inc.'}]
        bad_ipv6_devices3 = [{'ip-address': 'fd00::1', 'mac-address': '12:34:56:78:90:ab', 'vendor': 'Apple Inc.'},
                             {'ip-address': 'fd00:::2', 'mac-address': '12:34:56:78:90:ac', 'vendor': 'Apple Inc.'}]
        bad_ipv6_devices4 = [{'ip-address': 'fd00::1', 'mac-address': '12:34:56:78:90:ab', 'vendor': 'Apple Inc.'},
                             {'ip-address': 'fd00::2', 'mac-address': '12:34:56:78:90:abc', 'vendor': 'Apple Inc.'}]

        self.assertIsNone(self.scanner.ipv6_device_selection(bad_ipv6_devices1))
        self.assertIsNone(self.scanner.ipv6_device_selection(bad_ipv6_devices2))
        self.assertIsNone(self.scanner.ipv6_device_selection(bad_ipv6_devices3))
        self.assertIsNone(self.scanner.ipv6_device_selection(bad_ipv6_devices4))
        self.assertIsNone(self.scanner.ipv6_device_selection(None))
        self.assertIsNone(self.scanner.ipv6_device_selection([]))

        selection_result = self.scanner.ipv6_device_selection([ipv6_devices[0]])
        self.assertEqual(ipv6_devices[0], selection_result)

        with patch('builtins.input', return_value='yes'):
            self.assertIsNone(self.scanner.ipv6_device_selection(ipv6_devices))

        with patch('builtins.input', return_value='3'):
            self.assertIsNone(self.scanner.ipv6_device_selection(ipv6_devices))

        with patch('builtins.input', return_value='1'):
            self.assertEqual(self.scanner.ipv6_device_selection(ipv6_devices), ipv6_devices[0])

        with patch('builtins.input', return_value='2'):
            self.assertEqual(self.scanner.ipv6_device_selection(ipv6_devices), ipv6_devices[1])

    def test_find_ip_in_local_network(self):
        scan_result = self.scanner.find_ip_in_local_network(network_interface=self.network_interface)
        self.assertIsNotNone(scan_result)
        self.assertIn(self.router_ipv4_address, scan_result)

    def test_find_apple_devices_by_mac(self):
        scan_results = self.scanner.find_apple_devices_by_mac(network_interface=self.network_interface)
        self.assertIsNotNone(scan_results)
        find_apple_device: bool = False
        for scan_result in scan_results:
            if self.apple_device_mac_address in scan_result:
                find_apple_device = True
                break
        self.assertTrue(find_apple_device)

    def test_find_apple_devices_by_mac_ipv6(self):
        scan_results = self.scanner.find_apple_devices_by_mac_ipv6(network_interface=self.network_interface)
        self.assertIsNotNone(scan_results)
        find_apple_device: bool = False
        for scan_result in scan_results:
            if self.apple_device_mac_address in scan_result:
                find_apple_device = True
                break
        self.assertTrue(find_apple_device)

    def test_find_ipv6_devices(self):
        scan_results = self.scanner.find_ipv6_devices(network_interface=self.network_interface)
        self.assertIsNotNone(scan_results)
        find_apple_device: bool = False
        for scan_result in scan_results:
            if self.apple_device_mac_address == scan_result['mac-address']:
                find_apple_device = True
                break
        self.assertTrue(find_apple_device)

    def test_find_apple_devices_with_nmap(self):
        scan_results = self.scanner.find_apple_devices_with_nmap(network_interface=self.network_interface)
        self.assertIsNotNone(scan_results)
        find_apple_device: bool = False
        for scan_result in scan_results:
            if self.apple_device_mac_address in scan_result:
                find_apple_device = True
                break
        self.assertTrue(find_apple_device)

# endregion
