# region Description
"""
test_arp_scan.py: Unit tests for Raw-packet script: arp_scan.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Tests.Unit_tests.variables import Variables
from raw_packet.Tests.Unit_tests.context_manager import ContextManager
from raw_packet.Scripts.ARP.arp_scan import scan as arp_scan
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


# region Main class - ScriptArpScanTest
class ScriptArpScanTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    context_manager: ContextManager = ContextManager()
    # endregion

    def test01_main(self):
        with self.context_manager.captured_output() as (out, err):
            arp_scan(interface=self.variables.your.network_interface)
        arp_scan_output: str = out.getvalue()
        print(arp_scan_output)
        self.assertIn(self.variables.router.ipv4_address, arp_scan_output)
        self.assertIn(self.variables.router.mac_address, arp_scan_output)
        self.assertIn(self.variables.router.vendor, arp_scan_output)
        self.assertIn(self.variables.target.ipv4_address, arp_scan_output)
        self.assertIn(self.variables.target.mac_address, arp_scan_output)
        self.assertIn(self.variables.target.vendor, arp_scan_output)

    def test02_main_bad_interface(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                arp_scan(interface=self.variables.bad.network_interface)
        arp_scan_output: str = out.getvalue()
        print(arp_scan_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.network_interface, arp_scan_output)

    def test03_main_target_ip(self):
        with self.context_manager.captured_output() as (out, err):
            arp_scan(interface=self.variables.your.network_interface,
                     target_ip=self.variables.router.ipv4_address)
        arp_scan_output: str = out.getvalue()
        print(arp_scan_output)
        self.assertIn(self.variables.router.ipv4_address, arp_scan_output)
        self.assertIn(self.variables.router.mac_address, arp_scan_output)
        self.assertIn(self.variables.router.vendor, arp_scan_output)

        with self.context_manager.captured_output() as (out, err):
            arp_scan(interface=self.variables.your.network_interface,
                     target_ip=self.variables.target.ipv4_address)
        arp_scan_output: str = out.getvalue()
        print(arp_scan_output)
        self.assertIn(self.variables.target.ipv4_address, arp_scan_output)
        self.assertIn(self.variables.target.mac_address, arp_scan_output)
        self.assertIn(self.variables.target.vendor, arp_scan_output)

    def test04_main_bad_target_ip(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                arp_scan(interface=self.variables.your.network_interface,
                         target_ip=self.variables.bad.ipv4_address)
        arp_scan_output: str = out.getvalue()
        print(arp_scan_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.ipv4_address, arp_scan_output)

# endregion
