# region Description
"""
test_icmpv6_scan.py: Unit tests for Raw-packet script: icmpv6_scan.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from os.path import dirname, abspath
from subprocess import run, PIPE
import unittest

root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
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
class ScriptICMPV6ScanTest(unittest.TestCase):

    # region Properties - must change for your tests
    network_interface: str = 'wlan0'
    router_ipv6_address: str = 'fe80::c6a8:1dff:fe8a:f9b0'
    router_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    router_vendor: str = 'D-Link International'
    device_ipv6_address: str = 'fe80::ba27:ebff:fe3e:4c85'
    device_mac_address: str = 'b8:27:eb:3e:4c:85'
    bad_network_interface: str = 'wlan0123'
    bad_mac_address: str = '01:23:45:67:89:0ab'
    # endregion

    def test01_main(self):
        icmpv6_scan = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + self.network_interface],
                          shell=True, stdout=PIPE)
        icmpv6_scan_output: bytes = icmpv6_scan.stdout
        icmpv6_scan_output: str = icmpv6_scan_output.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(self.device_ipv6_address, icmpv6_scan_output)
        self.assertIn(self.device_mac_address, icmpv6_scan_output)

    def test02_main_set_target_mac_address(self):
        icmpv6_scan = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + self.network_interface +
                           ' --target_mac ' + self.device_mac_address], shell=True, stdout=PIPE)
        icmpv6_scan_output: bytes = icmpv6_scan.stdout
        icmpv6_scan_output: str = icmpv6_scan_output.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(self.device_ipv6_address, icmpv6_scan_output)
        self.assertIn(self.device_mac_address, icmpv6_scan_output)

    def test03_router_search(self):
        icmpv6_scan = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + self.network_interface +
                           ' --router_search'], shell=True, stdout=PIPE)
        icmpv6_scan_output: bytes = icmpv6_scan.stdout
        icmpv6_scan_output: str = icmpv6_scan_output.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(self.router_ipv6_address, icmpv6_scan_output)
        self.assertIn(self.router_mac_address, icmpv6_scan_output)
        self.assertIn(self.router_vendor, icmpv6_scan_output)

    def test04_main_bad_interface(self):
        icmpv6_scan = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + self.bad_network_interface],
                          shell=True, stdout=PIPE)
        icmpv6_scan_output: bytes = icmpv6_scan.stdout
        icmpv6_scan_output: str = icmpv6_scan_output.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(self.bad_network_interface, icmpv6_scan_output)

    def test05_main_bad_target_mac_address(self):
        icmpv6_scan = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + self.network_interface +
                        ' --target_mac ' + self.bad_mac_address], shell=True, stdout=PIPE)
        icmpv6_scan_output: bytes = icmpv6_scan.stdout
        icmpv6_scan_output: str = icmpv6_scan_output.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(self.bad_mac_address, icmpv6_scan_output)

# endregion
