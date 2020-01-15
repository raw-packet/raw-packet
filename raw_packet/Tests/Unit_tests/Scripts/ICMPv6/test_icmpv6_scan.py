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
from sys import path
from subprocess import run, PIPE
import unittest
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

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Tests.Unit_tests.variables import Variables
    # endregion

    def test01_main(self):
        icmpv6_scan = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + 
                           ScriptICMPV6ScanTest.Variables.test_network_interface], shell=True, stdout=PIPE)
        icmpv6_scan_output: str = icmpv6_scan.stdout.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_mac_address, icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_ipv6_link_address, icmpv6_scan_output)

    def test02_main_set_target_mac_address(self):
        icmpv6_scan = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + 
                           ScriptICMPV6ScanTest.Variables.test_network_interface +
                           ' --target_mac ' + ScriptICMPV6ScanTest.Variables.router_mac_address],
                          shell=True, stdout=PIPE)
        icmpv6_scan_output: str = icmpv6_scan.stdout.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_mac_address, icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_ipv6_link_address, icmpv6_scan_output)

    def test03_router_search(self):
        icmpv6_scan = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + 
                           ScriptICMPV6ScanTest.Variables.test_network_interface +
                           ' --router_search'], shell=True, stdout=PIPE)
        icmpv6_scan_output: str = icmpv6_scan.stdout.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_mac_address, icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_ipv6_link_address, icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_vendor, icmpv6_scan_output)

    def test04_main_bad_interface(self):
        icmpv6_scan = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' +
                           ScriptICMPV6ScanTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        icmpv6_scan_output: str = icmpv6_scan.stdout.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.bad_network_interface, icmpv6_scan_output)

    def test05_main_bad_target_mac_address(self):
        icmpv6_scan = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_scan.py -i ' + 
                           ScriptICMPV6ScanTest.Variables.test_network_interface +
                           ' --target_mac ' + ScriptICMPV6ScanTest.Variables.bad_mac_address], shell=True, stdout=PIPE)
        icmpv6_scan_output: str = icmpv6_scan.stdout.decode('utf-8')
        print(icmpv6_scan_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.bad_mac_address, icmpv6_scan_output)

# endregion
