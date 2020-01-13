# region Description
"""
test_arp_scan.py: Unit tests for Raw-packet script: arp_scan.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from os.path import dirname, abspath
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
class ScriptArpScanTest(unittest.TestCase):

    # region Properties
    from raw_packet.Tests.Unit_tests.variables import Variables
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    # endregion

    def test01_main(self):
        arp_scan = run(['python3 ' + self.root_path + '/Scripts/ARP/arp_scan.py -i ' +
                        ScriptArpScanTest.Variables.test_network_interface], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.router_ipv4_address, arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.router_mac_address, arp_scan_output)

    def test02_main_bad_interface(self):
        arp_scan = run(['python3 ' + self.root_path + '/Scripts/ARP/arp_scan.py -i ' + 
                        ScriptArpScanTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.bad_network_interface, arp_scan_output)

    def test03_main_target_ip(self):
        arp_scan = run(['python3 ' + self.root_path + '/Scripts/ARP/arp_scan.py -i ' + 
                        ScriptArpScanTest.Variables.test_network_interface + ' -T ' + 
                        ScriptArpScanTest.Variables.router_ipv4_address], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.router_ipv4_address, arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.router_mac_address, arp_scan_output)

    def test04_main_bad_target_ip(self):
        arp_scan = run(['python3 ' + self.root_path + '/Scripts/ARP/arp_scan.py -i ' + 
                        ScriptArpScanTest.Variables.test_network_interface + ' -T ' + 
                        ScriptArpScanTest.Variables.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(ScriptArpScanTest.Variables.bad_ipv4_address, arp_scan_output)

# endregion
