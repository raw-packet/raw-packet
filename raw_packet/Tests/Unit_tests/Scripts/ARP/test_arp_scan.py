# region Description
"""
test_arp_scan.py: Unit tests for Raw-packet script: arp_scan.py
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
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
__copyright__ = 'Copyright 2019, Raw-packet Project'
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
    network_interface: str = 'wlan0'
    router_ipv4_address: str = '192.168.0.254'
    router_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    bad_network_interface: str = 'wlan0123'
    bad_ipv4_address: str = '192.168.0.1234'
    # endregion

    def test_main(self):
        arp_scan = run(['python3 ' + root_path + '/Scripts/ARP/arp_scan.py -i ' + self.network_interface],
                       shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(self.router_ipv4_address, arp_scan_output)
        self.assertIn(self.router_mac_address, arp_scan_output)

    def test_main_bad_interface(self):
        arp_scan = run(['python3 ' + root_path + '/Scripts/ARP/arp_scan.py -i ' + self.bad_network_interface],
                       shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(self.bad_network_interface, arp_scan_output)

    def test_main_target_ip(self):
        arp_scan = run(['python3 ' + root_path + '/Scripts/ARP/arp_scan.py -i ' + self.network_interface + ' -T ' +
                        self.router_ipv4_address], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(self.router_ipv4_address, arp_scan_output)
        self.assertIn(self.router_mac_address, arp_scan_output)

    def test_main_bad_target_ip(self):
        arp_scan = run(['python3 ' + root_path + '/Scripts/ARP/arp_scan.py -i ' + self.network_interface + ' -T ' +
                        self.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_scan_output: bytes = arp_scan.stdout
        arp_scan_output: str = arp_scan_output.decode('utf-8')
        print(arp_scan_output)
        self.assertIn(self.bad_ipv4_address, arp_scan_output)

# endregion
