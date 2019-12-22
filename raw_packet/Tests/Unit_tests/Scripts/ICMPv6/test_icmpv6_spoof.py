# region Description
"""
test_icmpv6_spoof.py: Unit tests for Raw-packet script: icmpv6_spoof.py
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from os.path import dirname, abspath
from subprocess import run, PIPE, STDOUT, Popen
from typing import List
from time import sleep
from os import kill
from signal import SIGTERM
from sys import path
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
class ScriptICMPV6ScanTest(unittest.TestCase):

    # region Properties - must change for your tests
    path.append(root_path)
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    your_mac_address: str = base.get_interface_mac_address(network_interface)
    your_ipv6_address: str = base.get_interface_ipv6_link_address(network_interface)
    router_ipv6_address: str = 'fe80::c6a8:1dff:fe8a:f9b0'
    router_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    target_ipv4_address: str = '192.168.0.4'
    target_mac_address: str = 'd8:96:95:f3:b4:67'
    target_username: str = 'vladimir'
    bad_network_interface: str = 'wlan0123'
    bad_mac_address: str = '01:23:45:67:89:0ab'
    bad_ipv6_address1: str = 'fd00:::123'
    bad_ipv6_address2: str = 'fd00::123'
    # endregion

    @staticmethod
    def convert_mac(mac_address: str) -> str:
        address_in_macos_arp_table: str = ''
        for part_of_address in mac_address.split(':'):
            if part_of_address[0] == '0':
                address_in_macos_arp_table += part_of_address[1] + ':'
            else:
                address_in_macos_arp_table += part_of_address + ':'
        return address_in_macos_arp_table[:-1]

    def get_ipv6_router_mac_address_over_ssh(self) -> str:
        gateway_mac_address: str = ''
        target_command = run(['ssh ' + self.target_username + '@' + self.target_ipv4_address +
                              ' "ndp -an | grep ' + self.router_ipv6_address + '"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_ndp_table: bytes = target_command.stdout
        target_ndp_table: str = target_ndp_table.decode('utf-8')
        target_ndp_table: List[str] = target_ndp_table.split(' ')
        try:
            return target_ndp_table[3]
        except IndexError:
            return gateway_mac_address

    def test01_router_advertisement(self):
        current_router_mac_address: str = ''
        while self.convert_mac(self.router_mac_address) != current_router_mac_address:
            current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
            sleep(1)
        icmpv6_spoof = Popen(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                             ' --technique 1 --target_mac ' + self.target_mac_address], shell=True)
        sleep(15)
        current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
        kill(icmpv6_spoof.pid, SIGTERM)
        self.assertEqual(self.convert_mac(self.your_mac_address), current_router_mac_address)

    def test02_neighbor_advertisement(self):
        current_router_mac_address: str = ''
        while self.convert_mac(self.router_mac_address) != current_router_mac_address:
            current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
            sleep(1)
        icmpv6_spoof = Popen(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                              ' --technique 2 --target_mac ' + self.target_mac_address], shell=True)
        sleep(15)
        current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
        kill(icmpv6_spoof.pid, SIGTERM)
        self.assertEqual(self.convert_mac(self.your_mac_address), current_router_mac_address)

    def test03_bad_interface(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' +
                            self.bad_network_interface], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.bad_network_interface, icmpv6_spoof_output)

    def test04_bad_target_mac_address(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_mac ' + self.bad_mac_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.bad_mac_address, icmpv6_spoof_output)

    def test05_target_ip_without_target_mac(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_ip ' + self.bad_ipv6_address1], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn('target_mac', icmpv6_spoof_output)

    def test06_bad_target_ip_address1(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_mac ' + self.target_mac_address +
                            ' --target_ip ' + self.bad_ipv6_address1], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.bad_ipv6_address1, icmpv6_spoof_output)

    def test07_bad_target_ip_address2(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_mac ' + self.target_mac_address +
                            ' --target_ip ' + self.bad_ipv6_address2], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.bad_ipv6_address2, icmpv6_spoof_output)

    def test08_bad_target_ip_address3(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_mac ' + self.target_mac_address +
                            ' --target_ip ' + self.router_ipv6_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.router_ipv6_address, icmpv6_spoof_output)

    def test09_bad_target_ip_address4(self):
        icmpv6_spoof = run(['python3 ' + root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + self.network_interface +
                            ' --technique 1 --target_mac ' + self.target_mac_address +
                            ' --target_ip ' + self.your_ipv6_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: bytes = icmpv6_spoof.stdout
        icmpv6_spoof_output: str = icmpv6_spoof_output.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(self.your_ipv6_address, icmpv6_spoof_output)

# endregion
