# region Description
"""
test_icmpv6_spoof.py: Unit tests for Raw-packet script: icmpv6_spoof.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
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
from re import sub
from typing import Union
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

    # region Properties - must change for your tests
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    # endregion

    @staticmethod
    def get_ipv6_router_mac_address_over_ssh() -> str:
        gateway_mac_address: str = ''
        target_command = run(['ssh ' + ScriptICMPV6ScanTest.Variables.apple_device_username + '@' + 
                              ScriptICMPV6ScanTest.Variables.apple_device_ipv4_address + ' "ndp -an | grep ' + 
                              ScriptICMPV6ScanTest.Variables.router_ipv6_link_address + '"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_ndp_table: str = target_command.stdout.decode('utf-8')
        target_ndp_table: str = sub(r' +', ' ', target_ndp_table)
        target_ndp_table: List[str] = target_ndp_table.split(' ')
        try:
            return target_ndp_table[1]
        except IndexError:
            return gateway_mac_address

    @staticmethod
    def restart_network_interface_over_ssh(network_interface: Union[None, str] = None) -> None:
        if network_interface is None:
            network_interface = ScriptICMPV6ScanTest.Variables.apple_device_network_interface
        run(['ssh ' + ScriptICMPV6ScanTest.Variables.apple_device_root_username + '@' +
             ScriptICMPV6ScanTest.Variables.apple_device_ipv4_address + ' "ifconfig ' + network_interface +
             ' down && ifconfig ' + network_interface + ' up"'], shell=True)

    @staticmethod
    def restart_dhcp_server_over_ssh() -> None:
        run(['ssh ' + ScriptICMPV6ScanTest.Variables.router_root_username + '@' +
             ScriptICMPV6ScanTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    def test01_neighbor_advertisement(self):
        while self.base.macos_encode_mac_address(ScriptICMPV6ScanTest.Variables.router_mac_address) != \
                self.get_ipv6_router_mac_address_over_ssh():
            self.restart_network_interface_over_ssh()
            sleep(10)
        Popen(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' +
               ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 2 --target_mac ' +
               ScriptICMPV6ScanTest.Variables.apple_device_mac_address], shell=True)
        sleep(20)
        current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
        while self.base.get_process_pid('/icmpv6_spoof.py') != -1:
            kill(self.base.get_process_pid('/icmpv6_spoof.py'), SIGTERM)
            sleep(0.5)
        self.assertEqual(self.base.macos_encode_mac_address(ScriptICMPV6ScanTest.Variables.your_mac_address),
                         current_router_mac_address)

    def test02_router_advertisement(self):
        while self.base.macos_encode_mac_address(ScriptICMPV6ScanTest.Variables.router_mac_address) != \
                self.get_ipv6_router_mac_address_over_ssh():
            self.restart_network_interface_over_ssh()
            sleep(10)
        Popen(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' +
               ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
               ScriptICMPV6ScanTest.Variables.apple_device_mac_address], shell=True)
        sleep(20)
        current_router_mac_address = self.get_ipv6_router_mac_address_over_ssh()
        while self.base.get_process_pid('/icmpv6_spoof.py') != -1:
            kill(self.base.get_process_pid('/icmpv6_spoof.py'), SIGTERM)
            sleep(0.5)
        self.assertEqual(self.base.macos_encode_mac_address(ScriptICMPV6ScanTest.Variables.your_mac_address),
                         current_router_mac_address)

    def test03_bad_interface(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' +
                            ScriptICMPV6ScanTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.bad_network_interface, icmpv6_spoof_output)

    def test04_bad_target_mac_address(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
                            ScriptICMPV6ScanTest.Variables.bad_mac_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.bad_mac_address, icmpv6_spoof_output)

    def test05_target_ip_without_target_mac(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_ip ' +
                            ScriptICMPV6ScanTest.Variables.bad_ipv6_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn('target_mac', icmpv6_spoof_output)

    def test06_bad_target_ip_address1(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
                            ScriptICMPV6ScanTest.Variables.apple_device_mac_address + ' --target_ip ' +
                            ScriptICMPV6ScanTest.Variables.bad_ipv6_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.bad_ipv6_address, icmpv6_spoof_output)

    def test07_bad_target_ip_address2(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
                            ScriptICMPV6ScanTest.Variables.apple_device_mac_address + ' --target_ip ' +
                            ScriptICMPV6ScanTest.Variables.router_ipv6_glob_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_ipv6_glob_address, icmpv6_spoof_output)

    def test08_bad_target_ip_address3(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
                            ScriptICMPV6ScanTest.Variables.apple_device_mac_address + ' --target_ip ' +
                            ScriptICMPV6ScanTest.Variables.router_ipv6_link_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.router_ipv6_link_address, icmpv6_spoof_output)

    def test09_bad_target_ip_address4(self):
        icmpv6_spoof = run(['python3 ' + self.root_path + '/Scripts/ICMPv6/icmpv6_spoof.py -i ' + 
                            ScriptICMPV6ScanTest.Variables.test_network_interface + ' --technique 1 --target_mac ' +
                            ScriptICMPV6ScanTest.Variables.apple_device_mac_address + ' --target_ip ' +
                            ScriptICMPV6ScanTest.Variables.your_ipv6_link_address], shell=True, stdout=PIPE)
        icmpv6_spoof_output: str = icmpv6_spoof.stdout.decode('utf-8')
        print(icmpv6_spoof_output)
        self.assertIn(ScriptICMPV6ScanTest.Variables.your_ipv6_link_address, icmpv6_spoof_output)

# endregion
