# region Description
"""
test_apple_mitm.py: Unit tests for Raw-packet script: apple_mitm.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from os import system, kill
from signal import SIGTERM
from time import sleep, time
from subprocess import run, Popen, PIPE, STDOUT
from unittest.mock import patch
from typing import List, Union
import unittest
import paramiko
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


# region Main class - ScriptAppleMitmTest
class ScriptAppleMitmTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Tests.Unit_tests.variables import Variables
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    test_domain: str = 'google.com'
    bad_technique1: bytes = b'test'
    bad_technique2: bytes = b'123'
    # endregion

    @staticmethod
    def restart_network_interface_over_ssh(network_interface: Union[None, str] = None) -> None:
        if network_interface is None:
            network_interface = ScriptAppleMitmTest.Variables.apple_device_network_interface
        run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_root_username + '@' +
             ScriptAppleMitmTest.Variables.apple_device_ipv4_address + ' "ifconfig ' + network_interface +
             ' down && ifconfig ' + network_interface + ' up"'], shell=True)

    @staticmethod
    def get_ipv6_gateway_mac_address_over_ssh(host: Union[None, str] = None) -> str:
        if host is None:
            host = ScriptAppleMitmTest.Variables.apple_device_ipv4_address
        gateway_mac_address: str = ''
        target_command = run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_username + '@' + host +
                              ' "ndp -an | grep ' + ScriptAppleMitmTest.Variables.router_ipv6_link_address + '"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_ndp_table: bytes = target_command.stdout
        target_ndp_table: str = target_ndp_table.decode('utf-8')
        target_ndp_table: List[str] = target_ndp_table.split(' ')
        try:
            return target_ndp_table[3]
        except IndexError:
            return gateway_mac_address

    @staticmethod
    def get_ipv4_gateway_mac_address_over_ssh(host: Union[None, str] = None) -> str:
        if host is None:
            host = ScriptAppleMitmTest.Variables.apple_device_ipv4_address
        gateway_mac_address: str = ''
        target_command = run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_username + '@' + host +
                              ' "arp -an | grep ' + ScriptAppleMitmTest.Variables.router_ipv4_address + '"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_arp_table: bytes = target_command.stdout
        target_arp_table: str = target_arp_table.decode('utf-8')
        target_arp_table: List[str] = target_arp_table.split(' ')
        try:
            return target_arp_table[3]
        except IndexError:
            return gateway_mac_address

    @staticmethod
    def get_ipv4_gateway_ip_address_over_ssh(host: Union[None, str] = None) -> str:
        if host is None:
            host = ScriptAppleMitmTest.Variables.apple_device_ipv4_address
        target_command = run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_username + '@' + host +
                              ' "route -n get default | grep gateway"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_gateway: bytes = target_command.stdout
        target_gateway: str = target_gateway.decode('utf-8')
        if 'not in table' in target_gateway:
            return 'no gateway'
        target_gateway: str = target_gateway.replace(' ', '').replace('gateway:', '').replace('\t', '')
        if target_gateway.endswith('\n'):
            target_gateway: str = target_gateway[:-1]
        return target_gateway

    @staticmethod
    def restart_wifi_over_ssh(host: Union[None, str] = None) -> None:
        if host is None:
            host = ScriptAppleMitmTest.Variables.apple_device_ipv4_address
        run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_username + '@' + host +
             ' "networksetup -setairportpower \"Wi-Fi\" off; networksetup -setairportpower \"Wi-Fi\" on"'], shell=True)

    @staticmethod
    def get_domain_address_over_ssh(type: str, domain: str) -> str:
        dig_command = run(['ssh ' + ScriptAppleMitmTest.Variables.apple_device_username + '@' +
                           ScriptAppleMitmTest.Variables.apple_device_ipv4_address +
                           ' "dig +short -t ' + type + ' ' + domain + '"'], shell=True, stdout=PIPE, stderr=STDOUT)
        dig_result: bytes = dig_command.stdout
        dig_result: str = dig_result.decode('utf-8')
        if dig_result.endswith('\n'):
            dig_result: str = dig_result[:-1]
        return dig_result

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/apple_mitm.py') != -1:
            kill(self.base.get_process_pid('/apple_mitm.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def restart_dhcp_server_over_ssh() -> None:
        run(['ssh ' + ScriptAppleMitmTest.Variables.router_root_username + '@' +
             ScriptAppleMitmTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptAppleMitmTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.restart_dhcp_server_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptAppleMitmTest.Variables.apple_device_ipv4_address)

    def test01_main_bad_technique1(self):
        mitm_process = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique1)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not digit', mitm_process_stdout.decode())

    def test02_main_bad_technique2(self):
        mitm_process = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique2)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not within range', mitm_process_stdout.decode())

    def test03_main_bad_technique1(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T ' +
                            self.bad_technique1.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not digit', mitm_process_output)

    def test04_main_bad_technique2(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T ' +
                            self.bad_technique2.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not within range', mitm_process_output)

    def test05_main_bad_disconnect_technique1(self):
        mitm_process = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique1)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not digit', mitm_process_stdout.decode())

    def test06_main_bad_disconnect_technique2(self):
        mitm_process = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique2)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not within range', mitm_process_stdout.decode())

    def test07_main_bad_disconnect_technique1(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D ' +
                            self.bad_technique1.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not digit', mitm_process_output)

    def test08_main_bad_disconnect_technique2(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D ' +
                            self.bad_technique2.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not within range', mitm_process_output)

    def test09_main_bad_listen_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            ScriptAppleMitmTest.Variables.bad_network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(ScriptAppleMitmTest.Variables.bad_network_interface, mitm_process_output)

    def test10_main_bad_listen_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 2 -l ' +
                            ScriptAppleMitmTest.Variables.test_network_interface + ' -d ' +
                            ScriptAppleMitmTest.Variables.test_wireless_listen_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not connected to WiFi AP', mitm_process_output)

    def test11_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            ScriptAppleMitmTest.Variables.test_network_interface + ' -d ' +
                            ScriptAppleMitmTest.Variables.bad_network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(ScriptAppleMitmTest.Variables.bad_network_interface, mitm_process_output)

    def test12_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            ScriptAppleMitmTest.Variables.test_network_interface + ' -d ' +
                            ScriptAppleMitmTest.Variables.test_network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('must be differ', mitm_process_output)

    def test13_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            ScriptAppleMitmTest.Variables.test_wireless_listen_interface + ' -d ' +
                            ScriptAppleMitmTest.Variables.test_network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('is wired', mitm_process_output)

    def test14_main_bad_target_ip(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            ScriptAppleMitmTest.Variables.test_network_interface + ' -t ' +
                            ScriptAppleMitmTest.Variables.bad_ipv4_address],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(ScriptAppleMitmTest.Variables.bad_ipv4_address, mitm_process_output)
        self.assertIn('Target IP address', mitm_process_output)

    def test15_main_arp_spoofing(self):
        self.restart_network_interface_over_ssh()
        current_gateway_mac_address: str = self.get_ipv4_gateway_mac_address_over_ssh()
        current_domain_ipv4_address: str = self.get_domain_address_over_ssh('A', self.test_domain)
        current_domain_ipv6_address: str = self.get_domain_address_over_ssh('AAAA', self.test_domain)
        self.assertEqual(self.base.macos_encode_mac_address(ScriptAppleMitmTest.Variables.router_mac_address), 
                         current_gateway_mac_address)
        self.assertNotEqual(current_domain_ipv4_address, ScriptAppleMitmTest.Variables.your_ipv4_address)
        self.assertNotEqual(current_domain_ipv6_address, ScriptAppleMitmTest.Variables.your_ipv6_link_address)
        Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 3 -l ' +
               ScriptAppleMitmTest.Variables.test_network_interface + ' -t ' +
               ScriptAppleMitmTest.Variables.apple_device_ipv4_address + ' >/tmp/apple_mitm.output'], shell=True)
        sleep(15)
        current_gateway_mac_address: str = self.get_ipv4_gateway_mac_address_over_ssh()
        current_domain_ipv4_address: str = self.get_domain_address_over_ssh('A', self.test_domain)
        current_domain_ipv6_address: str = self.get_domain_address_over_ssh('AAAA', self.test_domain)
        self.base.kill_process_by_name('/apple_mitm.py')
        self.assertEqual(self.base.macos_encode_mac_address(ScriptAppleMitmTest.Variables.your_mac_address),
                         current_gateway_mac_address)
        self.assertEqual(current_domain_ipv4_address, ScriptAppleMitmTest.Variables.your_ipv4_address)
        self.assertEqual(current_domain_ipv6_address, ScriptAppleMitmTest.Variables.your_ipv6_link_address)
        self.restart_network_interface_over_ssh()

    # Not work
    # def test16_main_second_dhcp(self):
    #     current_gateway_mac_address: str = self.get_ipv4_gateway_mac_address_over_ssh()
    #     current_gateway_ipv4_address: str = self.get_ipv4_gateway_ip_address_over_ssh()
    #     current_domain_ipv4_address: str = self.get_domain_address_over_ssh('A', self.test_domain)
    #     current_domain_ipv6_address: str = self.get_domain_address_over_ssh('AAAA', self.test_domain)
    #     self.assertEqual(self.base.macos_encode_mac_address(ScriptAppleMitmTest.Variables.router_mac_address), current_gateway_mac_address)
    #     self.assertEqual(ScriptAppleMitmTest.Variables.router_ipv4_address, current_gateway_ipv4_address)
    #     self.assertNotEqual(current_domain_ipv4_address, ScriptAppleMitmTest.Variables.your_ipv4_address)
    #     self.assertNotEqual(current_domain_ipv6_address, ScriptAppleMitmTest.Variables.your_ipv6_link_address)
    #     Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 2 -D 2 -l ' + self.network_interface +
    #            ' -d ' + self.deauth_interface + ' -t ' + ScriptAppleMitmTest.Variables.apple_device_ipv4_address + ' >/tmp/apple_mitm.output'],
    #           shell=True)
    #     sleep(25)
    #     current_gateway_ipv4_address: str = self.get_ipv4_gateway_ip_address_over_ssh()
    #     self.base.kill_process_by_name('/apple_mitm.py')
    #     self.assertEqual('no gateway', current_gateway_ipv4_address)
    #     self.restart_wifi_over_ssh()

    # Not work
    def test17_main_predict_dhcp(self):
        self.check_apple_device_connected()
        current_gateway_mac_address: str = self.get_ipv4_gateway_mac_address_over_ssh()
        current_gateway_ipv4_address: str = self.get_ipv4_gateway_ip_address_over_ssh()
        current_domain_ipv4_address: str = self.get_domain_address_over_ssh('A', self.test_domain)
        current_domain_ipv6_address: str = self.get_domain_address_over_ssh('AAAA', self.test_domain)
        self.assertEqual(self.base.macos_encode_mac_address(ScriptAppleMitmTest.Variables.router_mac_address),
                         current_gateway_mac_address)
        self.assertEqual(ScriptAppleMitmTest.Variables.router_ipv4_address, current_gateway_ipv4_address)
        self.assertNotEqual(current_domain_ipv4_address, ScriptAppleMitmTest.Variables.your_ipv4_address)
        self.assertNotEqual(current_domain_ipv6_address, ScriptAppleMitmTest.Variables.your_ipv6_link_address)
        Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_mitm.py -T 3 -D 1 -l ' +
               ScriptAppleMitmTest.Variables.test_network_interface + ' -n ' +
               ScriptAppleMitmTest.Variables.apple_device_new_ipv4_address + ' -t ' +
               ScriptAppleMitmTest.Variables.apple_device_ipv4_address + ' >/tmp/apple_mitm.output'], shell=True)
        sleep(35)
        current_gateway_ipv4_address: str = \
            self.get_ipv4_gateway_ip_address_over_ssh(ScriptAppleMitmTest.Variables.apple_device_new_ipv4_address)
        self.base.kill_process_by_name('/apple_mitm.py')
        self.assertEqual(ScriptAppleMitmTest.Variables.your_ipv4_address, current_gateway_ipv4_address)
        self.base.success_text('MiTM success!')
        self.check_apple_device_connected()

# endregion
