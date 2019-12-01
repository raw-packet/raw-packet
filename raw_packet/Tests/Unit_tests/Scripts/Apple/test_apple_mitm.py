# region Description
"""
test_apple_mitm.py: Unit tests for Raw-packet script: apple_mitm.py
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
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
from typing import List
import unittest
import paramiko

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


# region Main class - ScriptAppleMitmTest
class ScriptAppleMitmTest(unittest.TestCase):

    # region Properties
    path.append(root_path)
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    your_mac_address: str = base.get_interface_mac_address(network_interface)
    wired_interface: str = 'eth0'
    deauth_interface: str = 'wlan1'
    target_ipv4_address: str = '192.168.0.4'
    target_username: str = 'vladimir'
    gateway_ipv4_address: str = '192.168.0.254'
    gateway_mac_address: str = 'c4:a8:1d:8a:f9:b0'
    bad_technique1: bytes = b'test'
    bad_technique2: bytes = b'123'
    bad_network_interface: str = 'wlan0123'
    bad_ipv4_address: str = '192.168.0.1234'
    bad_mac_address: str = '12:34:56:78:90:abc'
    # endregion

    def test01_main_bad_technique1(self):
        mitm_process = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique1)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not digit', mitm_process_stdout.decode())

    def test02_main_bad_technique2(self):
        mitm_process = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique2)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not within range', mitm_process_stdout.decode())

    def test03_main_bad_technique1(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T ' +
                            self.bad_technique1.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not digit', mitm_process_output)

    def test04_main_bad_technique2(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T ' +
                            self.bad_technique2.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not within range', mitm_process_output)

    def test05_main_bad_disconnect_technique1(self):
        mitm_process = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique1)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not digit', mitm_process_stdout.decode())

    def test06_main_bad_disconnect_technique2(self):
        mitm_process = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1'],
                             stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: bytes = mitm_process.communicate(input=self.bad_technique2)[0]
        print(mitm_process_stdout.decode())
        self.assertIn('not within range', mitm_process_stdout.decode())

    def test07_main_bad_disconnect_technique1(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D ' +
                            self.bad_technique1.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not digit', mitm_process_output)

    def test08_main_bad_disconnect_technique2(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D ' +
                            self.bad_technique2.decode('utf-8')], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not within range', mitm_process_output)

    def test09_main_bad_listen_interface(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            self.bad_network_interface], stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(self.bad_network_interface, mitm_process_output)

    def test10_main_bad_listen_interface(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 2 -l ' +
                            self.wired_interface + ' -d ' + self.deauth_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('not connected to WiFi AP', mitm_process_output)

    def test11_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            self.network_interface + ' -d ' + self.bad_network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(self.bad_network_interface, mitm_process_output)

    def test12_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            self.network_interface + ' -d ' + self.network_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('must be differ', mitm_process_output)

    def test13_main_bad_deauth_interface(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            self.network_interface + ' -d ' + self.wired_interface],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn('is wired', mitm_process_output)

    def test14_main_bad_target_ip(self):
        mitm_process = run(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 1 -l ' +
                            self.network_interface + ' -t ' + self.bad_ipv4_address],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_output: bytes = mitm_process.stdout
        mitm_process_output: str = mitm_process_output.decode('utf-8')
        print(mitm_process_output)
        self.assertIn(self.bad_ipv4_address, mitm_process_output)
        self.assertIn('Target IP address', mitm_process_output)

    def get_gateway_mac_address_over_ssh(self) -> str:
        gateway_mac_address: str = ''
        target_command = run(['ssh ' + self.target_username + '@' + self.target_ipv4_address +
                              ' "arp -an | grep ' + self.gateway_ipv4_address + '"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_arp_table: bytes = target_command.stdout
        target_arp_table: str = target_arp_table.decode('utf-8')
        target_arp_table: List[str] = target_arp_table.split(' ')
        try:
            return target_arp_table[3]
        except IndexError:
            return gateway_mac_address

    def test15_main_arp_spoofing(self):
        address_in_macos_arp_table: str = ''
        for part_of_address in self.your_mac_address.split(':'):
            if part_of_address[0] == '0':
                address_in_macos_arp_table += part_of_address[1] + ':'
            else:
                address_in_macos_arp_table += part_of_address + ':'
        address_in_macos_arp_table: str = address_in_macos_arp_table[:-1]
        current_gateway_mac_address: str = self.get_gateway_mac_address_over_ssh()
        self.assertEqual(self.gateway_mac_address, current_gateway_mac_address)
        mitm_process = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_mitm.py -T 1 -D 3 -l ' +
                              self.network_interface + ' -t ' + self.target_ipv4_address +
                              ' >/tmp/apple_mitm.output'], shell=True)
        sleep(15)
        current_gateway_mac_address: str = self.get_gateway_mac_address_over_ssh()
        kill(mitm_process.pid, SIGTERM)
        self.assertEqual(address_in_macos_arp_table, current_gateway_mac_address)


# endregion
