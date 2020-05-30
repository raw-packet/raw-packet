# region Description
"""
test_apple_rogue_dhcp.py: Unit tests for Raw-packet script: apple_dhcp_server.py
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


# region Main class - ScriptAppleRogueDhcpTest
class ScriptAppleRogueDhcpTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Tests.Unit_tests.variables import Variables
    from raw_packet.Utils.base import Base
    base: Base = Base()
    # endregion

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/apple_dhcp_server.py') != -1:
            kill(self.base.get_process_pid('/apple_dhcp_server.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def restart_dhcp_server_over_ssh() -> None:
        run(['ssh ' + ScriptAppleRogueDhcpTest.Variables.router_root_username + '@' +
             ScriptAppleRogueDhcpTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptAppleRogueDhcpTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.restart_dhcp_server_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptAppleRogueDhcpTest.Variables.apple_device_ipv4_address)

    def test01_start_without_params(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_dhcp_server.py'],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: str = mitm_process.stdout.decode('utf-8')
        print(mitm_process_stdout)
        self.assertIn('the following arguments are required', mitm_process_stdout)
        self.assertIn('--target_mac', mitm_process_stdout)
        self.assertIn('--target_new_ip', mitm_process_stdout)

    def test02_start_without_target_new_ip(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_dhcp_server.py --target_mac ' +
                            ScriptAppleRogueDhcpTest.Variables.apple_device_mac_address],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: str = mitm_process.stdout.decode('utf-8')
        print(mitm_process_stdout)
        self.assertIn('the following arguments are required', mitm_process_stdout)
        self.assertIn('--target_new_ip', mitm_process_stdout)

    def test03_start_without_target_mac(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_dhcp_server.py --target_new_ip ' +
                            ScriptAppleRogueDhcpTest.Variables.apple_device_new_ipv4_address],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: str = mitm_process.stdout.decode('utf-8')
        print(mitm_process_stdout)
        self.assertIn('the following arguments are required', mitm_process_stdout)
        self.assertIn('--target_mac', mitm_process_stdout)

    def test04_main_bad_interface(self):
        mitm_process = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_dhcp_server.py --interface ' +
                            ScriptAppleRogueDhcpTest.Variables.bad_network_interface + ' --target_mac ' +
                            ScriptAppleRogueDhcpTest.Variables.apple_device_mac_address + ' --target_new_ip ' +
                            ScriptAppleRogueDhcpTest.Variables.apple_device_new_ipv4_address],
                           stdout=PIPE, stderr=STDOUT, shell=True)
        mitm_process_stdout: str = mitm_process.stdout.decode('utf-8')
        print(mitm_process_stdout)
        self.assertIn(ScriptAppleRogueDhcpTest.Variables.bad_network_interface, mitm_process_stdout)

    def test05_main(self):
        self.check_apple_device_connected()
        run(['python3 ' + self.root_path + '/Scripts/Others/network_conflict_creator.py --interface ' +
             ScriptAppleRogueDhcpTest.Variables.test_network_interface + ' --target_mac ' +
             ScriptAppleRogueDhcpTest.Variables.apple_device_mac_address + ' --target_ip ' +
             ScriptAppleRogueDhcpTest.Variables.apple_device_ipv4_address + ' --quiet'], shell=True)
        run(['python3 ' + self.root_path + '/Scripts/Apple/apple_dhcp_server.py --interface ' +
             ScriptAppleRogueDhcpTest.Variables.test_network_interface + ' --target_mac ' +
             ScriptAppleRogueDhcpTest.Variables.apple_device_mac_address + ' --target_new_ip ' +
             ScriptAppleRogueDhcpTest.Variables.apple_device_new_ipv4_address + ' --quiet'], shell=True)
        sleep(5)
        response: int = system("ping -c 1 " + ScriptAppleRogueDhcpTest.Variables.apple_device_new_ipv4_address)
        self.assertEqual(response, 0)
        self.check_apple_device_connected()

# endregion
