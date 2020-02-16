# region Description
"""
test_dhcp_rogue_server.py: Unit tests for Raw-packet script: dhcp_rogue_server.py
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
from subprocess import Popen, run, PIPE, STDOUT
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


# region Main class - ScriptAppleArpDosTest
class ScriptDhcpRogueServerTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    # endregion

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/dhcp_rogue_server.py') != -1:
            kill(self.base.get_process_pid('/dhcp_rogue_server.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def stop_dhcp_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpRogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpRogueServerTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq stop"'], shell=True)

    @staticmethod
    def start_dhcp_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpRogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpRogueServerTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq start"'], shell=True)

    @staticmethod
    def restart_dhcp_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpRogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpRogueServerTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    @staticmethod
    def restart_apple_device_interface_over_ssh(host: Union[None, str] = None) -> None:
        if host is None:
            host = ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address
        run(['ssh ' + ScriptDhcpRogueServerTest.Variables.apple_device_root_username + '@' + host + ' "ifconfig ' +
             ScriptDhcpRogueServerTest.Variables.apple_device_network_interface + ' down && ifconfig ' +
             ScriptDhcpRogueServerTest.Variables.apple_device_network_interface + ' up"'], shell=True)

    @staticmethod
    def get_ipv4_gateway_apple_device_over_ssh(host: Union[None, str] = None) -> str:
        if host is None:
            host = ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address
        target_command = run(['ssh ' + ScriptDhcpRogueServerTest.Variables.apple_device_username + '@' + host +
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

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.stop_dhcp_server_in_router_over_ssh()
            self.start_dhcp_server_in_router_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address)

    def test01_main_target_mac_and_ip(self):
        self.check_apple_device_connected()
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.router_ipv4_address)
        self.stop_dhcp_server_in_router_over_ssh()
        Popen(['python3 ' + self.root_path + '/Scripts/DHCPv4/dhcp_rogue_server.py -i ' +
               ScriptDhcpRogueServerTest.Variables.test_network_interface + ' --target_mac ' +
               ScriptDhcpRogueServerTest.Variables.apple_device_mac_address + ' --target_ip ' +
               ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address], shell=True)
        sleep(1)
        self.restart_apple_device_interface_over_ssh()
        sleep(2)
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.your_ipv4_address)
        self.kill_test_process()
        self.start_dhcp_server_in_router_over_ssh()
        self.restart_apple_device_interface_over_ssh()
        sleep(2)
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.router_ipv4_address)
        self.check_apple_device_connected()

    # Not work
    # def test02_main_target_new_ip(self):
    #     self.check_apple_device_connected()
    #     self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
    #                      ScriptDhcpRogueServerTest.Variables.router_ipv4_address)
    #     self.stop_dhcp_server_in_router_over_ssh()
    #     self.restart_apple_device_interface_over_ssh()
    #     Popen(['python3 ' + self.root_path + '/Scripts/DHCPv4/dhcp_rogue_server.py -i ' +
    #            ScriptDhcpRogueServerTest.Variables.test_network_interface + ' --target_mac ' +
    #            ScriptDhcpRogueServerTest.Variables.apple_device_mac_address + ' --target_ip ' +
    #            ScriptDhcpRogueServerTest.Variables.apple_device_new_ipv4_address], shell=True)
    #     sleep(5)
    #     router_address: str = self.get_ipv4_gateway_apple_device_over_ssh(
    #         ScriptDhcpRogueServerTest.Variables.apple_device_new_ipv4_address)
    #     self.assertEqual(router_address, ScriptDhcpRogueServerTest.Variables.your_ipv4_address)
    #     self.kill_test_process()
    #     self.restart_apple_device_interface_over_ssh(ScriptDhcpRogueServerTest.Variables.apple_device_new_ipv4_address)
    #     self.check_apple_device_connected()

    def test03_main_apple(self):
        self.check_apple_device_connected()
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.router_ipv4_address)
        Popen(['python3 ' + self.root_path + '/Scripts/DHCPv4/dhcp_rogue_server.py -i ' +
               ScriptDhcpRogueServerTest.Variables.test_network_interface + ' --target_mac ' +
               ScriptDhcpRogueServerTest.Variables.apple_device_mac_address + ' --target_ip ' +
               ScriptDhcpRogueServerTest.Variables.apple_device_ipv4_address + ' --apple'], shell=True)
        sleep(1)
        self.restart_apple_device_interface_over_ssh()
        sleep(3)
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.your_ipv4_address)
        self.kill_test_process()
        self.restart_dhcp_server_in_router_over_ssh()
        self.restart_apple_device_interface_over_ssh()
        sleep(3)
        self.assertEqual(self.get_ipv4_gateway_apple_device_over_ssh(),
                         ScriptDhcpRogueServerTest.Variables.router_ipv4_address)
        self.check_apple_device_connected()

# endregion
