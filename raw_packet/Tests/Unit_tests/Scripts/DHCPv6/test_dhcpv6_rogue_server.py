# region Description
"""
test_dhcpv6_rogue_server.py: Unit tests for Raw-packet script: dhcpv6_rogue_server.py
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
from typing import Union, List
from re import sub
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
class ScriptDhcpv6RogueServerTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    # endregion

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/dhcpv6_rogue_server.py') != -1:
            kill(self.base.get_process_pid('/dhcpv6_rogue_server.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def stop_dhcpv6_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpv6RogueServerTest.Variables.router_ipv4_address +
             ' "sed \'/option \(ra\|dhcpv6\|ra_management\) .*/d\' /etc/config/dhcp > /tmp/dhcp;'
             ' cp /tmp/dhcp /etc/config/dhcp; /etc/init.d/dnsmasq restart; /etc/init.d/network restart"'], shell=True)

    @staticmethod
    def start_dhcpv6_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpv6RogueServerTest.Variables.router_ipv4_address +
             ' "awk \'1;/config dhcp .lan./{ print \\"\\toption ra \\x27server\\x27\\"; '
             'print \\"\\toption dhcpv6 \\x27server\\x27\\"; '
             'print \\"\\toption ra_management \\x271\\x27\\"}\' /etc/config/dhcp > /tmp/dhcp; '
             'cp /tmp/dhcp /etc/config/dhcp; /etc/init.d/dnsmasq restart; /etc/init.d/network restart"'], shell=True)

    @staticmethod
    def restart_dhcp_server_in_router_over_ssh() -> None:
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.router_root_username + '@' +
             ScriptDhcpv6RogueServerTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    @staticmethod
    def restart_apple_device_interface_over_ssh(host: Union[None, str] = None) -> None:
        if host is None:
            host = ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.apple_device_root_username + '@' + host + ' "ifconfig ' +
             ScriptDhcpv6RogueServerTest.Variables.apple_device_network_interface + ' down && ifconfig ' +
             ScriptDhcpv6RogueServerTest.Variables.apple_device_network_interface + ' up"'], shell=True)

    @staticmethod
    def disable_ipv6_in_apple_device_over_ssh(host: Union[None, str] = None) -> None:
        if host is None:
            host = ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.apple_device_root_username + '@' + host +
             ' "networksetup -setv6off Ethernet; networksetup -setv6off Wi-Fi"'], shell=True)

    @staticmethod
    def enable_ipv6_in_apple_device_over_ssh(host: Union[None, str] = None) -> None:
        if host is None:
            host = ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address
        run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.apple_device_root_username + '@' + host +
             ' "networksetup -setv6automatic Ethernet; networksetup -setv6automatic Wi-Fi"'], shell=True)

    @staticmethod
    def get_ipv6_gateway_apple_device_over_ssh(host: Union[None, str] = None) -> str:
        if host is None:
            host = ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address
        target_command = run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.apple_device_username + '@' + host +
                              ' "netstat -nr -f inet6 | grep UHLW"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_gateway: str = target_command.stdout.decode('utf-8')
        target_gateway: str = sub(r' +', ' ', target_gateway)
        target_gateway: List[str] = target_gateway.split(' ')
        target_gateway: str = target_gateway[0]
        if target_gateway.endswith('%en0'):
            target_gateway: str = target_gateway[:-4]
        return target_gateway

    def get_ipv6_nameservers_apple_device_over_ssh(self, host: Union[None, str] = None) -> List[str]:
        nameservers: List[str] = list()
        if host is None:
            host = ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address
        target_command = run(['ssh ' + ScriptDhcpv6RogueServerTest.Variables.apple_device_username + '@' + host +
                              ' "cat /etc/resolv.conf | grep nameserver"'],
                             shell=True, stdout=PIPE, stderr=STDOUT)
        target_nameservers: str = target_command.stdout.decode('utf-8')
        target_nameservers: str = sub(r' +', ' ', target_nameservers)
        target_nameservers: List[str] = target_nameservers.splitlines()
        for target_nameserver in target_nameservers:
            nameserver_address: str = target_nameserver.split(' ')[1]
            if self.base.ip_address_validation(nameserver_address):
                nameservers.append(nameserver_address)
            if self.base.ipv6_address_validation(nameserver_address):
                nameservers.append(nameserver_address)
        return nameservers

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.restart_dhcp_server_in_router_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv4_address)

    def test01_main_target_mac_and_ip(self):
        self.check_apple_device_connected()
        self.assertEqual(self.get_ipv6_gateway_apple_device_over_ssh(),
                         ScriptDhcpv6RogueServerTest.Variables.router_ipv6_link_address)
        self.assertIn(ScriptDhcpv6RogueServerTest.Variables.router_ipv6_glob_address,
                      self.get_ipv6_nameservers_apple_device_over_ssh())
        self.stop_dhcpv6_server_in_router_over_ssh()
        Popen(['python3 ' + self.root_path + '/Scripts/DHCPv6/dhcpv6_rogue_server.py -i ' +
               ScriptDhcpv6RogueServerTest.Variables.test_network_interface + ' --target_mac ' +
               ScriptDhcpv6RogueServerTest.Variables.apple_device_mac_address + ' --target_ip ' +
               ScriptDhcpv6RogueServerTest.Variables.apple_device_ipv6_glob_address], shell=True)
        self.disable_ipv6_in_apple_device_over_ssh()
        self.restart_apple_device_interface_over_ssh()
        self.enable_ipv6_in_apple_device_over_ssh()
        self.restart_apple_device_interface_over_ssh()
        sleep(5)
        self.assertEqual(self.get_ipv6_gateway_apple_device_over_ssh(),
                         ScriptDhcpv6RogueServerTest.Variables.your_ipv6_link_address)
        self.assertIn(ScriptDhcpv6RogueServerTest.Variables.your_ipv6_link_address,
                      self.get_ipv6_nameservers_apple_device_over_ssh())
        self.kill_test_process()
        self.start_dhcpv6_server_in_router_over_ssh()
        # self.disable_ipv6_in_apple_device_over_ssh()
        # self.restart_apple_device_interface_over_ssh()
        # self.enable_ipv6_in_apple_device_over_ssh()
        self.restart_apple_device_interface_over_ssh()
        sleep(2)
        self.assertEqual(self.get_ipv6_gateway_apple_device_over_ssh(),
                         ScriptDhcpv6RogueServerTest.Variables.router_ipv6_link_address)
        self.check_apple_device_connected()

# endregion
