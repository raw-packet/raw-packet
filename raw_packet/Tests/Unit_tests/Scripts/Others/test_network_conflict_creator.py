# region Description
"""
test_network_conflict_creator.py: Unit tests for Raw-packet script: network_conflict_creator.py
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
from subprocess import Popen, run, PIPE
from unittest import TestCase
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


# region Main class - ScriptNetworkConflictCreatorTest
class ScriptNetworkConflictCreatorTest(TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    # endregion

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/network_conflict_creator.py') != -1:
            kill(self.base.get_process_pid('/network_conflict_creator.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def restart_dhcp_server_over_ssh() -> None:
        run(['ssh ' + ScriptNetworkConflictCreatorTest.Variables.router_root_username + '@' +
             ScriptNetworkConflictCreatorTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'],
            shell=True)

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptNetworkConflictCreatorTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.restart_dhcp_server_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptNetworkConflictCreatorTest.Variables.apple_device_ipv4_address)

    def test01_main_bad_interface(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Others/network_conflict_creator.py -i ' +
                             ScriptNetworkConflictCreatorTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        apple_arp_dos_output: str = apple_arp_dos.stdout.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptNetworkConflictCreatorTest.Variables.bad_network_interface, apple_arp_dos_output)

    def test02_main_bad_target_ip(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Others/network_conflict_creator.py -i ' +
                             ScriptNetworkConflictCreatorTest.Variables.test_network_interface + ' -t ' +
                             ScriptNetworkConflictCreatorTest.Variables.bad_ipv4_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: str = apple_arp_dos.stdout.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptNetworkConflictCreatorTest.Variables.bad_ipv4_address, apple_arp_dos_output)

    def test03_main_bad_target_mac(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Others/network_conflict_creator.py -i ' +
                             ScriptNetworkConflictCreatorTest.Variables.test_network_interface + ' -t ' +
                             ScriptNetworkConflictCreatorTest.Variables.apple_device_ipv4_address + ' -m ' +
                             ScriptNetworkConflictCreatorTest.Variables.bad_mac_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: str = apple_arp_dos.stdout.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptNetworkConflictCreatorTest.Variables.bad_mac_address, apple_arp_dos_output)

    def test04_main(self):
        self.check_apple_device_connected()
        run(['python3 ' + self.root_path + '/Scripts/Others/network_conflict_creator.py -i ' +
             ScriptNetworkConflictCreatorTest.Variables.test_network_interface + ' -t ' +
             ScriptNetworkConflictCreatorTest.Variables.apple_device_ipv4_address + ' -m ' +
             ScriptNetworkConflictCreatorTest.Variables.apple_device_mac_address], shell=True)
        sleep(1)
        response = system("ping -c 1 " + ScriptNetworkConflictCreatorTest.Variables.apple_device_ipv4_address)
        self.assertNotEqual(response, 0)
        self.check_apple_device_connected()


# endregion
