# region Description
"""
test_apple_arp_dos.py: Unit tests for Raw-packet script: apple_arp_dos.py
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
class ScriptAppleArpDosTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    # endregion

    def kill_test_process(self) -> None:
        while self.base.get_process_pid('/apple_arp_dos.py') != -1:
            kill(self.base.get_process_pid('/apple_arp_dos.py'), SIGTERM)
            sleep(0.1)

    @staticmethod
    def restart_dhcp_server_over_ssh() -> None:
        run(['ssh ' + ScriptAppleArpDosTest.Variables.router_root_username + '@' +
             ScriptAppleArpDosTest.Variables.router_ipv4_address + ' "/etc/init.d/dnsmasq restart"'], shell=True)

    def check_apple_device_connected(self) -> None:
        self.kill_test_process()
        sleep(5)
        response: int = system("ping -c 1 " + ScriptAppleArpDosTest.Variables.apple_device_ipv4_address)
        if response == 0:
            return None
        else:
            self.restart_dhcp_server_over_ssh()
            while response != 0:
                response = system("ping -c 1 " + ScriptAppleArpDosTest.Variables.apple_device_ipv4_address)

    def test01_main_arp_scan(self):
        self.check_apple_device_connected()
        apple_arp_dos = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                               ScriptAppleArpDosTest.Variables.test_network_interface], shell=True, stdout=PIPE)
        find_target: bool = False
        start_time = time()
        for output_line in apple_arp_dos.stdout:
            output_line: str = output_line.decode('utf-8')
            print(output_line[:-1])
            if ScriptAppleArpDosTest.Variables.apple_device_ipv4_address in output_line:
                find_target = True
                break
            if int(time() - start_time) > 10:
                self.kill_test_process()
                break
        self.assertTrue(find_target)

    def test02_main_nmap_scan(self):
        self.check_apple_device_connected()
        apple_arp_dos = Popen(['python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                               ScriptAppleArpDosTest.Variables.test_network_interface + ' -n'], shell=True, stdout=PIPE)
        find_target: bool = False
        start_time = time()
        for output_line in apple_arp_dos.stdout:
            output_line: str = output_line.decode('utf-8')
            print(output_line[:-1])
            if ScriptAppleArpDosTest.Variables.apple_device_ipv4_address in output_line:
                find_target = True
                break
            if int(time() - start_time) > 120:
                self.kill_test_process()
                break
        self.assertTrue(find_target)

    def test03_main_bad_interface(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             ScriptAppleArpDosTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptAppleArpDosTest.Variables.bad_network_interface, apple_arp_dos_output)

    def test04_main_bad_target_ip(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             ScriptAppleArpDosTest.Variables.test_network_interface + ' -t ' + 
                             ScriptAppleArpDosTest.Variables.bad_ipv4_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptAppleArpDosTest.Variables.bad_ipv4_address, apple_arp_dos_output)

    def test05_main_bad_target_mac(self):
        apple_arp_dos = run(['python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             ScriptAppleArpDosTest.Variables.test_network_interface + ' -t ' + 
                             ScriptAppleArpDosTest.Variables.apple_device_ipv4_address + ' -m ' + 
                             ScriptAppleArpDosTest.Variables.bad_mac_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(ScriptAppleArpDosTest.Variables.bad_mac_address, apple_arp_dos_output)

    def test06_main(self):
        self.check_apple_device_connected()
        command: str = 'python3 ' + self.root_path + '/Scripts/Apple/apple_arp_dos.py -i ' + \
                       ScriptAppleArpDosTest.Variables.test_network_interface + ' -t ' + \
                       ScriptAppleArpDosTest.Variables.apple_device_ipv4_address
        Popen(command, shell=True)
        sleep(10)
        response = system("ping -c 1 " + ScriptAppleArpDosTest.Variables.apple_device_ipv4_address)
        self.assertNotEqual(response, 0)
        self.check_apple_device_connected()

# endregion
