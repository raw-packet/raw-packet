# region Description
"""
test_apple_arp_dos.py: Unit tests for Raw-packet script: apple_arp_dos.py
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
from subprocess import Popen, run, PIPE
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


# region Main class - ScriptAppleArpDosTest
class ScriptAppleArpDosTest(unittest.TestCase):

    # region Properties
    path.append(root_path)
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    target_ipv4_address: str = '192.168.0.53'
    bad_network_interface: str = 'wlan0123'
    bad_ipv4_address: str = '192.168.0.1234'
    bad_mac_address: str = '12:34:56:78:90:abc'
    # endregion

    def test01_main_arp_scan(self):
        apple_arp_dos = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                               self.network_interface], shell=True, stdout=PIPE)
        find_target: bool = False
        start_time = time()
        for output_line in apple_arp_dos.stdout:
            output_line: str = output_line.decode('utf-8')
            print(output_line[:-1])
            if self.target_ipv4_address in output_line:
                find_target = True
                break
            else:
                if int(time() - start_time) > 10:
                    kill(apple_arp_dos.pid, SIGTERM)
                    while self.base.get_process_pid('/apple_arp_dos.py') != -1:
                        kill(self.base.get_process_pid('/apple_arp_dos.py'), SIGTERM)
                        sleep(0.5)
                    break
        self.assertTrue(find_target)

    def test02_main_nmap_scan(self):
        apple_arp_dos = Popen(['python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                               self.network_interface + ' -n'], shell=True, stdout=PIPE)
        find_target: bool = False
        start_time = time()
        for output_line in apple_arp_dos.stdout:
            output_line: str = output_line.decode('utf-8')
            print(output_line[:-1])
            if self.target_ipv4_address in output_line:
                find_target = True
                break
            else:
                if int(time() - start_time) > 120:
                    kill(apple_arp_dos.pid, SIGTERM)
                    while self.base.get_process_pid('/apple_arp_dos.py') != -1:
                        kill(self.base.get_process_pid('/apple_arp_dos.py'), SIGTERM)
                        sleep(0.5)
                    break
        self.assertTrue(find_target)

    def test03_main_bad_interface(self):
        apple_arp_dos = run(['python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             self.bad_network_interface], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(self.bad_network_interface, apple_arp_dos_output)

    def test04_main_bad_target_ip(self):
        apple_arp_dos = run(['python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             self.network_interface + ' -t ' + self.bad_ipv4_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(self.bad_ipv4_address, apple_arp_dos_output)

    def test05_main_bad_target_mac(self):
        apple_arp_dos = run(['python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' +
                             self.network_interface + ' -t ' + self.target_ipv4_address +
                             ' -m ' + self.bad_mac_address], shell=True, stdout=PIPE)
        apple_arp_dos_output: bytes = apple_arp_dos.stdout
        apple_arp_dos_output: str = apple_arp_dos_output.decode('utf-8')
        print(apple_arp_dos_output)
        self.assertIn(self.bad_mac_address, apple_arp_dos_output)

    def test06_main(self):
        command: str = 'python3 ' + root_path + '/Scripts/Apple/apple_arp_dos.py -i ' + self.network_interface + \
                       ' -t ' + self.target_ipv4_address
        process = Popen(command, shell=True)
        sleep(10)
        response = system("ping -c 1 " + self.target_ipv4_address)
        kill(process.pid, SIGTERM)
        while self.base.get_process_pid('/apple_arp_dos.py') != -1:
            kill(self.base.get_process_pid('/apple_arp_dos.py'), SIGTERM)
            sleep(0.5)
        self.assertNotEqual(response, 0)

# endregion
