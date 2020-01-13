# region Description
"""
test_arp_spoof.py: Unit tests for Raw-packet script: arp_spoof.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath, isfile
from os import remove, kill
from signal import SIGTERM
from time import sleep
from subprocess import run, PIPE, Popen
from scapy.all import rdpcap, ARP
from typing import IO
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
class ScriptArpSpoofTest(unittest.TestCase):

    # region Properties
    root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    path.append(root_path)
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()
    tshark_pcap_filename: str = '/tmp/arp_spoof_test.pcap'
    # endregion

    def test01_main_responses(self):
        find_spoof_packet: bool = False
        arp_spoof_command: str = 'python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' + \
                                 ScriptArpSpoofTest.Variables.test_network_interface + ' -t ' + \
                                 ScriptArpSpoofTest.Variables.apple_device_ipv4_address
        run(arp_spoof_command, shell=True)
        tshark_command: str = 'tshark -i ' + ScriptArpSpoofTest.Variables.test_network_interface + \
                              ' -f "ether src ' + ScriptArpSpoofTest.Variables.your_mac_address + \
                              ' and ether dst ' + ScriptArpSpoofTest.Variables.apple_device_mac_address + \
                              ' and arp" -B 65535 -w ' + self.tshark_pcap_filename + \
                              ' 1>/dev/null 2>&1'
        run(tshark_command, shell=True)
        sleep(5)
        while self.base.get_process_pid('/arp_spoof.py') != -1:
            kill(self.base.get_process_pid('/arp_spoof.py'), SIGTERM)
            sleep(0.5)
        while self.base.get_process_pid('tshark') != -1:
            kill(self.base.get_process_pid('tshark'), SIGTERM)
            sleep(0.5)
        try:
            packets = rdpcap(self.tshark_pcap_filename)
            for packet in packets:
                if packet.haslayer(ARP):
                    arp_packet = packet[ARP]
                    print('ARP opcode: ' + str(arp_packet.op))
                    print('ARP sender MAC: ' + arp_packet.hwsrc)
                    print('ARP target MAC: ' + arp_packet.hwdst)
                    print('ARP sender IP: ' + arp_packet.psrc)
                    print('ARP target IP: ' + arp_packet.pdst)
                    if arp_packet.hwsrc == ScriptArpSpoofTest.Variables.your_mac_address and \
                            arp_packet.hwdst == ScriptArpSpoofTest.Variables.apple_device_mac_address and \
                            arp_packet.psrc == ScriptArpSpoofTest.Variables.router_ipv4_address and \
                            arp_packet.pdst == ScriptArpSpoofTest.Variables.apple_device_ipv4_address and \
                            arp_packet.op == 2:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test02_main_requests(self):
        find_spoof_packet: bool = False
        arp_spoof_command: str = 'python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' + \
                                 ScriptArpSpoofTest.Variables.test_network_interface + ' -t ' + \
                                 ScriptArpSpoofTest.Variables.apple_device_ipv4_address + ' -r'
        run(arp_spoof_command, shell=True)
        tshark_command: str = 'tshark -i ' + ScriptArpSpoofTest.Variables.test_network_interface + \
                              ' -f "ether src ' + ScriptArpSpoofTest.Variables.your_mac_address + \
                              ' and ether dst ' + ScriptArpSpoofTest.Variables.apple_device_mac_address + \
                              ' and arp" -B 65535 -w ' + self.tshark_pcap_filename + \
                              ' 1>/dev/null 2>&1'
        run(tshark_command, shell=True)
        sleep(5)
        while self.base.get_process_pid('/arp_spoof.py') != -1:
            kill(self.base.get_process_pid('/arp_spoof.py'), SIGTERM)
            sleep(0.5)
        while self.base.get_process_pid('tshark') != -1:
            kill(self.base.get_process_pid('tshark'), SIGTERM)
            sleep(0.5)
        try:
            packets = rdpcap(self.tshark_pcap_filename)
            for packet in packets:
                if packet.haslayer(ARP):
                    arp_packet = packet[ARP]
                    print('ARP opcode: ' + str(arp_packet.op))
                    print('ARP sender MAC: ' + arp_packet.hwsrc)
                    print('ARP target MAC: ' + arp_packet.hwdst)
                    print('ARP sender IP: ' + arp_packet.psrc)
                    print('ARP target IP: ' + arp_packet.pdst)
                    if arp_packet.hwsrc == ScriptArpSpoofTest.Variables.your_mac_address and \
                            arp_packet.hwdst == '00:00:00:00:00:00' and \
                            arp_packet.psrc == ScriptArpSpoofTest.Variables.router_ipv4_address and \
                            arp_packet.op == 1:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test03_main_bad_interface(self):
        arp_spoof = Popen(['python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' +
                           ScriptArpSpoofTest.Variables.bad_network_interface], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(ScriptArpSpoofTest.Variables.bad_network_interface, arp_spoof_output)

    def test04_main_bad_gateway_ip(self):
        arp_spoof = Popen(['python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' +
                           ScriptArpSpoofTest.Variables.test_network_interface + ' -g ' +
                           ScriptArpSpoofTest.Variables.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(ScriptArpSpoofTest.Variables.bad_ipv4_address, arp_spoof_output)

    def test05_main_bad_target_ip(self):
        arp_spoof = Popen(['python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' +
                           ScriptArpSpoofTest.Variables.test_network_interface + ' -t ' +
                           ScriptArpSpoofTest.Variables.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(ScriptArpSpoofTest.Variables.bad_ipv4_address, arp_spoof_output)

    def test06_main_bad_target_mac(self):
        arp_spoof = Popen(['python3 ' + self.root_path + '/Scripts/ARP/arp_spoof.py -i ' +
                           ScriptArpSpoofTest.Variables.test_network_interface + ' -t ' +
                           ScriptArpSpoofTest.Variables.apple_device_ipv4_address + ' -m ' +
                           ScriptArpSpoofTest.Variables.bad_mac_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(ScriptArpSpoofTest.Variables.bad_mac_address, arp_spoof_output)

# endregion
