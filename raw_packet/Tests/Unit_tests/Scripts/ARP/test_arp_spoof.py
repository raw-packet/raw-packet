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
from subprocess import Popen, run, PIPE
from scapy.all import rdpcap, ARP
import unittest

root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
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
    path.append(root_path)
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    network_interface_mac_address: str = base.get_interface_mac_address(network_interface)
    router_ipv4_address: str = '192.168.0.254'
    target_ipv4_address: str = '192.168.0.7'
    target_mac_address: str = 'b8:ae:ed:eb:cc:25'
    bad_network_interface: str = 'wlan0123'
    bad_ipv4_address: str = '192.168.0.1234'
    bad_mac_address: str = '12:34:56:78:90:abc'
    tshark_pcap_filename: str = '/tmp/arp_spoof_test.pcap'
    # endregion

    def test_main_responses(self):
        find_spoof_packet: bool = False
        arp_spoof_command: str = 'python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.network_interface + \
                                 ' -t ' + self.target_ipv4_address
        Popen(arp_spoof_command, shell=True)
        tshark_command: str = 'tshark -i ' + self.network_interface + \
                              ' -f "ether src ' + self.network_interface_mac_address + \
                              ' and ether dst ' + self.target_mac_address + \
                              ' and arp" -B 65535 -w ' + self.tshark_pcap_filename + \
                              ' 1>/dev/null 2>&1'
        Popen(tshark_command, shell=True)
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
                    if arp_packet.hwsrc == self.network_interface_mac_address and \
                            arp_packet.hwdst == self.target_mac_address and \
                            arp_packet.psrc == self.router_ipv4_address and \
                            arp_packet.pdst == self.target_ipv4_address and \
                            arp_packet.op == 2:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test_main_requests(self):
        find_spoof_packet: bool = False
        arp_spoof_command: str = 'python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.network_interface + \
                                 ' -t ' + self.target_ipv4_address + ' -r'
        Popen(arp_spoof_command, shell=True)
        tshark_command: str = 'tshark -i ' + self.network_interface + \
                              ' -f "ether src ' + self.network_interface_mac_address + \
                              ' and ether dst ' + self.target_mac_address + \
                              ' and arp" -B 65535 -w ' + self.tshark_pcap_filename + \
                              ' 1>/dev/null 2>&1'
        Popen(tshark_command, shell=True)
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
                    if arp_packet.hwsrc == self.network_interface_mac_address and \
                            arp_packet.hwdst == '00:00:00:00:00:00' and \
                            arp_packet.psrc == self.router_ipv4_address and \
                            arp_packet.op == 1:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test_main_bad_interface(self):
        arp_spoof = run(['python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.bad_network_interface],
                        shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(self.bad_network_interface, arp_spoof_output)

    def test_main_bad_gateway_ip(self):
        arp_spoof = run(['python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.network_interface +
                         ' -g ' + self.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(self.bad_ipv4_address, arp_spoof_output)

    def test_main_bad_target_ip(self):
        arp_spoof = run(['python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.network_interface +
                         ' -t ' + self.bad_ipv4_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(self.bad_ipv4_address, arp_spoof_output)

    def test_main_bad_target_mac(self):
        arp_spoof = run(['python3 ' + root_path + '/Scripts/ARP/arp_spoof.py -i ' + self.network_interface +
                         ' -t ' + self.target_ipv4_address + ' -m ' + self.bad_mac_address], shell=True, stdout=PIPE)
        arp_spoof_output: bytes = arp_spoof.stdout
        arp_spoof_output: str = arp_spoof_output.decode('utf-8')
        print(arp_spoof_output)
        self.assertIn(self.bad_mac_address, arp_spoof_output)
# endregion
