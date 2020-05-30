# region Description
"""
test_arp_spoof.py: Unit tests for Raw-packet script: arp_spoof.py
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Tests.Unit_tests.variables import Variables
from raw_packet.Tests.Unit_tests.context_manager import ContextManager
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Scripts.ARP.arp_spoof import ArpSpoof
from sys import path
from os.path import dirname, abspath, isfile, join
from os import remove, kill
from signal import SIGTERM
from time import sleep
from subprocess import run, PIPE, Popen, STDOUT
from scapy.all import rdpcap, ARP
from typing import IO
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


# region Main class - ScriptArpScanTest
class ScriptArpSpoofTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    context_manager: ContextManager = ContextManager()
    thread_manager: ThreadManager = ThreadManager(10)
    tshark_pcap_filename: str = join(variables.temp_directory, 'arp_spoof_test.pcap')
    # endregion

    def test01_main_responses(self):
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        find_spoof_packet: bool = False
        arp_spoof: ArpSpoof = ArpSpoof(network_interface=self.variables.your.network_interface)
        self.thread_manager.add_task(arp_spoof.start, self.variables.router.ipv4_address,
                                     self.variables.target.ipv4_address, self.variables.target.mac_address,
                                     False, False, False, False, False)
        command = self.variables.tshark_executable + \
                  ' -i "' + self.variables.your.network_interface + \
                  '" -f "ether src ' + self.variables.your.mac_address + \
                  ' and ether dst ' + self.variables.target.mac_address + \
                  ' and arp" -B 65535 -w "' + self.tshark_pcap_filename + '"'
        if self.base.get_platform().startswith('Darwin'):
            Popen([command], shell=True, stdout=PIPE, stderr=STDOUT)
        else:
            Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
        sleep(5)
        self.thread_manager.close()
        if self.base.get_platform().startswith('Windows'):
            self.base.kill_process_by_name(process_name='tshark.exe')
        else:
            self.base.kill_process_by_name(process_name='tshark')
        self.assertTrue(isfile(self.tshark_pcap_filename))
        try:
            packets = rdpcap(self.tshark_pcap_filename)
            for packet in packets:
                if packet.haslayer(ARP):
                    arp_packet = packet[ARP]
                    self.base.print_info('ARP opcode: ', str(arp_packet.op))
                    self.base.print_info('ARP sender MAC: ', arp_packet.hwsrc)
                    self.base.print_info('ARP target MAC: ', arp_packet.hwdst)
                    self.base.print_info('ARP sender IP: ', arp_packet.psrc)
                    self.base.print_info('ARP target IP: ', arp_packet.pdst)
                    if arp_packet.hwsrc == self.variables.your.mac_address and \
                            arp_packet.hwdst == self.variables.target.mac_address and \
                            arp_packet.psrc == self.variables.router.ipv4_address and \
                            arp_packet.pdst == self.variables.target.ipv4_address and \
                            arp_packet.op == 2:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        except FileNotFoundError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test02_main_requests(self):
        find_spoof_packet: bool = False
        arp_spoof: ArpSpoof = ArpSpoof(network_interface=self.variables.your.network_interface)
        self.thread_manager.add_task(arp_spoof.start, self.variables.router.ipv4_address,
                                     self.variables.target.ipv4_address, self.variables.target.mac_address,
                                     False, False, False, True, False)
        command = self.variables.tshark_executable + \
                  ' -i "' + self.variables.your.network_interface + \
                  '" -f "ether src ' + self.variables.your.mac_address + \
                  ' and ether dst ' + self.variables.target.mac_address + \
                  ' and arp" -B 65535 -w "' + self.tshark_pcap_filename + '"'
        if self.base.get_platform().startswith('Darwin'):
            Popen([command], shell=True, stdout=PIPE, stderr=STDOUT)
        else:
            Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
        sleep(5)
        self.thread_manager.close()
        if self.base.get_platform().startswith('Windows'):
            self.base.kill_process_by_name(process_name='tshark.exe')
        else:
            self.base.kill_process_by_name(process_name='tshark')
        self.assertTrue(isfile(self.tshark_pcap_filename))
        try:
            packets = rdpcap(self.tshark_pcap_filename)
            for packet in packets:
                if packet.haslayer(ARP):
                    arp_packet = packet[ARP]
                    self.base.print_info('ARP opcode: ', str(arp_packet.op))
                    self.base.print_info('ARP sender MAC: ', arp_packet.hwsrc)
                    self.base.print_info('ARP target MAC: ', arp_packet.hwdst)
                    self.base.print_info('ARP sender IP: ', arp_packet.psrc)
                    self.base.print_info('ARP target IP: ', arp_packet.pdst)
                    if arp_packet.hwsrc == self.variables.your.mac_address and \
                            arp_packet.hwdst == '00:00:00:00:00:00' and \
                            arp_packet.psrc == self.variables.router.ipv4_address and \
                            arp_packet.op == 1:
                        find_spoof_packet = True
                        break
        except ValueError:
            pass
        except FileNotFoundError:
            pass
        if isfile(self.tshark_pcap_filename):
            remove(self.tshark_pcap_filename)
        self.assertTrue(find_spoof_packet)

    def test03_main_bad_interface(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                ArpSpoof(network_interface=self.variables.bad.network_interface)
        arp_spoof_output: str = out.getvalue()
        print(arp_spoof_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.network_interface, arp_spoof_output)

    def test04_main_bad_gateway_ip(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                arp_spoof: ArpSpoof = ArpSpoof(network_interface=self.variables.your.network_interface)
                arp_spoof.start(gateway_ipv4_address=self.variables.bad.ipv4_address)
        arp_spoof_output: str = out.getvalue()
        print(arp_spoof_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.ipv4_address, arp_spoof_output)

    def test05_main_bad_target_ip(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                arp_spoof: ArpSpoof = ArpSpoof(network_interface=self.variables.your.network_interface)
                arp_spoof.start(gateway_ipv4_address=self.variables.router.ipv4_address,
                                target_ipv4_address=self.variables.bad.ipv4_address)
        arp_spoof_output: str = out.getvalue()
        print(arp_spoof_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.ipv4_address, arp_spoof_output)

    def test06_main_bad_target_mac(self):
        with self.assertRaises(SystemExit) as result:
            with self.context_manager.captured_output() as (out, err):
                arp_spoof: ArpSpoof = ArpSpoof(network_interface=self.variables.your.network_interface)
                arp_spoof.start(gateway_ipv4_address=self.variables.router.ipv4_address,
                                target_ipv4_address=self.variables.target.ipv4_address,
                                target_mac_address=self.variables.bad.mac_address)
        arp_spoof_output: str = out.getvalue()
        print(arp_spoof_output)
        self.assertEqual(result.exception.code, 1)
        self.assertIn(self.variables.bad.mac_address, arp_spoof_output)

# endregion
