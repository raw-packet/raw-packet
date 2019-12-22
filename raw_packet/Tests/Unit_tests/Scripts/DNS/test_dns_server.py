# region Description
"""
test_dns_server.py: Unit tests for Raw-packet script: dns_server.py
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from os.path import dirname, abspath, isfile
from os import remove
from subprocess import run, PIPE, STDOUT, Popen
from sys import path
from time import sleep
from typing import List, Dict
from xmltodict import parse
from json import loads
from warnings import simplefilter
import unittest

root_path = dirname(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
simplefilter("ignore", ResourceWarning)
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


# region Main class - ScriptArpScanTest
class ScriptDnsServerTest(unittest.TestCase):

    # region Properties - must change for your tests
    path.append(root_path)
    from raw_packet.Utils.base import Base
    base: Base = Base()
    network_interface: str = 'wlan0'
    your_mac_address: str = base.get_interface_mac_address(network_interface)
    your_ipv4_address: str = base.get_interface_ip_address(network_interface)
    your_ipv6_address: str = base.get_interface_ipv6_link_address(network_interface)
    target_ipv4_address: str = '192.168.0.4'
    target_mac_address: str = 'd8:96:95:f3:b4:67'
    target_username: str = 'vladimir'
    domain1: str = 'apple.com'
    domain2: str = 'google.com'
    domain3: str = 'evil.com'
    domain_regex1: str = '.*\.apple\.com'
    domain_regex2: str = '.*\.google\.com'
    fake_ipv4_address1: str = '192.168.0.1'
    fake_ipv4_address2: str = '192.168.0.2'
    fake_ipv6_address1: str = 'fd00::1'
    fake_ipv6_address2: str = 'fd00::2'
    config_file: str = 'dns_server_config.json'
    log_file_name: str = '/tmp/dns_server_log'
    bad_interface: str = 'wlan0123'
    bad_target_mac: str = '12:34:56:67:89:0ab'
    bad_target_ipv4: str = '192.168.0.1234'
    bad_target_ipv6: str = 'fd00:::1'
    bad_fake_ipv4: str = '192.168.0.1,192.168.0.1234'
    bad_fake_ipv6: str = 'fd00::1,fd00:::2'
    bad_port: str = '123456'
    # endregion

    def get_domain_address_over_ssh(self, type: str, domain: str) -> str:
        dig_command = run(['ssh ' + self.target_username + '@' + self.target_ipv4_address +
                           ' "dig +short -t ' + type + ' ' + domain + ' @' + self.your_ipv4_address + '"'],
                          shell=True, stdout=PIPE, stderr=STDOUT)
        dig_result: bytes = dig_command.stdout
        dig_result: str = dig_result.decode('utf-8')
        if dig_result.endswith('\n'):
            dig_result: str = dig_result[:-1]
        return dig_result

    def test01_bad_interface(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.bad_interface],
                         stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn(self.bad_interface, dns_server_stdout.decode())

    def test02_bad_target_mac_address(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --target_mac ' + self.bad_target_mac], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn(self.bad_target_mac, dns_server_stdout.decode())

    def test03_bad_target_ipv4_address(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --T4 ' + self.bad_target_ipv4], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn(self.bad_target_ipv4, dns_server_stdout.decode())

    def test04_bad_target_ipv6_address(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --T6 ' + self.bad_target_ipv6], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn(self.bad_target_ipv6, dns_server_stdout.decode())

    def test05_bad_fake_ipv4_address(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --fake_ipv4 ' + self.bad_fake_ipv4], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn('192.168.0.1234', dns_server_stdout.decode())

    def test06_bad_fake_ipv6_address(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --fake_ipv6 ' + self.bad_fake_ipv6], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn('fd00:::2', dns_server_stdout.decode())

    def test07_bad_port(self):
        dns_server = run(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
                          ' --port ' + self.bad_port], stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        dns_server_stdout: bytes = dns_server.stdout
        print(dns_server_stdout.decode())
        self.assertIn(self.bad_port, dns_server_stdout.decode())

    def test08_fake_answer(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface + ' --fake_answer'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', self.domain2)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, ipv4_address_domain2)
        self.assertEqual(ipv6_address_domain1, ipv6_address_domain2)
        self.assertEqual(ipv4_address_domain1, self.your_ipv4_address)
        self.assertEqual(ipv6_address_domain1, self.your_ipv6_address)
        print('A ' + self.domain1 + ' ' + ipv4_address_domain1)
        print('AAAA ' + self.domain1 + ' ' + ipv6_address_domain1)
        print('A ' + self.domain2 + ' ' + ipv4_address_domain2)
        print('AAAA ' + self.domain2 + ' ' + ipv6_address_domain2)

    def test09_fake_answer_target_mac(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --fake_answer --target_mac ' + self.target_mac_address], shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', self.domain2)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, ipv4_address_domain2)
        self.assertEqual(ipv6_address_domain1, ipv6_address_domain2)
        self.assertEqual(ipv4_address_domain1, self.your_ipv4_address)
        self.assertEqual(ipv6_address_domain1, self.your_ipv6_address)
        print('A ' + self.domain1 + ' ' + ipv4_address_domain1)
        print('AAAA ' + self.domain1 + ' ' + ipv6_address_domain1)
        print('A ' + self.domain2 + ' ' + ipv4_address_domain2)
        print('AAAA ' + self.domain2 + ' ' + ipv6_address_domain2)

    def test10_fake_answer_target_ipv4(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --fake_answer --T4 ' + self.target_ipv4_address], shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', self.domain2)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, ipv4_address_domain2)
        self.assertEqual(ipv6_address_domain1, ipv6_address_domain2)
        self.assertEqual(ipv4_address_domain1, self.your_ipv4_address)
        self.assertEqual(ipv6_address_domain1, self.your_ipv6_address)
        print('A ' + self.domain1 + ' ' + ipv4_address_domain1)
        print('AAAA ' + self.domain1 + ' ' + ipv6_address_domain1)
        print('A ' + self.domain2 + ' ' + ipv4_address_domain2)
        print('AAAA ' + self.domain2 + ' ' + ipv6_address_domain2)

    def test11_fake_domains(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --fake_domains "' + self.domain_regex1 + ',' + self.domain_regex2 + '"'], shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'www.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'home.' + self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'mail.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'market.' + self.domain2)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, ipv4_address_domain2)
        self.assertEqual(ipv6_address_domain1, ipv6_address_domain2)
        self.assertEqual(ipv4_address_domain1, self.your_ipv4_address)
        self.assertEqual(ipv6_address_domain1, self.your_ipv6_address)
        print('A ' + 'www.' + self.domain1 + ' ' + ipv4_address_domain1)
        print('AAAA ' + 'home.' + self.domain1 + ' ' + ipv6_address_domain1)
        print('A ' + 'mail.' + self.domain2 + ' ' + ipv4_address_domain2)
        print('AAAA ' + 'market.' + self.domain2 + ' ' + ipv6_address_domain2)

    def test12_fake_addresses(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --fake_domains "' + self.domain_regex1 + ',' + self.domain_regex2 +
               '" --fake_ipv4 "' + self.fake_ipv4_address1 + ',' + self.fake_ipv4_address2 +
               '" --fake_ipv6 "' + self.fake_ipv6_address1 + ',' + self.fake_ipv6_address2 + '"'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'photo.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'maps.' + self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'contact.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'note.' + self.domain2)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, ipv4_address_domain2)
        self.assertEqual(ipv6_address_domain1, ipv6_address_domain2)
        self.assertEqual(ipv4_address_domain1, self.fake_ipv4_address1 + '\n' + self.fake_ipv4_address2)
        self.assertEqual(ipv6_address_domain1, self.fake_ipv6_address1 + '\n' + self.fake_ipv6_address2)
        print('A ' + 'photo.' + self.domain1 + ' ' + ipv4_address_domain1.replace('\n', ', '))
        print('AAAA ' + 'maps.' + self.domain1 + ' ' + ipv6_address_domain1.replace('\n', ', '))
        print('A ' + 'contact.' + self.domain2 + ' ' + ipv4_address_domain2.replace('\n', ', '))
        print('AAAA ' + 'note.' + self.domain2 + ' ' + ipv6_address_domain2.replace('\n', ', '))

    def test13_config_file(self):
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --config_file "' + root_path + '/Scripts/DNS/' + self.config_file + '"'],
              shell=True, stdout=PIPE)
        sleep(5)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'text.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'remote.' + self.domain1)
        ns_address_domain1: str = self.get_domain_address_over_ssh('NS', self.domain1)
        mx_address_domain1: str = self.get_domain_address_over_ssh('MX', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'wire.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'book.' + self.domain2)
        ns_address_domain2: str = self.get_domain_address_over_ssh('NS', self.domain2)
        mx_address_domain2: str = self.get_domain_address_over_ssh('MX', self.domain2)
        ipv4_address_domain3: str = self.get_domain_address_over_ssh('A', self.domain3)
        ipv6_address_domain3: str = self.get_domain_address_over_ssh('AAAA', self.domain3)
        self.base.kill_process_by_name('/DNS/dns_server.py')
        self.assertEqual(ipv4_address_domain1, self.fake_ipv4_address1)
        self.assertEqual(ipv6_address_domain1, self.fake_ipv6_address1 + '\n' + self.fake_ipv6_address2)
        self.assertEqual(ns_address_domain1, 'ns.apple.com.')
        self.assertEqual(mx_address_domain1, '10 mail1.apple.com.\n20 mail2.apple.com.')
        self.assertEqual(ipv4_address_domain2, self.fake_ipv4_address1 + '\n' + self.fake_ipv4_address2)
        self.assertEqual(ipv6_address_domain2, self.fake_ipv6_address1)
        self.assertEqual(ns_address_domain2, 'ns1.google.com.\nns2.google.com.')
        self.assertEqual(mx_address_domain2, '10 mail.google.com.')
        self.assertEqual(ipv4_address_domain3, self.your_ipv4_address)
        self.assertEqual(ipv6_address_domain3, self.your_ipv6_address)
        print('A ' + 'text.' + self.domain1 + ' ' + ipv4_address_domain1.replace('\n', ', '))
        print('AAAA ' + 'remote.' + self.domain1 + ' ' + ipv6_address_domain1.replace('\n', ', '))
        print('NS ' + self.domain1 + ' ' + ns_address_domain1.replace('\n', ', '))
        print('MX ' + self.domain1 + ' ' + mx_address_domain1.replace('\n', ', '))
        print('A ' + 'wire.' + self.domain2 + ' ' + ipv4_address_domain2.replace('\n', ', '))
        print('AAAA ' + 'book.' + self.domain2 + ' ' + ipv6_address_domain2.replace('\n', ', '))
        print('NS ' + self.domain2 + ' ' + ns_address_domain2.replace('\n', ', '))
        print('MX ' + self.domain2 + ' ' + mx_address_domain2.replace('\n', ', '))
        print('A ' + self.domain3 + ' ' + ipv4_address_domain3.replace('\n', ', '))
        print('AAAA ' + self.domain3 + ' ' + ipv6_address_domain3.replace('\n', ', '))

    def test14_csv_log_file(self):
        if isfile(self.log_file_name + '.csv'):
            remove(self.log_file_name + '.csv')
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --config_file "' + root_path + '/Scripts/DNS/' + self.config_file + '"' +
               ' --log_file_name ' + self.log_file_name + ' --log_file_format csv'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'text.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'remote.' + self.domain1)
        ns_address_domain1: str = self.get_domain_address_over_ssh('NS', self.domain1)
        mx_address_domain1: str = self.get_domain_address_over_ssh('MX', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'wire.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'book.' + self.domain2)
        ns_address_domain2: str = self.get_domain_address_over_ssh('NS', self.domain2)
        mx_address_domain2: str = self.get_domain_address_over_ssh('MX', self.domain2)
        self.get_domain_address_over_ssh('A', self.domain3)
        self.get_domain_address_over_ssh('AAAA', self.domain3)
        self.base.kill_process_by_name('/DNS/dns_server.py')

        self.assertTrue(isfile(self.log_file_name + '.csv'))
        with open(file=self.log_file_name + '.csv', mode='r') as log_file:
            log_file_content = log_file.read().splitlines()
        remove(self.log_file_name + '.csv')

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,text.' + self.domain1 + ',' +
                      ipv4_address_domain1.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,remote.' + self.domain1 + ',' +
                      ipv6_address_domain1.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',NS,' + self.domain1 + ',' +
                      ns_address_domain1.replace('\n', ' ').replace('com.', 'com'), log_file_content)
        self.assertIn(
            self.target_ipv4_address + ',' + self.your_ipv4_address + ',MX,' + self.domain1 + ',' +
            mx_address_domain1.replace('\n', ' ').replace('10 ', '').replace('20 ', '').replace('com.', 'com'),
            log_file_content)

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,wire.' + self.domain2 + ',' +
                      ipv4_address_domain2.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,book.' + self.domain2 + ',' +
                      ipv6_address_domain2.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',NS,' + self.domain2 + ',' +
                      ns_address_domain2.replace('\n', ' ').replace('com.', 'com'), log_file_content)
        self.assertIn(
            self.target_ipv4_address + ',' + self.your_ipv4_address + ',MX,' + self.domain2 + ',' +
            mx_address_domain2.replace('\n', ' ').replace('10 ', '').replace('20 ', '').replace('com.', 'com'),
            log_file_content)

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,' + self.domain3 + ',' +
                      self.your_ipv4_address, log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,' + self.domain3 + ',' +
                      self.your_ipv6_address, log_file_content)

    def test15_txt_log_file(self):
        if isfile(self.log_file_name + '.txt'):
            remove(self.log_file_name + '.txt')
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --config_file "' + root_path + '/Scripts/DNS/' + self.config_file + '"' +
               ' --log_file_name ' + self.log_file_name + ' --log_file_format txt'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'text.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'remote.' + self.domain1)
        ns_address_domain1: str = self.get_domain_address_over_ssh('NS', self.domain1)
        mx_address_domain1: str = self.get_domain_address_over_ssh('MX', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'wire.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'book.' + self.domain2)
        ns_address_domain2: str = self.get_domain_address_over_ssh('NS', self.domain2)
        mx_address_domain2: str = self.get_domain_address_over_ssh('MX', self.domain2)
        self.get_domain_address_over_ssh('A', self.domain3)
        self.get_domain_address_over_ssh('AAAA', self.domain3)
        self.base.kill_process_by_name('/DNS/dns_server.py')

        self.assertTrue(isfile(self.log_file_name + '.txt'))
        with open(file=self.log_file_name + '.txt', mode='r') as log_file:
            log_file_content = log_file.read().splitlines()
        remove(self.log_file_name + '.txt')

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,text.' + self.domain1 + ',' +
                      ipv4_address_domain1.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,remote.' + self.domain1 + ',' +
                      ipv6_address_domain1.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',NS,' + self.domain1 + ',' +
                      ns_address_domain1.replace('\n', ' ').replace('com.', 'com'), log_file_content)
        self.assertIn(
            self.target_ipv4_address + ',' + self.your_ipv4_address + ',MX,' + self.domain1 + ',' +
            mx_address_domain1.replace('\n', ' ').replace('10 ', '').replace('20 ', '').replace('com.', 'com'),
            log_file_content)

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,wire.' + self.domain2 + ',' +
                      ipv4_address_domain2.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,book.' + self.domain2 + ',' +
                      ipv6_address_domain2.replace('\n', ' '), log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',NS,' + self.domain2 + ',' +
                      ns_address_domain2.replace('\n', ' ').replace('com.', 'com'), log_file_content)
        self.assertIn(
            self.target_ipv4_address + ',' + self.your_ipv4_address + ',MX,' + self.domain2 + ',' +
            mx_address_domain2.replace('\n', ' ').replace('10 ', '').replace('20 ', '').replace('com.', 'com'),
            log_file_content)

        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',A,' + self.domain3 + ',' +
                      self.your_ipv4_address, log_file_content)
        self.assertIn(self.target_ipv4_address + ',' + self.your_ipv4_address + ',AAAA,' + self.domain3 + ',' +
                      self.your_ipv6_address, log_file_content)

    def test16_xml_log_file(self):
        if isfile(self.log_file_name + '.xml'):
            remove(self.log_file_name + '.xml')
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --config_file "' + root_path + '/Scripts/DNS/' + self.config_file + '"' +
               ' --log_file_name ' + self.log_file_name + ' --log_file_format xml'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'text.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'remote.' + self.domain1)
        ns_address_domain1: str = self.get_domain_address_over_ssh('NS', self.domain1)
        mx_address_domain1: str = self.get_domain_address_over_ssh('MX', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'wire.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'book.' + self.domain2)
        ns_address_domain2: str = self.get_domain_address_over_ssh('NS', self.domain2)
        mx_address_domain2: str = self.get_domain_address_over_ssh('MX', self.domain2)
        self.get_domain_address_over_ssh('A', self.domain3)
        self.get_domain_address_over_ssh('AAAA', self.domain3)
        self.base.kill_process_by_name('/DNS/dns_server.py')

        self.assertTrue(isfile(self.log_file_name + '.xml'))
        with open(file=self.log_file_name + '.xml', mode='r') as log_file:
            log_file_data: str = log_file.read()
        remove(self.log_file_name + '.xml')

        log_file_dict: Dict = parse(log_file_data)
        self.assertIn('dns_queries', log_file_dict.keys())
        self.assertEqual(len(log_file_dict['dns_queries']['dns_query']), 10)

        for dns_query in log_file_dict['dns_queries']['dns_query']:
            print(dict(dns_query))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': 'text.' + self.domain1,
                          'answer_address': ipv4_address_domain1.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries']['dns_query'][0]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': 'remote.' + self.domain1,
                          'answer_address': ipv6_address_domain1.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries']['dns_query'][1]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'NS',
                          'query_name': self.domain1,
                          'answer_address': ns_address_domain1.replace('\n', ' ').replace('.com.', '.com')},
                         dict(log_file_dict['dns_queries']['dns_query'][2]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'MX',
                          'query_name': self.domain1,
                          'answer_address':  mx_address_domain1.replace('\n', ' ').replace('.com.', '.com').
                         replace('10 ', '').replace('20 ', '')},
                         dict(log_file_dict['dns_queries']['dns_query'][3]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': 'wire.' + self.domain2,
                          'answer_address': ipv4_address_domain2.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries']['dns_query'][4]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': 'book.' + self.domain2,
                          'answer_address': ipv6_address_domain2.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries']['dns_query'][5]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'NS',
                          'query_name': self.domain2,
                          'answer_address': ns_address_domain2.replace('\n', ' ').replace('.com.', '.com')},
                         dict(log_file_dict['dns_queries']['dns_query'][6]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'MX',
                          'query_name': self.domain2,
                          'answer_address':  mx_address_domain2.replace('\n', ' ').replace('.com.', '.com').
                         replace('10 ', '').replace('20 ', '')},
                         dict(log_file_dict['dns_queries']['dns_query'][7]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': self.domain3,
                          'answer_address': self.your_ipv4_address},
                         dict(log_file_dict['dns_queries']['dns_query'][8]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': self.domain3,
                          'answer_address': self.your_ipv6_address},
                         dict(log_file_dict['dns_queries']['dns_query'][9]))

    def test17_json_log_file(self):
        if isfile(self.log_file_name + '.json'):
            remove(self.log_file_name + '.json')
        Popen(['python3 ' + root_path + '/Scripts/DNS/dns_server.py -i ' + self.network_interface +
               ' --config_file "' + root_path + '/Scripts/DNS/' + self.config_file + '"' +
               ' --log_file_name ' + self.log_file_name + ' --log_file_format json'],
              shell=True, stdout=PIPE)
        ipv4_address_domain1: str = self.get_domain_address_over_ssh('A', 'text.' + self.domain1)
        ipv6_address_domain1: str = self.get_domain_address_over_ssh('AAAA', 'remote.' + self.domain1)
        ns_address_domain1: str = self.get_domain_address_over_ssh('NS', self.domain1)
        mx_address_domain1: str = self.get_domain_address_over_ssh('MX', self.domain1)
        ipv4_address_domain2: str = self.get_domain_address_over_ssh('A', 'wire.' + self.domain2)
        ipv6_address_domain2: str = self.get_domain_address_over_ssh('AAAA', 'book.' + self.domain2)
        ns_address_domain2: str = self.get_domain_address_over_ssh('NS', self.domain2)
        mx_address_domain2: str = self.get_domain_address_over_ssh('MX', self.domain2)
        self.get_domain_address_over_ssh('A', self.domain3)
        self.get_domain_address_over_ssh('AAAA', self.domain3)
        self.base.kill_process_by_name('/DNS/dns_server.py')

        self.assertTrue(isfile(self.log_file_name + '.json'))
        with open(self.log_file_name + '.json', 'r') as log_file:
            log_file_data: str = log_file.read()
        remove(self.log_file_name + '.json')

        log_file_dict: Dict[str, List[str, str]] = loads(log_file_data)
        self.assertIn('dns_queries', log_file_dict.keys())
        self.assertEqual(len(log_file_dict['dns_queries']), 10)

        for dns_query in log_file_dict['dns_queries']:
            print(dict(dns_query))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': 'text.' + self.domain1,
                          'answer_address': ipv4_address_domain1.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries'][0]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': 'remote.' + self.domain1,
                          'answer_address': ipv6_address_domain1.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries'][1]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'NS',
                          'query_name': self.domain1,
                          'answer_address': ns_address_domain1.replace('\n', ' ').replace('.com.', '.com')},
                         dict(log_file_dict['dns_queries'][2]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'MX',
                          'query_name': self.domain1,
                          'answer_address':  mx_address_domain1.replace('\n', ' ').replace('.com.', '.com').
                         replace('10 ', '').replace('20 ', '')},
                         dict(log_file_dict['dns_queries'][3]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': 'wire.' + self.domain2,
                          'answer_address': ipv4_address_domain2.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries'][4]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': 'book.' + self.domain2,
                          'answer_address': ipv6_address_domain2.replace('\n', ' ')},
                         dict(log_file_dict['dns_queries'][5]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'NS',
                          'query_name': self.domain2,
                          'answer_address': ns_address_domain2.replace('\n', ' ').replace('.com.', '.com')},
                         dict(log_file_dict['dns_queries'][6]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'MX',
                          'query_name': self.domain2,
                          'answer_address':  mx_address_domain2.replace('\n', ' ').replace('.com.', '.com').
                         replace('10 ', '').replace('20 ', '')},
                         dict(log_file_dict['dns_queries'][7]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'A',
                          'query_name': self.domain3,
                          'answer_address': self.your_ipv4_address},
                         dict(log_file_dict['dns_queries'][8]))

        self.assertEqual({'from_ip_address': self.target_ipv4_address,
                          'to_ip_address': self.your_ipv4_address,
                          'query_type': 'AAAA',
                          'query_name': self.domain3,
                          'answer_address': self.your_ipv6_address},
                         dict(log_file_dict['dns_queries'][9]))

# endregion
