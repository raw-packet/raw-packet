# region Description
"""
test_base.py: Unit tests for Raw-packet Base class
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from platform import system
from os import getuid
from netifaces import interfaces, ifaddresses, AF_LINK, AF_INET
from subprocess import run, PIPE
from netaddr import IPNetwork
from time import sleep
from typing import List
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


# region Main class - BaseTest
class BaseTest(unittest.TestCase):

    # region Properties
    from raw_packet.Utils.base import Base
    from raw_packet.Tests.Unit_tests.variables import Variables
    base: Base = Base()

    test: str = ''
    ipv4_network_list: IPNetwork = IPNetwork(Variables.ipv4_network)

    run('ifconfig ' + Variables.test_network_interface + ' down', shell=True)
    run('ifconfig ' + Variables.test_network_interface + ' up', shell=True)
    run('sysctl -w net.ipv6.conf.' + Variables.test_network_interface + '.disable_ipv6=0', shell=True)
    sleep(1)
    run('ifconfig ' + Variables.test_network_interface + ' ' + Variables.your_ipv4_address +
        ' netmask ' + Variables.ipv4_network_mask, shell=True)
    run('ifconfig ' + Variables.test_network_interface +
        ' inet6 add ' + Variables.your_ipv6_glob_address + '/64', shell=True)
    run('ip route replace default via ' + Variables.router_ipv4_address, shell=True)
    run('ip -6 route replace default via ' + Variables.router_ipv6_glob_address, shell=True)
    # endregion

    # region Static methods
    @staticmethod
    def start_apache2_process() -> None:
        run('service apache2 start', shell=True)
        sleep(2)

    @staticmethod
    def pidof_apache2_process() -> List[str]:
        get_pid_command = run('pidof apache2', shell=True, stdout=PIPE)
        pids: bytes = get_pid_command.stdout
        pids: str = pids[:-1].decode('utf-8')
        return pids.split(' ')
    # endregion

    # region Test color text
    def test01_info_text(self):
        self.assertEqual(self.base.info_text('test'), str(self.base.cINFO + 'test' + self.base.cEND))

    def test02_error_text(self):
        self.assertEqual(self.base.error_text('test'), str(self.base.cERROR + 'test' + self.base.cEND))

    def test03_warning_text(self):
        self.assertEqual(self.base.warning_text('test'), str(self.base.cWARNING + 'test' + self.base.cEND))

    def test04_success_text(self):
        self.assertEqual(self.base.success_text('test'), str(self.base.cSUCCESS + 'test' + self.base.cEND))
    # endregion

    # region Check platform and user functions
    def test05_check_platform(self):
        if 'Linux' not in system():
            self.assertFalse(self.base.check_platform(False, 1, True))
        else:
            self.assertTrue(self.base.check_platform(False, 1, True))

    def test06_check_user(self):
        if getuid() != 0:
            self.assertFalse(self.base.check_user(False, 2, True))
        else:
            self.assertTrue(self.base.check_user(False, 2, True))
    # endregion

    # region Pack functions
    def test07_pack8(self):
        # Normal
        self.assertEqual(self.base.pack8(1, False, 3, True), b'\x01')
        # Bad input value
        self.assertIsNone(self.base.pack8('test', False, 3, False))

    def test08_pack16(self):
        # Normal
        self.assertEqual(self.base.pack16(1, False, 4, True), b'\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack16('test', False, 4, False))

    def test09_pack32(self):
        # Normal
        self.assertEqual(self.base.pack32(1, False, 5, True), b'\x00\x00\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack32('test', False, 5, False))

    def test10_pack64(self):
        # Normal
        self.assertEqual(self.base.pack64(1, False, 6, True), b'\x00\x00\x00\x00\x00\x00\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack64('test', False, 6, False))
    # endregion

    # region Network functions
    def test11_network_interface_selection(self):
        self.assertEqual(self.base.network_interface_selection(BaseTest.Variables.test_network_interface),
                         BaseTest.Variables.test_network_interface)

    def test12_get_interface_settings(self):
        # Normal
        interface_settings = self.base.get_interface_settings(BaseTest.Variables.test_network_interface, False)
        self.assertIn('Interface name', interface_settings.keys())
        self.assertIn('MAC address', interface_settings.keys())
        self.assertIn('IPv4 address', interface_settings.keys())
        self.assertIn('IPv6 link local address', interface_settings.keys())
        self.assertIn('IPv6 global addresses', interface_settings.keys())
        self.assertIn('IPv4 netmask', interface_settings.keys())
        self.assertIn('IPv4 network', interface_settings.keys())
        self.assertIn('First IPv4 address', interface_settings.keys())
        self.assertIn('Second IPv4 address', interface_settings.keys())
        self.assertIn('Penultimate IPv4 address', interface_settings.keys())
        self.assertIn('Last IPv4 address', interface_settings.keys())
        self.assertIn('IPv4 broadcast', interface_settings.keys())
        self.assertIn('IPv4 gateway', interface_settings.keys())
        self.assertIn('IPv6 gateway', interface_settings.keys())

        self.assertEqual(BaseTest.Variables.test_network_interface, interface_settings['Interface name'])
        self.assertEqual(BaseTest.Variables.your_mac_address, interface_settings['MAC address'])
        self.assertEqual(BaseTest.Variables.your_ipv4_address, interface_settings['IPv4 address'])
        self.assertEqual(BaseTest.Variables.your_ipv6_link_address, interface_settings['IPv6 link local address'])
        self.assertIn(BaseTest.Variables.your_ipv6_glob_address, interface_settings['IPv6 global addresses'])
        self.assertEqual(BaseTest.Variables.ipv4_network_mask, interface_settings['IPv4 netmask'])
        self.assertEqual(BaseTest.Variables.ipv4_network, interface_settings['IPv4 network'])
        self.assertEqual(BaseTest.Variables.ipv4_first_address, interface_settings['First IPv4 address'])
        self.assertEqual(BaseTest.Variables.ipv4_second_address, interface_settings['Second IPv4 address'])
        self.assertEqual(BaseTest.Variables.ipv4_penultimate_address, interface_settings['Penultimate IPv4 address'])
        self.assertEqual(BaseTest.Variables.ipv4_last_address, interface_settings['Last IPv4 address'])
        self.assertEqual(BaseTest.Variables.ipv4_broadcast, interface_settings['IPv4 broadcast'])
        self.assertEqual(BaseTest.Variables.router_ipv4_address, interface_settings['IPv4 gateway'])
        self.assertEqual(BaseTest.Variables.router_ipv6_glob_address, interface_settings['IPv6 gateway'])

        # Bad network interface name
        self.assertEqual(self.base.get_interface_settings(BaseTest.Variables.bad_network_interface, False),
                         {
                             'Interface name': BaseTest.Variables.bad_network_interface,
                             'MAC address': None,
                             'IPv4 address': None,
                             'IPv6 link local address': None,
                             'IPv6 global address': None,
                             'IPv6 global addresses': [],
                             'IPv4 netmask': None,
                             'IPv4 network': None,
                             'First IPv4 address': None,
                             'Second IPv4 address': None,
                             'Penultimate IPv4 address': None,
                             'Last IPv4 address': None,
                             'IPv4 broadcast': None,
                             'IPv4 gateway': None,
                             'IPv6 gateway': None
                         })

    def test13_get_interface_mac_address(self):
        # Normal
        self.assertEqual(self.base.get_interface_mac_address(BaseTest.Variables.test_network_interface, True, 7),
                         BaseTest.Variables.your_mac_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_mac_address(BaseTest.Variables.bad_network_interface, False, 7))

    def test14_get_interface_ipv4_address(self):
        # Normal
        self.assertEqual(self.base.get_interface_ip_address(BaseTest.Variables.test_network_interface, True, 8),
                         BaseTest.Variables.your_ipv4_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ip_address(BaseTest.Variables.bad_network_interface, False, 8))

    def test15_get_interface_ipv6_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_address(BaseTest.Variables.test_network_interface, 0, True, 9))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_address(BaseTest.Variables.bad_network_interface, 0, False, 9))

    def test16_get_interface_ipv6_link_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_link_address(BaseTest.Variables.test_network_interface, True, 10))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_link_address(BaseTest.Variables.bad_network_interface, False, 10))

    def test17_get_interface_ipv6_glob_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_glob_address(BaseTest.Variables.test_network_interface))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_glob_address(BaseTest.Variables.bad_network_interface))

    def test18_get_interface_ipv6_glob_addresses(self):
        # Normal
        self.assertIn(BaseTest.Variables.your_ipv6_glob_address,
                      self.base.get_interface_ipv6_glob_addresses(BaseTest.Variables.test_network_interface))
        # Bad network interface name
        self.assertEqual(len(self.base.get_interface_ipv6_glob_addresses(BaseTest.Variables.bad_network_interface)), 0)

    def test19_make_ipv6_link_address(self):
        # Normal
        self.assertEqual(self.base.make_ipv6_link_address('12:34:56:78:90:ab'), 'fe80::1034:56ff:fe78:90ab')
        # Bad MAC address
        self.assertIsNone(self.base.make_ipv6_link_address('12:34:56:78:90:abc', False, 12))

    def test20_get_interface_netmask(self):
        # Normal
        self.assertEqual(self.base.get_interface_netmask(BaseTest.Variables.test_network_interface, True, 13),
                         BaseTest.Variables.ipv4_network_mask)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_netmask(BaseTest.Variables.bad_network_interface, False, 13))

    def test21_get_interface_network(self):
        # Normal
        self.assertEqual(self.base.get_interface_network(BaseTest.Variables.test_network_interface, True, 14),
                         BaseTest.Variables.ipv4_network)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_network(BaseTest.Variables.bad_network_interface, False, 14))

    def test22_get_ip_on_interface_by_index(self):
        # Normal
        self.assertEqual(self.base.get_ip_on_interface_by_index(BaseTest.Variables.test_network_interface, 1, True, 15),
                         BaseTest.Variables.ipv4_first_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_ip_on_interface_by_index(BaseTest.Variables.bad_network_interface, 1, False, 15))

    def test23_get_first_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_first_ip_on_interface(BaseTest.Variables.test_network_interface, True, 16),
                         BaseTest.Variables.ipv4_first_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_first_ip_on_interface(BaseTest.Variables.bad_network_interface, False, 16))

    def test24_get_second_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_second_ip_on_interface(BaseTest.Variables.test_network_interface, True, 17),
                         BaseTest.Variables.ipv4_second_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_second_ip_on_interface(BaseTest.Variables.bad_network_interface, False, 17))

    def test25_get_penultimate_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_penultimate_ip_on_interface(BaseTest.Variables.test_network_interface, True, 18),
                         BaseTest.Variables.ipv4_penultimate_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_penultimate_ip_on_interface(BaseTest.Variables.bad_network_interface, False, 18))

    def test26_get_last_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_last_ip_on_interface(BaseTest.Variables.test_network_interface, True, 19),
                         BaseTest.Variables.ipv4_last_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_last_ip_on_interface(BaseTest.Variables.bad_network_interface, False, 19))

    def test27_get_random_ip_on_interface(self):
        # Normal
        self.assertIn(self.base.get_random_ip_on_interface(BaseTest.Variables.test_network_interface, True, 20),
                      self.ipv4_network_list)
        # Bad network interface name
        self.assertIsNone(self.base.get_random_ip_on_interface(BaseTest.Variables.bad_network_interface, False, 20))

    def test28_get_interface_broadcast(self):
        # Normal
        self.assertEqual(self.base.get_interface_broadcast(BaseTest.Variables.test_network_interface, True, 21),
                         BaseTest.Variables.ipv4_broadcast)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_broadcast(BaseTest.Variables.bad_network_interface, False, 21))

    def test29_get_interface_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_gateway(BaseTest.Variables.test_network_interface, AF_INET, True, 22),
                         BaseTest.Variables.router_ipv4_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_gateway(BaseTest.Variables.bad_network_interface, AF_INET, False, 22))

    def test30_get_interface_ipv4_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_ipv4_gateway(BaseTest.Variables.test_network_interface, True, 23),
                         BaseTest.Variables.router_ipv4_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv4_gateway(BaseTest.Variables.bad_network_interface, False, 23))

    def test31_get_interface_ipv6_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_ipv6_gateway(BaseTest.Variables.test_network_interface, True, 24),
                         BaseTest.Variables.router_ipv6_glob_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_gateway(BaseTest.Variables.bad_network_interface, False, 24))
    # endregion

    # region Check installed software
    def test32_apt_list_installed_packages(self):
        # Normal
        self.assertIn(b'python3', self.base.apt_list_installed_packages(True, 25))
        # Bad software name
        self.assertNotIn(b'test_test_test', self.base.apt_list_installed_packages(True, 25))

    def test33_check_installed_software(self):
        # Normal
        self.assertTrue(self.base.check_installed_software('python3', True, 26))
        # Bad software name
        self.assertFalse(self.base.check_installed_software('test_test_test', True, 26))
    # endregion

    # region Process control functions
    def test34_check_process(self):
        # Normal
        self.assertEqual(self.base.check_process('systemd'), 1)
        # Bad process name
        self.assertEqual(self.base.check_process('test_test_test'), -1)

    def test35_get_process_pid(self):
        # Normal
        self.assertEqual(self.base.get_process_pid('systemd'), 1)
        # Bad process name
        self.assertEqual(self.base.get_process_pid('test_test_test'), -1)

    def test36_get_process_pid_by_listen_port(self):
        # Start apache2 process
        self.start_apache2_process()
        # Normal
        self.assertIsNotNone(self.base.get_process_pid_by_listen_port(80, '::', 'tcp', True, 27))
        # Bad port
        self.assertIsNone(self.base.get_process_pid_by_listen_port(123123, '::', 'tcp', False, 27))
        # Bad proto
        self.assertIsNone(self.base.get_process_pid_by_listen_port(80, '::', 'test', False, 27))

    def test37_kill_process(self):
        # Start apache2 processes
        self.start_apache2_process()
        # Check apache2 process is exist
        self.assertGreater(len(self.pidof_apache2_process()), 1)
        # Get apache2 processes first pid
        apache2_pid: str = self.pidof_apache2_process()[0]
        # Kill process by pid
        self.assertTrue(self.base.kill_process(int(apache2_pid)))
        sleep(1)
        # Check process is killed
        self.assertNotIn(apache2_pid, self.pidof_apache2_process())

    def test38_kill_process_by_name(self):
        # Start apache2 processes
        self.start_apache2_process()
        # Check apache2 process is exist
        self.assertGreater(len(self.pidof_apache2_process()), 1)
        # Kill apache2 process by name
        self.assertTrue(self.base.kill_process_by_name('apache2'))
        sleep(1)
        # Check apache2 process is killed
        apache2_pids: List[str] = self.pidof_apache2_process()
        self.assertEqual(len(apache2_pids), 1)

    def test39_kill_processes_by_listen_port(self):
        # Start apache2 processes
        self.start_apache2_process()
        # Check apache2 process is exist
        self.assertGreater(len(self.pidof_apache2_process()), 1)
        # Kill apache2 process by listen port
        self.assertTrue(self.base.kill_processes_by_listen_port(80))
        sleep(1)
        # Check apache2 process is killed
        apache2_pids: List[str] = self.pidof_apache2_process()
        self.assertEqual(len(apache2_pids), 1)
    # endregion

    # region Others functions
    def test40_ipv6_address_validation(self):
        # Normal
        self.assertTrue(self.base.ipv6_address_validation('fd00::1', True, 28))
        # Bad IPv6 address
        self.assertFalse(self.base.ipv6_address_validation('fd00:::1', False, 28))

    def test41_ip_address_validation(self):
        # Normal
        self.assertTrue(self.base.ip_address_validation('192.168.1.1', True, 29))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_validation('192.168.1.1.1', False, 29))

    def test42_mac_address_validation(self):
        # Normal
        self.assertTrue(self.base.mac_address_validation('01:23:45:67:89:0a', True, 30))
        # Bad MAC address
        self.assertFalse(self.base.mac_address_validation('01:23:45:67:89:0ab', False, 30))

    def test43_ip_address_in_range(self):
        # Normal
        self.assertTrue(self.base.ip_address_in_range('192.168.1.2', '192.168.1.1', '192.168.1.3', True, 31))
        # Address not in range
        self.assertFalse(self.base.ip_address_in_range('192.168.1.4', '192.168.1.1', '192.168.1.3', False, 31))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_in_range('192.168.1.4.5', '192.168.1.1', '192.168.1.3', False, 31))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_in_range('192.168.1.4', '192.168.1.1.2', '192.168.1.3', False, 31))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_in_range('192.168.1.4', '192.168.1.1', '192.168.1.3.4', False, 31))

    def test44_ip_address_in_network(self):
        # Normal
        self.assertTrue(self.base.ip_address_in_network('192.168.1.1', '192.168.1.0/24', True, 32))
        # Address not in network
        self.assertFalse(self.base.ip_address_in_network('192.168.1.254', '192.168.1.0/27', False, 32))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_in_network('192.168.1.1.1', '192.168.1.0/27', False, 32))
        # Bad Network
        self.assertFalse(self.base.ip_address_in_network('192.168.1.1', '192.168.1.0.0/24', False, 32))
        # Bad Network
        self.assertFalse(self.base.ip_address_in_network('192.168.1.1', '192.168.1.1/33', False, 32))

    def test45_ip_address_increment(self):
        # Normal
        self.assertEqual(self.base.ip_address_increment(BaseTest.Variables.ipv4_first_address, True, 33),
                         BaseTest.Variables.ipv4_second_address)
        # Bad IPv4 address
        self.assertIsNone(self.base.ip_address_increment('192.168.1.1.1', False, 33))

    def test46_ip_address_decrement(self):
        # Normal
        self.assertEqual(self.base.ip_address_decrement(BaseTest.Variables.ipv4_second_address, True, 34),
                         BaseTest.Variables.ipv4_first_address)
        # Bad IPv4 address
        self.assertIsNone(self.base.ip_address_decrement('192.168.1.1.1', False, 34))

    def test47_ip_address_compare(self):
        # Bad first address equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.1.1', '192.168.1.2', 'eq', False, 35))
        # Bad second address equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.1', '192.168.1.2.2', 'eq', False, 35))

        # Normal equal
        self.assertTrue(self.base.ip_address_compare('192.168.1.1', '192.168.1.1', 'eq', True, 35))
        # Not equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.1', '192.168.1.2', 'eq', False, 35))

        # Normal not equal
        self.assertTrue(self.base.ip_address_compare('192.168.1.1', '192.168.1.2', 'ne', True, 35))
        # Equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.1', '192.168.1.1', 'ne', False, 35))

        # Normal greater
        self.assertTrue(self.base.ip_address_compare('192.168.1.2', '192.168.1.1', 'gt', True, 35))
        # Not greater
        self.assertFalse(self.base.ip_address_compare('192.168.1.2', '192.168.1.2', 'gt', False, 35))

        # Normal greater or equal
        self.assertTrue(self.base.ip_address_compare('192.168.1.2', '192.168.1.1', 'ge', True, 35))
        # Not greater or equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.2', '192.168.1.3', 'ge', False, 35))

        # Normal less
        self.assertTrue(self.base.ip_address_compare('192.168.1.1', '192.168.1.2', 'lt', True, 35))
        # Not less
        self.assertFalse(self.base.ip_address_compare('192.168.1.2', '192.168.1.2', 'lt', False, 35))

        # Normal less or equal
        self.assertTrue(self.base.ip_address_compare('192.168.1.1', '192.168.1.2', 'le', True, 35))
        # Not less or equal
        self.assertFalse(self.base.ip_address_compare('192.168.1.2', '192.168.1.1', 'le', False, 35))

    def test48_make_random_string(self):
        self.assertEqual(len(self.base.make_random_string(8)), 8)

    def test49_get_mac_prefixes(self):
        self.assertIn({'prefix': '00:00:01', 'vendor': 'Xerox Corporation'},
                      self.base.get_mac_prefixes('mac-prefixes.txt'))

    def test50_get_vendor_by_mac_address(self):
        self.assertEqual(self.base.get_vendor_by_mac_address('00:00:01:23:45:67'), 'Xerox Corporation')
    # endregion

    # region End of tests
    def test51_end_of_tests(self):
        run('ip link set ' + BaseTest.Variables.test_network_interface + ' down', shell=True)
        run('ip link set ' + BaseTest.Variables.test_network_interface + ' up', shell=True)
        run('dhclient ' + BaseTest.Variables.test_network_interface, shell=True)
        run('ip route del 0/0', shell=True)
        run('ip route add default via ' + BaseTest.Variables.router_ipv4_address, shell=True)
        sleep(1)
        self.assertTrue(True)
    # endregion

# endregion
