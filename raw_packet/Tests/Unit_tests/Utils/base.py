# region Description
"""
base.py: Unit tests for Raw-packet Base class
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(abspath(__file__))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from platform import system
from os import getuid
from netifaces import interfaces, ifaddresses, AF_LINK, AF_INET
from subprocess import run, PIPE
from netaddr import IPNetwork
from time import sleep
from typing import List
import unittest
# endregion

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


# region Main class - BaseTest
class BaseTest(unittest.TestCase):

    # region Properties
    base: Base = Base()
    interface: str = interfaces()[1]
    mac_address: str = str(ifaddresses(interface)[AF_LINK][0]['addr'])

    ipv4_address: str = '192.168.119.136'
    ipv4_network_mask: str = '255.255.255.0'
    ipv4_broadcast: str = '192.168.119.255'
    ipv4_network: str = '192.168.119.0/24'
    ipv4_network_list: IPNetwork = IPNetwork(ipv4_network)
    first_ipv4: str = '192.168.119.1'
    second_ipv4: str = '192.168.119.2'
    penultimate_ipv4: str = '192.168.119.253'
    last_ipv4: str = '192.168.119.254'
    test: str = ''
    ipv4_default_gateway_command = run('ip route show | grep "default" | awk \'{print $3}\'', shell=True, stdout=PIPE)
    ipv4_default_gateway: bytes = ipv4_default_gateway_command.stdout
    ipv4_default_gateway: str = ipv4_default_gateway[:-1].decode('utf-8')
    ipv4_gateway: str = '192.168.119.1'
    ipv6_link_local_address_command = run('ip address list dev eth0 | grep \'fe80::\' | sed \'s/\// /\' ' +
                                          '| awk \'{print $2}\'', shell=True, stdout=PIPE)
    ipv6_link_local_address: bytes = ipv6_link_local_address_command.stdout
    ipv6_link_local_address: str = ipv6_link_local_address[:-1].decode('utf-8')
    ipv6_address: str = 'fd00::123'
    ipv6_gateway: str = 'fd00::1'

    # run('ip link set ' + interface + ' down', shell=True)
    run('ip link set ' + interface + ' up', shell=True)
    run('ip a add ' + ipv4_address + '/' + ipv4_network_mask + ' dev ' + interface, shell=True)
    run('ip route del 0/0', shell=True)
    run('ip route add default via ' + ipv4_gateway, shell=True)
    run('ip -6 addr add ' + ipv6_address + '/64 dev ' + interface, shell=True)
    run('ip -6 route add default via ' + ipv6_gateway, shell=True)
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
    def test_info_text(self):
        self.assertEqual(self.base.info_text('test'), str(self.base.cINFO + 'test' + self.base.cEND))

    def test_error_text(self):
        self.assertEqual(self.base.error_text('test'), str(self.base.cERROR + 'test' + self.base.cEND))

    def test_warning_text(self):
        self.assertEqual(self.base.warning_text('test'), str(self.base.cWARNING + 'test' + self.base.cEND))

    def test_success_text(self):
        self.assertEqual(self.base.success_text('test'), str(self.base.cSUCCESS + 'test' + self.base.cEND))
    # endregion

    # region Check platform and user functions
    def test_check_platform(self):
        if 'Linux' not in system():
            self.assertFalse(self.base.check_platform(False, 1, True))
        else:
            self.assertTrue(self.base.check_platform(False, 1, True))

    def test_check_user(self):
        if getuid() != 0:
            self.assertFalse(self.base.check_user(False, 2, True))
        else:
            self.assertTrue(self.base.check_user(False, 2, True))
    # endregion

    # region Pack functions
    def test_pack8(self):
        # Normal
        self.assertEqual(self.base.pack8(1, False, 3, True), b'\x01')
        # Bad input value
        self.assertIsNone(self.base.pack8('test', False, 3, False))

    def test_pack16(self):
        # Normal
        self.assertEqual(self.base.pack16(1, False, 4, True), b'\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack16('test', False, 4, False))

    def test_pack32(self):
        # Normal
        self.assertEqual(self.base.pack32(1, False, 5, True), b'\x00\x00\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack32('test', False, 5, False))

    def test_pack64(self):
        # Normal
        self.assertEqual(self.base.pack64(1, False, 6, True), b'\x00\x00\x00\x00\x00\x00\x00\x01')
        # Bad input value
        self.assertIsNone(self.base.pack64('test', False, 6, False))
    # endregion

    # region Network functions
    def test_network_interface_selection(self):
        self.assertEqual(self.base.network_interface_selection(self.interface), self.interface)

    def test_get_interface_settings(self):
        # Normal
        self.assertEqual(self.base.get_interface_settings(self.interface, False),
                         {
                             'MAC address': self.mac_address,
                             'IPv4 address': self.ipv4_address,
                             'IPv6 link local address': self.ipv6_link_local_address,
                             'IPv6 global address': self.ipv6_address,
                             'IPv6 global addresses': [self.ipv6_address],
                             'IPv4 netmask': self.ipv4_network_mask,
                             'IPv4 network': self.ipv4_network,
                             'First IPv4 address': self.first_ipv4,
                             'Second IPv4 address': self.second_ipv4,
                             'Penultimate IPv4 address': self.penultimate_ipv4,
                             'Last IPv4 address': self.last_ipv4,
                             'IPv4 broadcast': self.ipv4_broadcast,
                             'IPv4 gateway': self.ipv4_gateway,
                             'IPv6 gateway': self.ipv6_gateway
                         })
        # Bad network interface name
        self.assertEqual(self.base.get_interface_settings('self.interface', False),
                         {
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

    def test_get_interface_mac_address(self):
        # Normal
        self.assertEqual(self.base.get_interface_mac_address(self.interface, True, 7), self.mac_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_mac_address('self.interface', False, 7))

    def test_get_interface_ip_address(self):
        # Normal
        self.assertEqual(self.base.get_interface_ip_address(self.interface, True, 8), self.ipv4_address)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ip_address('self.interface', False, 8))

    def test_get_interface_ipv6_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_address(self.interface, 0, True, 9))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_address('self.interface', 0, False, 9))

    def test_get_interface_ipv6_link_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_link_address(self.interface, True, 10))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_link_address('self.interface', False, 10))

    def test_get_interface_ipv6_glob_address(self):
        # Normal
        self.assertIsNotNone(self.base.get_interface_ipv6_glob_address(self.interface))
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_glob_address('self.interface'))

    def test_get_interface_ipv6_glob_addresses(self):
        # Normal
        self.assertIn(self.ipv6_address, self.base.get_interface_ipv6_glob_addresses(self.interface))
        # Bad network interface name
        self.assertEqual(len(self.base.get_interface_ipv6_glob_addresses('self.interface')), 0)

    def test_make_ipv6_link_address(self):
        # Normal
        self.assertEqual(self.base.make_ipv6_link_address('12:34:56:78:90:ab'), 'fe80::1034:56ff:fe78:90ab')
        # Bad MAC address
        self.assertIsNone(self.base.make_ipv6_link_address('12:34:56:78:90:abc', False, 12))

    def test_get_interface_netmask(self):
        # Normal
        self.assertEqual(self.base.get_interface_netmask(self.interface, True, 13), self.ipv4_network_mask)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_netmask('self.interface', False, 13))

    def test_get_interface_network(self):
        # Normal
        self.assertEqual(self.base.get_interface_network(self.interface, True, 14), self.ipv4_network)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_network('self.interface', False, 14))

    def test_get_ip_on_interface_by_index(self):
        # Normal
        self.assertEqual(self.base.get_ip_on_interface_by_index(self.interface, 1, True, 15), self.first_ipv4)
        # Bad network interface name
        self.assertIsNone(self.base.get_ip_on_interface_by_index('self.interface', 1, False, 15))

    def test_get_first_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_first_ip_on_interface(self.interface, True, 16), self.first_ipv4)
        # Bad network interface name
        self.assertIsNone(self.base.get_first_ip_on_interface('self.interface', False, 16))

    def test_get_second_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_second_ip_on_interface(self.interface, True, 17), self.second_ipv4)
        # Bad network interface name
        self.assertIsNone(self.base.get_second_ip_on_interface('self.interface', False, 17))

    def test_get_penultimate_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_penultimate_ip_on_interface(self.interface, True, 18), self.penultimate_ipv4)
        # Bad network interface name
        self.assertIsNone(self.base.get_penultimate_ip_on_interface('self.interface', False, 18))

    def test_get_last_ip_on_interface(self):
        # Normal
        self.assertEqual(self.base.get_last_ip_on_interface(self.interface, True, 19), self.last_ipv4)
        # Bad network interface name
        self.assertIsNone(self.base.get_last_ip_on_interface('self.interface', False, 19))

    def test_get_random_ip_on_interface(self):
        # Normal
        self.assertIn(self.base.get_random_ip_on_interface(self.interface, True, 20), self.ipv4_network_list)
        # Bad network interface name
        self.assertIsNone(self.base.get_random_ip_on_interface('self.interface', False, 20))

    def test_get_interface_broadcast(self):
        # Normal
        self.assertEqual(self.base.get_interface_broadcast(self.interface, True, 21), self.ipv4_broadcast)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_broadcast('self.interface', False, 21))

    def test_get_interface_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_gateway(self.interface, AF_INET, True, 22), self.ipv4_gateway)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_gateway('self.interface', AF_INET, False, 22))

    def test_get_interface_ipv4_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_ipv4_gateway(self.interface, True, 23), self.ipv4_gateway)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv4_gateway('self.interface', False, 23))

    def test_get_interface_ipv6_gateway(self):
        # Normal
        self.assertEqual(self.base.get_interface_ipv6_gateway(self.interface, True, 24), self.ipv6_gateway)
        # Bad network interface name
        self.assertIsNone(self.base.get_interface_ipv6_gateway('self.interface', False, 24))
    # endregion

    # region Check installed software
    def test_apt_list_installed_packages(self):
        # Normal
        self.assertIn(b'python3', self.base.apt_list_installed_packages(True, 25))
        # Bad software name
        self.assertNotIn(b'test_test_test', self.base.apt_list_installed_packages(True, 25))

    def test_check_installed_software(self):
        # Normal
        self.assertTrue(self.base.check_installed_software('python3', True, 26))
        # Bad software name
        self.assertFalse(self.base.check_installed_software('test_test_test', True, 26))
    # endregion

    # region Process control functions
    def test_check_process(self):
        # Normal
        self.assertEqual(self.base.check_process('systemd'), 1)
        # Bad process name
        self.assertEqual(self.base.check_process('test_test_test'), -1)

    def test_get_process_pid(self):
        # Normal
        self.assertEqual(self.base.get_process_pid('systemd'), 1)
        # Bad process name
        self.assertEqual(self.base.get_process_pid('test_test_test'), -1)

    def test_get_process_pid_by_listen_port(self):
        # Start apache2 process
        self.start_apache2_process()
        # Normal
        self.assertIsNotNone(self.base.get_process_pid_by_listen_port(80, '::', 'tcp', True, 27))
        # Bad port
        self.assertIsNone(self.base.get_process_pid_by_listen_port(123123, '::', 'tcp', False, 27))
        # Bad proto
        self.assertIsNone(self.base.get_process_pid_by_listen_port(80, '::', 'test', False, 27))

    def test_kill_process(self):
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

    def test_kill_process_by_name(self):
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

    def test_kill_processes_by_listen_port(self):
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
    def test_ipv6_address_validation(self):
        # Normal
        self.assertTrue(self.base.ipv6_address_validation('fd00::1', True, 28))
        # Bad IPv6 address
        self.assertFalse(self.base.ipv6_address_validation('fd00:::1', False, 28))

    def test_ip_address_validation(self):
        # Normal
        self.assertTrue(self.base.ip_address_validation('192.168.1.1', True, 29))
        # Bad IPv4 address
        self.assertFalse(self.base.ip_address_validation('192.168.1.1.1', False, 29))

    def test_mac_address_validation(self):
        # Normal
        self.assertTrue(self.base.mac_address_validation('01:23:45:67:89:0a', True, 30))
        # Bad MAC address
        self.assertFalse(self.base.mac_address_validation('01:23:45:67:89:0ab', False, 30))

    def test_ip_address_in_range(self):
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

    def test_ip_address_in_network(self):
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

    def test_ip_address_increment(self):
        # Normal
        self.assertEqual(self.base.ip_address_increment(self.first_ipv4, True, 33), self.second_ipv4)
        # Bad IPv4 address
        self.assertIsNone(self.base.ip_address_increment('192.168.1.1.1', False, 33))

    def test_ip_address_decrement(self):
        # Normal
        self.assertEqual(self.base.ip_address_decrement(self.second_ipv4, True, 34), self.first_ipv4)
        # Bad IPv4 address
        self.assertIsNone(self.base.ip_address_decrement('192.168.1.1.1', False, 34))

    def test_ip_address_compare(self):
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

    def test_make_random_string(self):
        self.assertEqual(len(self.base.make_random_string(8)), 8)

    def test_get_mac_prefixes(self):
        self.assertIn({'prefix': '0050BA', 'vendor': 'D-Link'}, self.base.get_mac_prefixes('mac-prefixes.txt'))
    # endregion

    # region End of tests
    def end_of_tests(self):
        run('ip link set ' + self.interface + ' down', shell=True)
        run('ip link set ' + self.interface + ' up', shell=True)
        run('dhclient ' + self.interface, shell=True)
        run('ip route del 0/0', shell=True)
        run('ip route add default via ' + self.ipv4_default_gateway, shell=True)
    # endregion

# endregion
