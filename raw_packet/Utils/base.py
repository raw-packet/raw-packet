# region Description
"""
test_base.py: Base class for Raw-packet project
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from platform import system, release
from sys import exit, stdout
try:
    from os import getuid
except ImportError:
    from ctypes import windll
from os.path import dirname, abspath, isfile, join
try:
    from pwd import getpwuid
except ModuleNotFoundError:
    pass
from random import choice, randint
try:
    from netifaces import interfaces, ifaddresses, AF_LINK, AF_INET, AF_INET6
    from netifaces import gateways
except ModuleNotFoundError:
    from socket import AF_INET, AF_INET6, gethostname, gethostbyname
    from getmac import get_mac_address
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from struct import pack, error
from ipaddress import IPv4Address, AddressValueError
from re import match, compile, search
import subprocess as sub
import psutil as ps
import socket as sock
from distro import linux_distribution
from prettytable import PrettyTable
from typing import Dict, List, Union
from paramiko import RSAKey, SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError, AuthenticationException
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


# region Main class - Base
class Base:

    # region Set variables
    vendor_list: List[Dict[str, str]] = list()
    os_installed_packages_list = None
    windows_mac_address_regex = compile(r'([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})')
    # endregion

    # region Init
    def __init__(self) -> None:
        """
        Init string variables
        """

        if self.get_platform().startswith('Windows'):
            self.cINFO: str = ''
            self.cERROR: str = ''
            self.cSUCCESS: str = ''
            self.cWARNING: str = ''
            self.cEND: str = ''
        else:
            self.cINFO: str = '\033[1;34m'
            self.cERROR: str = '\033[1;31m'
            self.cSUCCESS: str = '\033[1;32m'
            self.cWARNING: str = '\033[1;33m'
            self.cEND: str = '\033[0m'

        self.c_info: str = self.cINFO + '[*]' + self.cEND + ' '
        self.c_error: str = self.cERROR + '[-]' + self.cEND + ' '
        self.c_success: str = self.cSUCCESS + '[+]' + self.cEND + ' '
        self.c_warning: str = self.cWARNING + '[!]' + self.cEND + ' '

        self.lowercase_letters: str = 'abcdefghijklmnopqrstuvwxyz'
        self.uppercase_letters: str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.digits: str = '0123456789'
    # endregion

    # region Output functions
    def get_banner(self) -> str:
        """
        Get string of colored banner
        :return: String of colored banner
        """
        return \
            self.cSUCCESS + \
            "                                          _        _   \n" + \
            " _ __ __ ___      __     _ __   __ _  ___| | _____| |_ \n" + \
            "| '__/ _` \ \ /\ / /___ | '_ \ / _` |/ __| |/ / _ \ __|\n" + \
            "| | | (_| |\ V  V /|___|| |_) | (_| | (__|   <  __/ |_ \n" + \
            "|_|  \__,_| \_/\_/      | .__/ \__,_|\___|_|\_\___|\__|\n" + \
            "                        |_|                      v" + __version__ + "\n" + \
            self.cEND + self.cWARNING + \
            "             https://raw-packet.github.io/\r\n" + self.cEND

    def print_banner(self) -> None:
        """
        Print colored banner in console
        :return: None
        """
        print(self.get_banner())

    def _color_print(self, color: str = 'blue', *strings: str) -> None:
        """
        Print colored text in console
        :param color: Set color: blue, red, orange, green (default: blue)
        :param strings: Strings for printing in console
        :return: None
        """
        if color == 'blue':
            stdout.write(self.c_info)
        elif color == 'red':
            stdout.write(self.c_error)
        elif color == 'orange':
            stdout.write(self.c_warning)
        elif color == 'green':
            stdout.write(self.c_success)
        else:
            stdout.write(self.c_info)
        for index in range(len(strings)):
            if index % 2 == 0:
                stdout.write(strings[index])
            else:
                if color == 'blue':
                    stdout.write(self.cINFO)
                if color == 'red':
                    stdout.write(self.cERROR)
                if color == 'orange':
                    stdout.write(self.cWARNING)
                if color == 'green':
                    stdout.write(self.cSUCCESS)
                stdout.write(strings[index] + self.cEND)
        stdout.write('\n')

    def _color_text(self, color: str = 'blue', string: str = '') -> str:
        """
        Make colored string
        :param color: Set color: blue, red, orange, green (default: blue)
        :param string: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        if color == 'blue':
            return self.cINFO + string + self.cEND
        elif color == 'red':
            return self.cERROR + string + self.cEND
        elif color == 'orange':
            return self.cWARNING + string + self.cEND
        elif color == 'green':
            return self.cSUCCESS + string + self.cEND
        else:
            return self.cINFO + string + self.cEND

    def print_info(self, *strings: str) -> None:
        """
        Print informational text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print('blue', *strings)

    def print_error(self, *strings: str) -> None:
        """
        Print error text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print('red', *strings)

    def print_warning(self, *strings: str) -> None:
        """
        Print warning text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print('orange', *strings)

    def print_success(self, *strings: str) -> None:
        """
        Print success text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print('green', *strings)

    def info_text(self, text: str) -> str:
        """
        Make information text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        return self._color_text('blue', text)

    def error_text(self, text: str) -> str:
        """
        Make error text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;31mtest\033[0m')
        """
        return self._color_text('red', text)

    def warning_text(self, text: str) -> str:
        """
        Make warning text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;32mtest\033[0m')
        """
        return self._color_text('orange', text)

    def success_text(self, text: str) -> str:
        """
        Make success text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;33mtest\033[0m')
        """
        return self._color_text('green', text)

    # endregion

    # region Check platform and user functions
    @staticmethod
    def get_platform() -> str:
        return str(system()) + ' ' + str(release())

    @staticmethod
    def check_platform(exit_on_failure: bool = True,
                       exit_code: int = 1,
                       quiet: bool = False) -> bool:
        """
        Check Python version and OS
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 1)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if OS is Linux or False if not
        """
        if system() != 'Linux':
            if not quiet:
                print('This script can run only in Linux platform!')
                print('Your platform: ' + str(system()) + ' ' + str(release()) + ' not supported!')
            if exit_on_failure:
                exit(exit_code)
            return False
        return True

    @staticmethod
    def check_user(exit_on_failure: bool = True,
                   exit_code: int = 2,
                   quiet: bool = False) -> bool:
        """
        Check user privileges
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 2)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if user is root or False if not
        """
        try:
            if getuid() != 0:
                if not quiet:
                    print('Only root can run this script!')
                    print('User: ' + str(getpwuid(getuid())[0]) + ' can not run this script!')
                if exit_on_failure:
                    exit(exit_code)
                return False
        except NameError:
            if windll.shell32.IsUserAnAdmin() == 0:
                if not quiet:
                    print('Only Administartor can run this script!')
                if exit_on_failure:
                    exit(exit_code)
                return False
        return True
    # endregion

    # region Pack functions
    @staticmethod
    def pack8(data: Union[int, str, bytes],
              exit_on_failure: bool = True,
              exit_code: int = 3,
              quiet: bool = False) -> Union[None, bytes]:
        """
        Pack 8 bit data
        :param data: Input data
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 3)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Packed 8 bit data
        """
        try:
            return pack('B', data)
        except error:
            if not quiet:
                print('Bad value for 8 bit pack: ' + str(data))
            if exit_on_failure:
                exit(exit_code)
            return None

    @staticmethod
    def pack16(data: Union[int, str, bytes],
               exit_on_failure: bool = True,
               exit_code: int = 4,
               quiet: bool = False) -> Union[None, bytes]:
        """
        Pack 16 bit data
        :param data: Input data
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 4)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Packed 16 bit data
        """
        try:
            return pack('!H', data)
        except error:
            if not quiet:
                print('Bad value for 16 bit pack: ' + str(data))
            if exit_on_failure:
                exit(exit_code)
            return None

    @staticmethod
    def pack32(data: Union[int, str, bytes],
               exit_on_failure: bool = True,
               exit_code: int = 5,
               quiet: bool = False) -> Union[None, bytes]:
        """
        Pack 32 bit data
        :param data: Input data
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 5)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Packed 32 bit data
        """
        try:
            return pack('!I', data)
        except error:
            if not quiet:
                print('Bad value for 32 bit pack: ' + str(data))
            if exit_on_failure:
                exit(exit_code)
            return None

    @staticmethod
    def pack64(data: Union[int, str, bytes],
               exit_on_failure: bool = True,
               exit_code: int = 6,
               quiet: bool = False) -> Union[None, bytes]:
        """
        Pack 64 bit data
        :param data: Input data
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 6)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Packed 64 bit data
        """
        try:
            return pack('!Q', data)
        except error:
            if not quiet:
                print('Bad value for 64 bit pack: ' + str(data))
            if exit_on_failure:
                exit(exit_code)
            return None
    # endregion

    # region Network interface functions
    @staticmethod
    def list_of_network_interfaces() -> Union[None, List[str]]:
        """
        Get list of network interfaces
        :return: list of network interfaces (example: ['lo', 'eth0'])
        """
        return interfaces()

    def list_of_wireless_network_interfaces(self) -> List[str]:
        """
        Get list of wireless network interfaces
        :return: list of wireless network interfaces (example: ['wlan0', 'wlan1'])
        """
        try:
            wireless_network_interfaces: List[str] = list()
            current_platform: str = self.get_platform()

            # Mac OS
            if current_platform.startswith('Darwin'):
                interfaces_info: sub.CompletedProcess = \
                    sub.run(['networksetup -listnetworkserviceorder'], shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
                interfaces_info: str = interfaces_info.stdout.decode('utf-8')
                interfaces_info: List[str] = interfaces_info.splitlines()
                for output_line in interfaces_info:
                    if 'Wi-Fi' in output_line and 'Device: ' in output_line:
                        search_result = search(r'Device: (?P<interface_name>[a-zA-Z0-9]{2,16})\)', output_line)
                        if search_result is not None:
                            wireless_network_interfaces.append(search_result.group('interface_name'))

            # Linux
            elif current_platform.startswith('Linux'):
                interfaces_info: sub.CompletedProcess = \
                    sub.run(['iwconfig'], shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
                interfaces_info: str = interfaces_info.stdout.decode('utf-8')
                interfaces_info: List[str] = interfaces_info.splitlines()
                for output_line in interfaces_info:
                    if 'IEEE 802.11' in output_line:
                        search_result = search(r'^(?P<interface_name>[a-zA-Z0-9]{2,32}) +IEEE', output_line)
                        if search_result is not None:
                            wireless_network_interfaces.append(search_result.group('interface_name'))

            # Windows
            elif current_platform.startswith('Windows'):
                netsh_command: sub.Popen = \
                    sub.Popen('netsh wlan show interfaces', shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                netsh_command_output, netsh_command_error = netsh_command.communicate()
                interfaces_info: str = netsh_command_output.decode('utf-8') + \
                                       netsh_command_error.decode('utf-8')
                interfaces_info: List[str] = interfaces_info.splitlines()
                for output_line in interfaces_info:
                    if 'Name' in output_line:
                        search_result = search(r'^ +Name +: (?P<interface_name>.*)$', output_line)
                        if search_result is not None:
                            wireless_network_interfaces.append(search_result.group('interface_name'))

            # Other
            else:
                pass

            return wireless_network_interfaces

        except AssertionError:
            return list()

    def network_interface_selection(self,
                                    interface_name: Union[None, str] = None,
                                    exclude_interface: Union[None, str] = None,
                                    only_wireless: bool = False) -> str:
        """
        Select network interface
        :param interface_name: Network interface name (example: 'eth0'; default: None)
        :param exclude_interface: Exclude network interface from list of interfaces (example: 'eth1'; default: None)
        :param only_wireless: Select network interface only from wireless interfaces (default: False)
        :return: Network interface name (example: 'eth0')
        """
        network_interface_index: int = 1
        if not only_wireless:
            available_network_interfaces: List[str] = interfaces()
        else:
            available_network_interfaces: List[str] = self.list_of_wireless_network_interfaces()
        if exclude_interface is not None:
            available_network_interfaces.remove(exclude_interface)

        if interface_name is not None:
            if interface_name in available_network_interfaces:
                return interface_name
            else:
                if not only_wireless:
                    self.print_error('Network interface: ', interface_name, ' does not exist!')
                else:
                    self.print_error('Wireless network interface: ', interface_name, ' does not exist!')
                exit(1)
        else:
            if 'lo' in available_network_interfaces:
                available_network_interfaces.remove('lo')

            if len(available_network_interfaces) > 1:
                if not only_wireless:
                    self.print_info('Your interface list:')
                else:
                    self.print_info('Your wireless interface list:')

                interfaces_pretty_table = PrettyTable([self.info_text('Index'),
                                                       self.info_text('Interface name'),
                                                       self.info_text('MAC address'),
                                                       self.info_text('IPv4 address'),
                                                       self.info_text('IPv6 address')])

                for network_interface in available_network_interfaces:
                    network_interface_mac_address: Union[None, str] = \
                        self.get_interface_mac_address(network_interface)
                    if network_interface_mac_address is None:
                        network_interface_mac_address = 'None'

                    network_interface_ipv4_address: Union[None, str] = \
                        self.get_interface_ip_address(network_interface)
                    if network_interface_ipv4_address is None:
                        network_interface_ipv4_address = 'None'

                    network_interface_ipv6_address: Union[None, str] = \
                        self.get_interface_ipv6_link_address(network_interface)
                    if network_interface_ipv6_address is None:
                        network_interface_ipv6_address = 'None'

                    interfaces_pretty_table.add_row([str(network_interface_index),
                                                     network_interface,
                                                     network_interface_mac_address,
                                                     network_interface_ipv4_address,
                                                     network_interface_ipv6_address])
                    network_interface_index += 1

                print(interfaces_pretty_table)

                network_interface_index -= 1
                current_network_interface_index = input(self.c_warning + 'Set network interface from range (1-' +
                                                        str(network_interface_index) + '): ')

                if not current_network_interface_index.isdigit():
                    self.print_error('Your input data: ', current_network_interface_index, ' is not digit!')
                    exit(1)
                else:
                    current_network_interface_index = int(current_network_interface_index)

                if any([int(current_network_interface_index) < 1,
                        int(current_network_interface_index) > network_interface_index]):
                    self.print_error('Your number: ', current_network_interface_index,
                                     ' is not within range (', '1-' + str(network_interface_index), ')')
                    exit(1)

                current_network_interface = ''
                try:
                    current_network_interface = str(available_network_interfaces[current_network_interface_index - 1])
                except:
                    self.print_error('This network interface has some problem!')
                    exit(1)
                if not only_wireless:
                    self.print_info('Your choose network interface: ', current_network_interface)
                else:
                    self.print_info('Your choose wireless network interface: ', current_network_interface)
                return current_network_interface

            if len(available_network_interfaces) == 1:
                if not only_wireless:
                    self.print_info('You have only one network interface: ', available_network_interfaces[0])
                else:
                    self.print_info('You have only one wireless network interface: ', available_network_interfaces[0])
                return available_network_interfaces[0]

            if len(available_network_interfaces) == 0:
                if not only_wireless:
                    self.print_error('Network interfaces not found!')
                else:
                    self.print_error('Wireless network interfaces not found!')
                exit(1)

    def check_network_interface_is_wireless(self, interface_name: str = 'wlan0') -> bool:
        """
        Check network interface is wireless
        :param interface_name: Network interface name (example: 'wlan0')
        :return: True or False
        """
        try:
            current_platform: str = self.get_platform()

            # Mac OS
            if current_platform.startswith('Darwin'):
                interface_info: sub.CompletedProcess = \
                    sub.run(['networksetup -listnetworkserviceorder | grep ' + interface_name],
                            shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
                interface_info: str = interface_info.stdout.decode('utf-8')
                assert 'Wi-Fi' in interface_info, 'Is not wireless interface!'
                return True

            # Linux
            elif current_platform.startswith('Linux'):
                interface_info: sub.CompletedProcess = \
                    sub.run(['iwconfig ' + interface_name],
                            shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
                interface_info: str = interface_info.stdout.decode('utf-8')
                assert 'no wireless extensions' not in interface_info, 'Is not wireless interface!'
                return True

            # Windows
            elif current_platform.startswith('Windows'):
                netsh_command: sub.Popen = \
                    sub.Popen('netsh wlan show interfaces', shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                netsh_command_output, netsh_command_error = netsh_command.communicate()
                interfaces_info: str = netsh_command_output.decode('utf-8') + \
                                       netsh_command_error.decode('utf-8')
                assert 'no wireless extensions' not in interfaces_info, 'Is not wireless interface!'
                return True

            # Other
            else:
                return False

        except AssertionError:
            return False

    # @staticmethod
    # def get_netiface_essid(interface_name):
    #     try:
    #         wifi = Wireless(interface_name)
    #         essid = wifi.getEssid()
    #     except:
    #         essid = None
    #     return essid
    #
    # @staticmethod
    # def get_netiface_frequency(interface_name):
    #     try:
    #         wifi = Wireless(interface_name)
    #         frequency = wifi.getFrequency()
    #     except:
    #         frequency = 0
    #     return frequency

    def get_interface_settings(self,
                               interface_name: str = 'eth0',
                               exit_on_failure: bool = False,
                               quiet: bool = False) -> Dict[str, Union[None, str, List[str]]]:
        """
        Get network interface settings
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Network interface settings (example: {})
        """
        return {
            'Interface name': interface_name,
            'MAC address': self.get_interface_mac_address(interface_name=interface_name,
                                                          exit_on_failure=exit_on_failure,
                                                          quiet=quiet),
            'IPv4 address': self.get_interface_ip_address(interface_name=interface_name,
                                                          exit_on_failure=exit_on_failure,
                                                          quiet=quiet),
            'IPv6 link local address': self.get_interface_ipv6_link_address(interface_name=interface_name,
                                                                            exit_on_failure=exit_on_failure,
                                                                            quiet=quiet),
            'IPv6 global address': self.get_interface_ipv6_glob_address(interface_name=interface_name),
            'IPv6 global addresses': self.get_interface_ipv6_glob_addresses(interface_name=interface_name),
            'IPv4 netmask': self.get_interface_netmask(interface_name=interface_name,
                                                       exit_on_failure=exit_on_failure,
                                                       quiet=quiet),
            'IPv4 network': self.get_interface_network(interface_name=interface_name,
                                                       exit_on_failure=exit_on_failure,
                                                       quiet=quiet),
            'First IPv4 address': self.get_first_ip_on_interface(interface_name=interface_name,
                                                                 exit_on_failure=exit_on_failure,
                                                                 quiet=quiet),
            'Second IPv4 address': self.get_second_ip_on_interface(interface_name=interface_name,
                                                                   exit_on_failure=exit_on_failure,
                                                                   quiet=quiet),
            'Penultimate IPv4 address': self.get_penultimate_ip_on_interface(interface_name=interface_name,
                                                                             exit_on_failure=exit_on_failure,
                                                                             quiet=quiet),
            'Last IPv4 address': self.get_last_ip_on_interface(interface_name=interface_name,
                                                               exit_on_failure=exit_on_failure,
                                                               quiet=quiet),
            'IPv4 broadcast': self.get_interface_broadcast(interface_name=interface_name,
                                                           exit_on_failure=exit_on_failure,
                                                           quiet=quiet),
            'IPv4 gateway': self.get_interface_ipv4_gateway(interface_name=interface_name,
                                                            exit_on_failure=exit_on_failure,
                                                            quiet=quiet),
            'IPv6 gateway': self.get_interface_ipv6_gateway(interface_name=interface_name,
                                                            exit_on_failure=exit_on_failure,
                                                            quiet=quiet)
        }

    def get_interface_mac_address(self,
                                  interface_name: str = 'eth0',
                                  exit_on_failure: bool = True,
                                  exit_code: int = 7,
                                  quiet: bool = False) -> Union[None, str]:
        """
        Get MAC address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :param exit_code: Set exit code integer (default: 7)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: MAC address string (example: '01:23:45:67:89:0a') or None in case of error
        """
        try:
            return str(ifaddresses(interface_name)[AF_LINK][0]['addr'])

        except NameError:
            return get_mac_address(interface=interface_name)

        except ValueError:
            pass

        except KeyError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have MAC address!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_interface_ip_address(self,
                                 interface_name: str = 'eth0',
                                 exit_on_failure: bool = True,
                                 exit_code: int = 8,
                                 quiet: bool = False) -> Union[None, str]:
        """
        Get IPv4 address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 8)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        try:
            return str(ifaddresses(interface_name)[AF_INET][0]['addr'])

        except NameError:
            host_name = gethostname()
            return gethostbyname(host_name)

        except ValueError:
            pass

        except KeyError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have IP address!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_interface_ipv6_address(self,
                                   interface_name: str = 'eth0',
                                   address_index: int = 0,
                                   exit_on_failure: bool = False,
                                   exit_code: int = 9,
                                   quiet: bool = False) -> Union[None, str]:
        """
        Get IPv6 address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param address_index: Index of IPv6 address (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 9)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv6 address string (example: 'fd00::1') or None in case of error
        """
        try:
            ipv6_address = str(ifaddresses(interface_name)[AF_INET6][address_index]['addr'])
            ipv6_address = ipv6_address.replace('%' + interface_name, '', 1)

        except NameError:
            ipv6_address = '::1'

        except IndexError:
            ipv6_address = None

        except ValueError:
            ipv6_address = None

        except KeyError:
            ipv6_address = None

        if ipv6_address is None:
            if not quiet:
                self.print_error('Network interface: ', interface_name,
                                 ' does not have IPv6 address with index: ', str(address_index))
            if exit_on_failure:
                exit(exit_code)
        return ipv6_address

    def get_interface_ipv6_link_address(self,
                                        interface_name: str = 'eth0',
                                        exit_on_failure: bool = True,
                                        exit_code: int = 10,
                                        quiet: bool = False) -> Union[None, str]:
        """
        Get IPv6 link local address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 10)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv6 link local address string (example: 'fe80::1') or None in case of error
        """
        if interface_name == 'lo':
            return '::1'
        for address_index in range(0, 10, 1):
            ipv6_address = self.get_interface_ipv6_address(interface_name=interface_name,
                                                           address_index=address_index,
                                                           exit_on_failure=exit_on_failure,
                                                           exit_code=exit_code,
                                                           quiet=quiet)
            try:
                # IPv6 link local address starts with: 'fe80::'
                if ipv6_address.startswith('fe80::'):
                    return ipv6_address
            except AttributeError:
                if not quiet:
                    self.print_error('Network interface: ', interface_name, ' does not have IPv6 link local address!')
                if exit_on_failure:
                    exit(exit_code)
                return None
        return None

    def get_interface_ipv6_glob_address(self,
                                        interface_name: str = 'eth0') -> Union[None, str]:
        """
        Get IPv6 global address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :return: IPv6 global address string (example: 'fd00::1') or None in case of error
        """
        address_index: int = 0
        ipv6_address: Union[None, str] = self.get_interface_ipv6_address(interface_name=interface_name,
                                                                         address_index=address_index,
                                                                         exit_on_failure=False,
                                                                         quiet=True)
        while ipv6_address is not None:
            # IPv6 link local address starts with: 'fe80::'
            if not ipv6_address.startswith('fe80::'):
                return ipv6_address
            address_index += 1
            ipv6_address: Union[None, str] = self.get_interface_ipv6_address(interface_name=interface_name,
                                                                             address_index=address_index,
                                                                             exit_on_failure=False,
                                                                             quiet=True)

        return None

    def get_interface_ipv6_glob_addresses(self,
                                          interface_name: str = 'eth0') -> List[str]:
        """
        Get IPv6 global addresses list of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :return: IPv6 global addresses list (example: ['fd00::1', 'fd00::2'])
        """
        ipv6_addresses: List[str] = list()
        address_index: int = 0
        ipv6_address: Union[None, str] = self.get_interface_ipv6_address(interface_name=interface_name,
                                                                         address_index=address_index,
                                                                         exit_on_failure=False,
                                                                         quiet=True)
        while ipv6_address is not None:
            # IPv6 link local address starts with: 'fe80::'
            if not ipv6_address.startswith('fe80::'):
                ipv6_addresses.append(ipv6_address)
            address_index += 1
            ipv6_address: Union[None, str] = self.get_interface_ipv6_address(interface_name=interface_name,
                                                                             address_index=address_index,
                                                                             exit_on_failure=False,
                                                                             quiet=True)

        return ipv6_addresses

    def make_ipv6_link_address(self,
                               mac_address: str = '01:23:45:67:89:0a',
                               exit_on_failure: bool = True,
                               exit_code: int = 12,
                               quiet: bool = False) -> Union[None, str]:
        """
        Make IPv6 link local address by MAC address
        :param mac_address: MAC address (default: '01:23:45:67:89:0a')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 12)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv6 link local address string (example: 'fe80::1') or None in case of error
        """
        try:
            assert self.mac_address_validation(mac_address=mac_address,
                                               exit_on_failure=exit_on_failure,
                                               exit_code=exit_code,
                                               quiet=quiet), \
                'Failed to make IPv6 link local address from MAC address: ' + self.error_text(str(mac_address))
            parts: List[str] = mac_address.split(':')
            parts.insert(3, 'ff')
            parts.insert(4, 'fe')
            parts[0] = '%x' % (int(parts[0], 16) ^ 2)
            ipv6_parts: List[str] = list()
            for index in range(0, len(parts), 2):
                ipv6_parts.append(''.join(parts[index:index + 2]))
            return 'fe80::%s' % (':'.join(ipv6_parts))

        except AssertionError as Error:
            error_text = Error.args[0]

        if not quiet:
            self.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def get_interface_netmask(self,
                              interface_name: str = 'eth0',
                              exit_on_failure: bool = True,
                              exit_code: int = 13,
                              quiet: bool = False) -> Union[None, str]:
        """
        Get network interface mask
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 13)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Network interface mask string (example: '255.255.255.0') or None in case of error
        """
        try:
            return str(ifaddresses(interface_name)[AF_INET][0]['netmask'])

        except ValueError:
            pass

        except KeyError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have network mask!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_interface_network(self,
                              interface_name: str = 'eth0',
                              exit_on_failure: bool = True,
                              exit_code: int = 14,
                              quiet: bool = False) -> Union[None, str]:
        """
        Get IPv4 network on interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 14)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 network string (example: '192.168.1.0/24') or None in case of error
        """
        try:
            netmask = self.get_interface_netmask(interface_name=interface_name,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)
            ip_address = self.get_interface_ip_address(interface_name=interface_name,
                                                       exit_on_failure=exit_on_failure,
                                                       exit_code=exit_code,
                                                       quiet=quiet)
            ip = IPNetwork(ip_address + '/' + netmask)
            return str(ip[0]) + '/' + str(IPAddress(netmask).netmask_bits())

        except KeyError:
            pass

        except ValueError:
            pass

        except TypeError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_ip_on_interface_by_index(self,
                                     interface_name: str = 'eth0',
                                     index: int = 1,
                                     exit_on_failure: bool = True,
                                     exit_code: int = 15,
                                     quiet: bool = False) -> Union[None, str]:
        """
        Get IPv4 address on network interface by index of address
        :param interface_name: Network interface name (default: 'eth0')
        :param index: Index of IPv4 address integer (default: 1)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 15)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        try:
            network: IPNetwork = IPNetwork(self.get_interface_network(interface_name=interface_name,
                                                                      exit_on_failure=exit_on_failure,
                                                                      exit_code=exit_code,
                                                                      quiet=quiet))
            return str(network[index])

        except KeyError:
            pass

        except ValueError:
            pass

        except TypeError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_first_ip_on_interface(self,
                                  interface_name: str = 'eth0',
                                  exit_on_failure: bool = True,
                                  exit_code: int = 16,
                                  quiet: bool = False) -> Union[None, str]:
        """
        Get first IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 16)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=1,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)

    def get_second_ip_on_interface(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True,
                                   exit_code: int = 17,
                                   quiet: bool = False) -> Union[None, str]:
        """
        Get second IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 17)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.2') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=2,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)

    def get_penultimate_ip_on_interface(self,
                                        interface_name: str = 'eth0',
                                        exit_on_failure: bool = True,
                                        exit_code: int = 18,
                                        quiet: bool = False) -> Union[None, str]:
        """
        Get penultimate IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 18)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.253') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=-3,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)

    def get_last_ip_on_interface(self,
                                 interface_name: str = 'eth0',
                                 exit_on_failure: bool = True,
                                 exit_code: int = 19,
                                 quiet: bool = False) -> Union[None, str]:
        """
        Get last IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 19)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.254') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=-2,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)

    def get_random_ip_on_interface(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True,
                                   exit_code: int = 20,
                                   quiet: bool = False) -> Union[None, str]:
        """
        Get random IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 20)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.123') or None in case of error
        """
        try:
            network = IPNetwork(self.get_interface_network(interface_name=interface_name,
                                                           exit_on_failure=exit_on_failure,
                                                           exit_code=exit_code,
                                                           quiet=quiet))
            return str(network[randint(2, len(network) - 3)])

        except KeyError:
            pass

        except ValueError:
            pass

        except TypeError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_interface_broadcast(self,
                                interface_name: str = 'eth0',
                                exit_on_failure: bool = True,
                                exit_code: int = 21,
                                quiet: bool = False) -> Union[None, str]:
        """
        Get IPv4 broadcast address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 21)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.255') or None in case of error
        """
        try:
            return str(ifaddresses(interface_name)[AF_INET][0]['broadcast'])

        except KeyError:
            pass

        except ValueError:
            pass

        if not quiet:
            self.print_error('Network interface: ', interface_name, ' does not have broadcast address!')
        if exit_on_failure:
            exit(exit_code)
        return None

    def get_interface_gateway(self,
                              interface_name: str = 'eth0',
                              network_type: int = AF_INET,
                              exit_on_failure: bool = True,
                              exit_code: int = 22,
                              quiet: bool = False) -> Union[None, str]:
        """
        Get gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param network_type: Set network type AF_INET for IPv4 network or AF_INET6 for IPv6 (default: AF_INET)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 22)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Address string (example: '192.168.1.254') or None in case of error
        """
        try:
            gateway_address = None
            gws = gateways()
            for gw in gws:
                gateway_interface = gws[gw][network_type]
                gateway_ip, interface = gateway_interface[0], gateway_interface[1]
                if interface == interface_name:
                    gateway_address = gateway_ip
                    break

        except KeyError:
            gateway_address = None

        except ValueError:
            gateway_address = None

        except IndexError:
            gateway_address = None

        if gateway_address is None:
            if not quiet:
                if network_type == AF_INET:
                    if exit_on_failure:
                        self.print_error('Network interface: ', interface_name, ' does not have IPv4 gateway!')
                    else:
                        self.print_warning('Network interface: ', interface_name, ' does not have IPv4 gateway!')
                if network_type == AF_INET6:
                    if exit_on_failure:
                        self.print_error('Network interface: ', interface_name, ' does not have IPv6 gateway!')
                    else:
                        self.print_warning('Network interface: ', interface_name, ' does not have IPv6 gateway!')
            if exit_on_failure:
                exit(exit_code)
        return gateway_address

    def get_interface_ipv4_gateway(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True,
                                   exit_code: int = 23,
                                   quiet: bool = False) -> Union[None, str]:
        """
        Get IPv4 gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 23)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.254') or None in case of error
        """
        return self.get_interface_gateway(interface_name=interface_name,
                                          network_type=AF_INET,
                                          exit_on_failure=exit_on_failure,
                                          exit_code=exit_code,
                                          quiet=quiet)

    def get_interface_ipv6_gateway(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True,
                                   exit_code: int = 24,
                                   quiet: bool = False) -> Union[None, str]:
        """
        Get IPv6 gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 24)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv6 address string (example: 'fd00::1') or None in case of error
        """
        return self.get_interface_gateway(interface_name=interface_name,
                                          network_type=AF_INET6,
                                          exit_on_failure=exit_on_failure,
                                          exit_code=exit_code,
                                          quiet=quiet)

    # endregion

    # region Check installed software
    def apt_list_installed_packages(self,
                                    exit_on_failure: bool = True,
                                    exit_code: int = 25,
                                    quiet: bool = False) -> Union[None, bytes]:
        """
        Get output of bash command: apt list --installed
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 25)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: result bytes
        """
        try:
            apt_list_command = sub.Popen(['apt list --installed'], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            apt_list_out, apt_list_err = apt_list_command.communicate()
            assert apt_list_out is not None, \
                'Something else went wrong while trying to run command: ' + \
                self.error_text('`apt list --installed`')
            self.os_installed_packages_list = apt_list_out
            return apt_list_out

        except OSError:
            error_text = 'Something else went wrong while trying to run command: ' + \
                         self.error_text('`apt list --installed`')

        except AssertionError as Error:
            error_text = Error.args[0]

        if not quiet:
            self.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def check_installed_software(self,
                                 software_name: str = 'apache2',
                                 exit_on_failure: bool = True,
                                 exit_code: int = 26,
                                 quiet: bool = False) -> bool:
        """
        Check software is installed or not
        :param software_name: Name of software (default: 'apache2')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 26)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True or False
        """
        try:
            assert self.check_platform(exit_on_failure=exit_on_failure,
                                       exit_code=exit_code,
                                       quiet=quiet), \
                'This is not a Linux platform'

            assert not ('Kali' in linux_distribution()
                        or 'Debian' in linux_distribution()
                        or 'Ubuntu' in linux_distribution()), \
                'Unable to verify OS installed software. ' + \
                'This function works normal only in Debian, Ubuntu or Kali linux.'

            if self.os_installed_packages_list is None:
                self.apt_list_installed_packages(exit_on_failure)

            assert self.os_installed_packages_list is not None, 'Unable to verify OS installed software.'

            if software_name.encode(encoding='utf-8') in self.os_installed_packages_list:
                return True
            else:
                if isfile('/bin/' + software_name) or isfile('/sbin/' + software_name) or \
                        isfile('/usr/bin/' + software_name) or isfile('/usr/sbin/' + software_name) or \
                        isfile('/usr/local/bin/' + software_name) or isfile('/usr/local/sbin/' + software_name):
                    return True
                else:
                    return False

        except AssertionError as Error:
            error_text = Error.args[0]

            if 'Debian, Ubuntu or Kali linux' in error_text:
                if not quiet:
                    self.print_warning(error_text)

                if isfile('/bin/' + software_name) or isfile('/sbin/' + software_name) or \
                        isfile('/usr/bin/' + software_name) or isfile('/usr/sbin/' + software_name) or \
                        isfile('/usr/local/bin/' + software_name) or isfile('/usr/local/sbin/' + software_name):
                    return True
                else:
                    return False

            else:
                if not quiet:
                    self.print_error(error_text)
                if exit_on_failure:
                    exit(exit_code)
                return False

    # endregion

    # region Process control functions
    @staticmethod
    def check_process(process_name: str = 'systemd') -> int:
        """
        Check process is running
        :param process_name: Process name string (default: 'systemd')
        :return: Process ID integer (example: 1)
        """
        for process in ps.process_iter():
            if 'python' in process.name():
                for argument in process.cmdline():
                    if process_name in argument:
                        return int(process.pid)
            if process.name() == process_name:
                return int(process.pid)
        return -1

    def get_process_pid(self, process_name: str = 'systemd') -> int:
        """
        Get process ID
        :param process_name: Process name string (default: 'apache2')
        :return: Process ID integer (example: 1234)
        """
        return self.check_process(process_name)

    def get_process_pid_by_listen_port(self,
                                       listen_port: int = 80,
                                       listen_address: Union[None, str] = None,
                                       listen_proto: Union[None, str] = None,
                                       exit_on_failure: bool = True,
                                       exit_code: int = 27,
                                       quiet: bool = False) -> Union[None, List[int]]:
        """
        Get list of processes ID by listen TCP or UDP port
        :param listen_port: Listening TCP or UDP port integer (default: 80)
        :param listen_address: Listening IPv4 or IPv6 address string (default: None)
        :param listen_proto: Listening protocol string 'tcp' or 'udp' (default: 'tcp')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 27)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: List of processes ID by listen TCP or UDP port
        """
        pids: List[int] = list()
        try:
            assert 1 < listen_port < 65535, \
                'Bad listen port: ' + self.error_text(str(listen_port)) + \
                ' listen port must be in range: ' + self.info_text('1 - 65535')
            assert (listen_proto is None or listen_proto == 'tcp' or listen_proto == 'udp'), \
                'Bad value in listen proto: ' + self.error_text(str(listen_proto)) + \
                ' listen proto must be ' + self.info_text('None' + ' or ' + '\'tcp\'' + ' or ' + '\'udp\'')
            if listen_proto is None:
                listen_proto = 'tcp'
            for process in ps.process_iter():
                connections = process.connections()
                for connection in connections:
                    (address, port) = connection.laddr

                    if connection.type == sock.SOCK_STREAM and connection.status == ps.CONN_LISTEN:
                        proto = 'tcp'
                    elif connection.type == sock.SOCK_DGRAM:
                        proto = 'udp'
                    else:
                        continue

                    if listen_address is not None:
                        if address == listen_address and proto == listen_proto \
                                and port == listen_port and process.pid is not None:
                            pids.append(process.pid)
                    else:
                        if proto == listen_proto and port == listen_port and process.pid is not None:
                            pids.append(process.pid)
            return pids

        except ps.NoSuchProcess:
            return pids

        except AssertionError as Error:
            if not quiet:
                self.print_error(Error.args[0])
            if exit_on_failure:
                exit(exit_code)
            return None

    @staticmethod
    def kill_process(process_pid: int) -> bool:
        """
        Kill process by ID
        :param process_pid: Process ID integer
        :return: True if kill process or False if not
        """
        try:
            process = ps.Process(process_pid)
            process.terminate()
            return True
        except ps.NoSuchProcess:
            return False

    def kill_process_by_name(self, process_name: str = 'apache2') -> bool:
        """
        Kill process by name
        :param process_name: Process name string (default: apache2)
        :return: True if kill process or False if not
        """
        process_pid = self.get_process_pid(process_name)
        if process_pid != -1:
            while (self.get_process_pid(process_name) != -1):
                self.kill_process(process_pid)
            return True
        else:
            return False

    def kill_processes_by_listen_port(self,
                                      listen_port: int = 80,
                                      listen_address: Union[None, str] = None,
                                      listen_proto: str = 'tcp') -> bool:
        """
        Kill processes by listen TCP or UDP port
        :param listen_port: Listening TCP or UDP port integer (default: 80)
        :param listen_address: Listening IPv4 or IPv6 address string (default: None)
        :param listen_proto: Listening protocol string 'tcp' or 'udp' (default: 'tcp')
        :return: True if kill all processes or False if not
        """
        # Get pids all process and kill
        pid_list: List[int] = self.get_process_pid_by_listen_port(listen_port, listen_address, listen_proto)
        if len(pid_list) > 0:
            for pid in pid_list:
                if not self.kill_process(pid):
                    return False
            return True
        else:
            return False

    # endregion

    # region Others functions
    def ipv6_address_validation(self,
                                ipv6_address: str = 'fd00::1',
                                exit_on_failure: bool = False,
                                exit_code: int = 28,
                                quiet: bool = True) -> bool:
        """
        Validate IPv6 address string
        :param ipv6_address: IPv6 address string (example: 'fd00::1')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 28)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if a valid IPv6 address or False if not
        """
        try:
            sock.inet_pton(sock.AF_INET6, ipv6_address)
            return True
        except sock.error:
            if not quiet:
                self.print_error('Failed to validate IPv6 address: ', str(ipv6_address))
            if exit_on_failure:
                exit(exit_code)
            return False

    def ip_address_validation(self,
                              ip_address: str = '192.168.1.1',
                              exit_on_failure: bool = False,
                              exit_code: int = 29,
                              quiet: bool = True) -> bool:
        """
        Validate IPv4 address string
        :param ip_address: IPv4 address string (example: '192.168.1.1')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 29)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if a valid IPv4 address or False if not
        """
        try:
            sock.inet_aton(ip_address)
            return True
        except sock.error:
            if not quiet:
                self.print_error('Failed to validate IP address: ', str(ip_address))
            if exit_on_failure:
                exit(exit_code)
            return False

    def mac_address_validation(self,
                               mac_address: str = '01:23:45:67:89:0a',
                               exit_on_failure: bool = False,
                               exit_code: int = 30,
                               quiet: bool = False) -> bool:
        """
        Validate MAC address string
        :param mac_address: MAC address string (example: '01:23:45:67:89:0a')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 10)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if a valid MAC address or False if not
        """
        if match(r'^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$', mac_address):
            return True
        else:
            if not quiet:
                self.print_error('Failed to validate MAC address: ', str(mac_address))
            if exit_on_failure:
                exit(exit_code)
            return False

    def mac_address_normalization(self,
                                  mac_address: str = 'AB:CD:EF:AB:CD:EF',
                                  exit_on_failure: bool = False,
                                  exit_code: int = 30,
                                  quiet: bool = False) -> Union[None, str]:
        """
        Validate MAC address string
        :param mac_address: MAC address string (example: 'AB:CD:EF:AB:CD:EF')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 10)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: MAC address (example: 'ab:cd:ef:ab:cd:ef') or None if not
        """
        try:
            assert self.mac_address_validation(mac_address=mac_address), 'Bad MAC address'
            return mac_address.lower()
        except AssertionError:
            if not quiet:
                self.print_error('Failed to normalize MAC address: ', str(mac_address))
            if exit_on_failure:
                exit(exit_code)
            return None

    def ip_address_in_range(self,
                            ip_address: str = '192.168.1.2',
                            first_ip_address: str = '192.168.1.1',
                            last_ip_address: str = '192.168.1.3',
                            exit_on_failure: bool = False,
                            exit_code: int = 31,
                            quiet: bool = False) -> bool:
        """
        Check IPv4 address in range
        :param ip_address: IPv4 address string (example: '192.168.1.2')
        :param first_ip_address: First IPv4 address in range (example: '192.168.1.1')
        :param last_ip_address: Last IPv4 address in range (example: '192.168.1.3')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 31)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if IPv4 address in range or False if not
        """
        try:
            assert (IPv4Address(first_ip_address) <= IPv4Address(ip_address) <= IPv4Address(last_ip_address)), \
                'IP address: ' + self.error_text(str(ip_address)) + \
                ' not in range: ' + self.error_text(str(first_ip_address) + ' - ' + str(last_ip_address))
            return True

        except AddressValueError:
            error_text = 'Bad IPv4 address: ' + self.error_text(str(ip_address))

        except AssertionError as Error:
            error_text = Error.args[0]

        if not quiet:
            self.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return False

    def ip_address_in_network(self,
                              ip_address: str = '192.168.1.1',
                              network: str = '192.168.1.0/24',
                              exit_on_failure: bool = False,
                              exit_code: int = 32,
                              quiet: bool = True) -> bool:
        """
        Check IPv4 address in network
        :param ip_address: IPv4 address string (example: '192.168.1.1')
        :param network: IPv4 network string (example: '192.168.1.0/24')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 32)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if IPv4 address in network or False if not
        """
        try:
            assert IPAddress(ip_address) in IPNetwork(network), \
                'IPv4 address: ' + self.error_text(str(ip_address)) + \
                ' not in IPv4 network: ' + self.error_text(str(network))
            return True

        except AddressValueError:
            error_text = 'Bad IPv4 address: ' + self.error_text(str(ip_address))

        except AddrFormatError:
            error_text = 'Bad IPv4 network: ' + self.error_text(str(network)) + \
                         ' or IPv4 address: ' + self.error_text(str(ip_address)) + \
                         ' not in IPv4 network: ' + self.error_text(str(network))

        except AssertionError as Error:
            error_text = Error.args[0]

        if not quiet:
            self.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return False

    def ip_address_increment(self,
                             ip_address: str = '192.168.1.1',
                             exit_on_failure: bool = False,
                             exit_code: int = 33,
                             quiet: bool = False) -> Union[None, str]:
        """
        Increment IPv4 address
        :param ip_address: IPv4 address string (example: '192.168.1.1')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 33)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.2')
        """
        try:
            return str(IPv4Address(ip_address) + 1)
        except AddressValueError:
            if quiet:
                self.print_error('Bad IPv4 address: ', str(ip_address))
            if exit_on_failure:
                exit(exit_code)
            return None

    def ip_address_decrement(self,
                             ip_address: str = '192.168.1.2',
                             exit_on_failure: bool = False,
                             exit_code: int = 34,
                             quiet: bool = False) -> Union[None, str]:
        """
        Decrement IPv4 address
        :param ip_address: IPv4 address string (example: '192.168.1.2')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 33)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv4 address string (example: '192.168.1.1')
        """
        try:
            return str(IPv4Address(ip_address) - 1)
        except AddressValueError:
            if quiet:
                self.print_error('Bad IPv4 address: ', str(ip_address))
            if exit_on_failure:
                exit(exit_code)
            return None

    def ip_address_compare(self,
                           first_ip_address: str = '192.168.1.1',
                           second_ip_address: str = '192.168.1.1',
                           operator: str = 'eq',
                           exit_on_failure: bool = False,
                           exit_code: int = 35,
                           quiet: bool = False) -> bool:
        """
        Compare IPv4 addresses
        :param first_ip_address: First IPv4 address for compare (example: 192.168.0.1)
        :param second_ip_address: Second IPv4 address for compare (example: 192.168.0.2)
        :param operator: eq - equal; ne - not equal; gt - greater; ge - greater or equal; lt - less; le - less or equal (default: eq)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 33)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True or False
        """
        try:
            assert (operator == 'eq' or operator == 'ne' or operator == 'gt' or operator == 'ge'
                    or operator == 'lt' or operator == 'le'), \
                'Bad operator: ' + self.error_text(str(operator)) + \
                ' acceptable operator values: ' + self.info_text('eq - equal; ne - not equal; ' +
                                                                 'gt - greater; ge - greater or equal; ' +
                                                                 'lt - less; le - less or equal')

            if operator == 'eq':
                if IPv4Address(first_ip_address) == IPv4Address(second_ip_address):
                    return True
                else:
                    return False

            elif operator == 'ne':
                if IPv4Address(first_ip_address) != IPv4Address(second_ip_address):
                    return True
                else:
                    return False

            elif operator == 'gt':
                if IPv4Address(first_ip_address) > IPv4Address(second_ip_address):
                    return True
                else:
                    return False

            elif operator == 'ge':
                if IPv4Address(first_ip_address) >= IPv4Address(second_ip_address):
                    return True
                else:
                    return False

            elif operator == 'lt':
                if IPv4Address(first_ip_address) < IPv4Address(second_ip_address):
                    return True
                else:
                    return False

            elif operator == 'le':
                if IPv4Address(first_ip_address) <= IPv4Address(second_ip_address):
                    return True
                else:
                    return False

        except AssertionError as Error:
            error_text = Error.args[0]

        except AddressValueError:
            error_text = 'Bad ip address in input parameters'

        if not quiet:
            self.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return False

    def make_random_string(self, length: int = 8) -> str:
        """
        Make random string from lowercase letter, uppercase letter and digits
        :param length: Length of string (default: 8)
        :return: Random string (example: d1dfJ3a032)
        """
        return ''.join(choice(self.lowercase_letters + self.uppercase_letters + self.digits) for _ in range(length))

    @staticmethod
    def get_system_name_servers() -> List[str]:
        name_servers_ip_addresses: List[str] = list()
        resolve_conf_filename: str = '/etc/resolv.conf'
        try:
            assert isfile(resolve_conf_filename), \
                'Not found ' + resolve_conf_filename + ' file!'
            with open(resolve_conf_filename, 'r') as resolve_conf:
                for settings_line in resolve_conf.read().splitlines():
                    settings_columns = settings_line.split()
                    if settings_columns[0] == 'nameserver':
                        name_servers_ip_addresses.append(settings_columns[1])
        except AssertionError:
            pass
        return name_servers_ip_addresses

    def get_mac_prefixes(self, prefixes_filename: str = 'mac-prefixes.txt') -> List[Dict[str, str]]:
        """
        Get MAC address prefixes from file
        :param prefixes_filename: Name of file with MAC address prefixes (content example: 00:00:01\tXerox\tXerox Corporation)
        :return: MAC prefixes list (example: [{'prefix': '00:00:01', 'vendor': 'Xerox Corporation'}])
        """
        assert len(self.vendor_list) == 0, 'Vendor list already exist!'
        try:
            if not isfile(prefixes_filename):
                prefixes_filename = join(dirname(abspath(__file__)), prefixes_filename)
                assert isfile(prefixes_filename), \
                    'File with MAC addresses list: ' + self.error_text(prefixes_filename) + ' not found!'
            with open(prefixes_filename, 'r') as mac_prefixes_descriptor:
                for mac_and_vendor_string in mac_prefixes_descriptor.read().splitlines():
                    mac_and_vendor_list = mac_and_vendor_string.split('\t')
                    try:
                        self.vendor_list.append({
                            'prefix': mac_and_vendor_list[0],
                            'vendor': mac_and_vendor_list[2]
                        })
                    except IndexError:
                        self.vendor_list.append({
                            'prefix': mac_and_vendor_list[0],
                            'vendor': mac_and_vendor_list[1]
                        })
        except AssertionError:
            pass
        return self.vendor_list

    def get_vendor_by_mac_address(self, mac_address: str = '01:23:45:67:89:0a') -> str:
        """
        Get vendor of host by MAC address
        :param mac_address: MAC address of host (example: '01:23:45:67:89:0a')
        :return: Vendor string
        """
        if len(self.vendor_list) == 0:
            self.get_mac_prefixes()
        if not self.mac_address_validation(mac_address):
            return 'Unknown vendor'
        mac_address: str = mac_address.upper()
        for vendor_dictionary in self.vendor_list:
            if len(vendor_dictionary['prefix']) == 8:
                if vendor_dictionary['prefix'] in mac_address:
                    return vendor_dictionary['vendor']
        return 'Unknown vendor'

    def macos_encode_mac_address(self, mac_address: str = '01:23:45:67:89:0a') -> str:
        """
        Convert MAC address to MacOS format
        :param mac_address: MAC address string (example: 01:23:45:67:89:0a)
        :return: Converted MAC address string (example: 1:23:45:67:89:a)
        """
        if self.mac_address_validation(mac_address):
            address_in_macos_arp_table: str = ''
            for part_of_address in mac_address.split(':'):
                if part_of_address[0] == '0':
                    address_in_macos_arp_table += part_of_address[1] + ':'
                else:
                    address_in_macos_arp_table += part_of_address + ':'
            return address_in_macos_arp_table[:-1]
        else:
            return mac_address

    def exec_command_over_ssh(self,
                              command: str = 'ifconfig',
                              ssh_user: str = 'root',
                              ssh_password: Union[None, str] = None,
                              ssh_pkey: Union[None, RSAKey] = None,
                              ssh_host: str = '192.168.0.1',
                              need_output: bool = True,
                              exit_on_failure: bool = True) -> Union[None, bool, str]:
        """
        Exec cmd command over SSH
        :param command: CMD command string (example: 'ifconfig')
        :param ssh_user: SSH user string (example: 'root')
        :param ssh_password: SSH password string or None if use ssh private key
        :param ssh_pkey: SSH private key or None if use ssh password
        :param ssh_host: SSH host string (example: '192.168.0.1')
        :param need_output: Need command output or not (default: True)
        :param exit_on_failure: Exit in case of error (default: False)
        :return: True or False if not need output, Output string or None if need output
        """
        command_result: Union[None, str] = None
        try:
            assert not (ssh_password is None and ssh_pkey is None), \
                'SSH password and private key is None'

            ssh_client: SSHClient = SSHClient()
            ssh_client.set_missing_host_key_policy(AutoAddPolicy())
            if ssh_password is not None:
                ssh_client.connect(hostname=ssh_host, username=ssh_user, password=ssh_password)
            if ssh_pkey is not None:
                ssh_client.connect(hostname=ssh_host, username=ssh_user, pkey=ssh_pkey)

            if need_output:
                stdin, stdout, stderr = ssh_client.exec_command(command)
                command_result = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                ssh_client.close()
                return command_result
            else:
                ssh_client.exec_command(command)
                ssh_client.close()
                return True

        except AssertionError as Error:
            self.print_error(Error.args[0])

        except NoValidConnectionsError:
            self.print_error('Could not connect to SSH host: ', ssh_host)

        except AuthenticationException:
            self.print_error('SSH authentication error: ', ssh_user + '@' + ssh_host)

        if exit_on_failure:
            exit(1)
        if need_output:
            return command_result
        else:
            return False

    def download_file_over_ssh(self,
                               remote_path: str = '/tmp/test.txt',
                               local_path: str = 'test.txt',
                               ssh_user: str = 'root',
                               ssh_password: Union[None, str] = None,
                               ssh_pkey: Union[None, RSAKey] = None,
                               ssh_host: str = '192.168.0.1',
                               exit_on_failure: bool = True) -> Union[bool]:
        """
        Transfer file over SSH
        :param remote_path: Remote file path string
        :param local_path: Local file path string
        :param ssh_user: SSH user string (example: 'root')
        :param ssh_password: SSH password string or None if use ssh private key
        :param ssh_pkey: SSH private key or None if use ssh password
        :param ssh_host: SSH host string (example: '192.168.0.1')
        :param exit_on_failure: Exit in case of error (default: False)
        :return: True or False if not need output, Output string or None if need output
        """
        try:
            assert not (ssh_password is None and ssh_pkey is None), \
                'SSH password and private key is None'

            ssh_client: SSHClient = SSHClient()
            ssh_client.set_missing_host_key_policy(AutoAddPolicy())
            if ssh_password is not None:
                ssh_client.connect(hostname=ssh_host, username=ssh_user, password=ssh_password)
            if ssh_pkey is not None:
                ssh_client.connect(hostname=ssh_host, username=ssh_user, pkey=ssh_pkey)

            sftp = ssh_client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            ssh_client.close()
            return True

        except AssertionError as Error:
            self.print_error(Error.args[0])

        except NoValidConnectionsError:
            self.print_error('Could not connect to SSH host: ', ssh_host)

        except AuthenticationException:
            self.print_error('SSH authentication error: ', ssh_user + '@' + ssh_host)

        except FileNotFoundError:
            self.print_error('Not found remote file: ', remote_path)

        if exit_on_failure:
            exit(1)
        return False
    # endregion

# endregion
