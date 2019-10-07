# region Description
"""
base.py: Base class for Raw-packet project
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from platform import system, release, dist
from sys import exit, stdout
from os import getuid
from os.path import dirname, abspath, isfile, join
from pwd import getpwuid
from random import choice, randint
from netifaces import interfaces, ifaddresses, AF_LINK, AF_INET, AF_INET6
from netifaces import gateways
from netaddr import IPNetwork, IPAddress
from struct import pack, error
from ipaddress import IPv4Address
from re import match
import subprocess as sub
import psutil as ps
import socket as sock
from distro import linux_distribution
from prettytable import PrettyTable
from typing import Dict, List, Union
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


# region Main class - Base
class Base:

    # region Set variables
    os_installed_packages_list = None
    # endregion

    # region Init
    def __init__(self) -> None:
        """
        Init string variables
        """

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
    @staticmethod
    def print_banner() -> None:
        """
        Print colored banner in console
        :return: None
        """

        with open(dirname(abspath(__file__)) + '/version.txt', 'r') as version_file:
            current_version = version_file.read()

        green_color: str = '\033[1;32m'
        yellow_color: str = '\033[1;33m'
        end_color: str = '\033[0m'

        print(green_color + "                                          _        _   " + end_color)
        print(green_color + " _ __ __ ___      __     _ __   __ _  ___| | _____| |_ " + end_color)
        print(green_color + "| '__/ _` \ \ /\ / /___ | '_ \ / _` |/ __| |/ / _ \ __|" + end_color)
        print(green_color + "| | | (_| |\ V  V /|___|| |_) | (_| | (__|   <  __/ |_ " + end_color)
        print(green_color + "|_|  \__,_| \_/\_/      | .__/ \__,_|\___|_|\_\___|\__|" + end_color)
        print(green_color + "                        |_|                      v" + current_version + end_color)
        print(yellow_color + "\r\n             https://raw-packet.github.io/\r\n" + end_color)

    def color_print(self, color: str = 'blue', *strings: str) -> None:
        """
        Print colored text in console
        :param color: Set color: blue, red, orange, green (default: blue)
        :param strings: Strings for printing in console
        :return: None
        """
        if color == 'blue':
            stdout.write(self.c_info)
        if color == 'red':
            stdout.write(self.c_error)
        if color == 'orange':
            stdout.write(self.c_warning)
        if color == 'green':
            stdout.write(self.c_success)
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

    def print_info(self, *strings: str) -> None:
        """
        Print informational text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self.color_print('blue', *strings)

    def print_error(self, *strings: str) -> None:
        """
        Print error text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self.color_print('red', *strings)

    def print_warning(self, *strings: str) -> None:
        """
        Print warning text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self.color_print('orange', *strings)

    def print_success(self, *strings: str) -> None:
        """
        Print success text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self.color_print('green', *strings)

    def color_text(self, color: str = 'blue', string: str = '') -> str:
        """
        Make colored string
        :param color: Set color: blue, red, orange, green (default: blue)
        :param string: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        if color == 'blue':
            return self.cINFO + string + self.cEND
        if color == 'red':
            return self.cERROR + string + self.cEND
        if color == 'orange':
            return self.cWARNING + string + self.cEND
        if color == 'green':
            return self.cSUCCESS + string + self.cEND

    def info_text(self, text: str) -> str:
        """
        Make information text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        return self.color_text('blue', text)

    def error_text(self, text: str) -> str:
        """
        Make error text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;31mtest\033[0m')
        """
        return self.color_text('red', text)

    def warning_text(self, text: str) -> str:
        """
        Make warning text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;32mtest\033[0m')
        """
        return self.color_text('orange', text)

    def success_text(self, text: str) -> str:
        """
        Make success text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;33mtest\033[0m')
        """
        return self.color_text('green', text)
    # endregion

    # region Check platform and user functions
    @staticmethod
    def check_platform() -> None:
        """
        Check Python version and OS
        :return: None
        """
        if system() != 'Linux':
            print('This script can run only in Linux platform!')
            print('Your platform: ' + str(system()) + ' ' + str(release()) + ' not supported!')
            exit(1)

    @staticmethod
    def check_user() -> None:
        """
        Check user privileges
        :return: None
        """
        if getuid() != 0:
            print('Only root can run this script!')
            print('You: ' + str(getpwuid(getuid())[0]) + ' can not run this script!')
            exit(1)
    # endregion

    # region Pack functions
    @staticmethod
    def pack8(data: Union[int, str, bytes]) -> bytes:
        """
        Pack 8 bit data
        :param data: Input data
        :return: Packed 8 bit data
        """
        try:
            return pack('B', data)
        except error:
            print('Bad value for 8 bit pack: ' + str(data))
            exit(1)

    @staticmethod
    def pack16(data: Union[str, bytes]) -> bytes:
        """
        Pack 16 bit data
        :param data: Input data
        :return: Packed 16 bit data
        """
        try:
            return pack('!H', data)
        except error:
            print('Bad value for 16 bit pack: ' + str(data))
            exit(1)

    @staticmethod
    def pack32(data: Union[str, bytes]) -> bytes:
        """
        Pack 32 bit data
        :param data: Input data
        :return: Packed 32 bit data
        """
        try:
            return pack('!I', data)
        except error:
            print('Bad value for 32 bit pack: ' + str(data))
            exit(1)

    @staticmethod
    def pack64(data: Union[str, bytes]) -> bytes:
        """
        Pack 64 bit data
        :param data: Input data
        :return: Packed 64 bit data
        """
        try:
            return pack('!Q', data)
        except error:
            print('Bad value for 64 bit pack: ' + str(data))
            exit(1)
    # endregion

    # region Network interface functions
    def network_interface_selection(self,
                                    interface_name: Union[None, str] = None) -> str:
        """
        Select network interface
        :param interface_name: Network interface name (example: 'eth0'; default: None)
        :return: Network interface name (example: 'eth0')
        """
        network_interface_index: int = 1
        available_network_interfaces: List[str] = interfaces()

        if interface_name is not None:
            if interface_name in available_network_interfaces:
                return interface_name
            else:
                self.print_error('Network interface: ', interface_name, ' does not exist!')
                exit(1)
        else:
            if 'lo' in available_network_interfaces:
                available_network_interfaces.remove('lo')

            if len(available_network_interfaces) > 1:
                self.print_info('Your interface list:')

                interfaces_pretty_table = PrettyTable([self.info_text('Index'), self.info_text('Interface name')])

                for network_interface in available_network_interfaces:
                    interfaces_pretty_table.add_row([str(network_interface_index), network_interface])
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
                return current_network_interface

            if len(available_network_interfaces) == 1:
                self.print_info('You have only one network interface: ', available_network_interfaces[0])
                return available_network_interfaces[0]

            if len(available_network_interfaces) == 0:
                self.print_error('Network interfaces not found!')
                exit(1)

    # @staticmethod
    # def check_netiface_is_wireless(interface_name):
    #     try:
    #         wifi = Wireless(interface_name)
    #         wifi.getEssid()
    #         result = True
    #     except:
    #         result = False
    #     return result
    #
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

    def get_interface_mac_address(self,
                                  interface_name: str = 'eth0',
                                  exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get MAC address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: MAC address string (example: '01:23:45:67:89:0a') or None in case of error
        """
        try:
            return str(ifaddresses(interface_name)[AF_LINK][0]['addr'])
        except ValueError:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have MAC address!')
                exit(1)
            else:
                return None

    def get_interface_ip_address(self,
                                 interface_name: str = 'eth0',
                                 exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv4 address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        try:
            ipv4_address = str(ifaddresses(interface_name)[AF_INET][0]['addr'])

        except ValueError:
            ipv4_address = None

        except KeyError:
            ipv4_address = None

        if ipv4_address is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have IPv4 address!')
                exit(1)
        return ipv4_address

    def get_interface_ipv6_address(self,
                                   interface_name: str = 'eth0',
                                   address_index: int = 0,
                                   exit_on_failure: bool = False) -> Union[None, str]:
        """
        Get IPv6 address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param address_index: Index of IPv6 address (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :return: IPv6 address string (example: 'fd00::1') or None in case of error
        """
        try:
            ipv6_address = str(ifaddresses(interface_name)[AF_INET6][address_index]['addr'])
            ipv6_address = ipv6_address.replace('%' + interface_name, '', 1)

        except IndexError:
            ipv6_address = None

        except ValueError:
            ipv6_address = None

        except KeyError:
            ipv6_address = None

        if ipv6_address is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name,
                                 ' does not have IPv6 address with index: ', str(address_index))
                exit(1)
        return ipv6_address

    def get_interface_ipv6_link_address(self,
                                        interface_name: str = 'eth0',
                                        exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv6 link local address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv6 link local address string (example: 'fe80::1') or None in case of error
        """
        for address_index in range(0, 10, 1):
            ipv6_address = self.get_interface_ipv6_address(interface_name, address_index)
            try:
                # IPv6 link local address starts with: 'fe80::'
                if ipv6_address.startswith('fe80::'):
                    return ipv6_address
            except AttributeError:
                if exit_on_failure:
                    self.print_error('Network interface: ', interface_name, ' does not have IPv6 link local address!')
                    exit(1)
                return None
        return None

    def get_interface_ipv6_glob_address(self,
                                        interface_name: str = 'eth0',
                                        exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv6 global address of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv6 global address string (example: 'fd00::1') or None in case of error
        """
        for address_index in range(0, 10, 1):
            ipv6_address = self.get_interface_ipv6_address(interface_name, address_index)
            try:
                # IPv6 link local address starts with: 'fe80::'
                if not ipv6_address.startswith('fe80::'):
                    return ipv6_address
            except AttributeError:
                if exit_on_failure:
                    self.print_error('Network interface: ', interface_name, ' does not have IPv6 global address!')
                    exit(1)
                return None
        return None

    def get_interface_ipv6_glob_addresses(self,
                                          interface_name: str = 'eth0') -> List[str]:
        """
        Get IPv6 global addresses list of the network interface
        :param interface_name: Network interface name (default: 'eth0')
        :return: IPv6 global addresses list (example: ['fd00::1', 'fd00::2'])
        """
        ipv6_addresses: List[str] = list()
        for address_index in range(0, 10, 1):
            try:
                ipv6_address = self.get_interface_ipv6_address(interface_name, address_index)
                # IPv6 link local address starts with: 'fe80::'
                if not ipv6_address.startswith('fe80::'):
                    ipv6_addresses.append(ipv6_address)
            except AttributeError:
                break
        return ipv6_addresses

    def make_ipv6_link_address(self,
                               mac_address: str = '01:23:45:67:89:0a') -> Union[None, str]:
        """
        Make IPv6 link local address by MAC address
        :param mac_address: MAC address (default: '01:23:45:67:89:0a')
        :return: IPv6 link local address string (example: 'fe80::1') or None in case of error
        """
        if not self.mac_address_validation(mac_address):
            return None
        parts: List[str] = mac_address.split(':')
        parts.insert(3, 'ff')
        parts.insert(4, 'fe')
        parts[0] = '%x' % (int(parts[0], 16) ^ 2)
        ipv6_parts: List[str] = list()
        for index in range(0, len(parts), 2):
            ipv6_parts.append(''.join(parts[index:index + 2]))
        return 'fe80::%s' % (':'.join(ipv6_parts))

    def get_interface_netmask(self,
                              interface_name: str = 'eth0',
                              exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get network interface mask
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: Network interface mask string (example: '255.255.255.0') or None in case of error
        """
        try:
            network_mask = str(ifaddresses(interface_name)[AF_INET][0]['netmask'])

        except ValueError:
            network_mask = None

        except KeyError:
            network_mask = None

        if network_mask is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have network mask!')
                exit(1)
        return network_mask

    def get_interface_network(self,
                              interface_name: str = 'eth0',
                              exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv4 network on interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 network string (example: '192.168.1.0/24') or None in case of error
        """
        try:
            netmask = self.get_interface_netmask(interface_name, exit_on_failure)
            ip_address = self.get_interface_ip_address(interface_name, exit_on_failure)
            ip = IPNetwork(ip_address + '/' + netmask)
            network = str(ip[0]) + '/' + str(IPAddress(netmask).netmask_bits())

        except KeyError:
            network = None

        except ValueError:
            network = None

        except TypeError:
            network = None

        if network is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
                exit(1)
        return network

    def get_ip_on_interface_by_index(self,
                                     interface_name: str = 'eth0',
                                     index: int = 1,
                                     exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv4 address on network interface by index of address
        :param interface_name: Network interface name (default: 'eth0')
        :param index: Index of IPv4 address integer (default: 1)
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        try:
            network = IPNetwork(self.get_interface_network(interface_name, exit_on_failure))
            result_address = str(network[index])

        except KeyError:
            result_address = None

        except ValueError:
            result_address = None

        except TypeError:
            result_address = None

        if result_address is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
                exit(1)
        return result_address

    def get_first_ip_on_interface(self,
                                  interface_name: str = 'eth0',
                                  exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get first IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.1') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=1,
                                                 exit_on_failure=exit_on_failure)

    def get_second_ip_on_interface(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get second IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.2') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=2,
                                                 exit_on_failure=exit_on_failure)

    def get_penultimate_ip_on_interface(self,
                                        interface_name: str = 'eth0',
                                        exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get penultimate IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.253') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=-3,
                                                 exit_on_failure=exit_on_failure)

    def get_last_ip_on_interface(self,
                                 interface_name: str = 'eth0',
                                 exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get last IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.254') or None in case of error
        """
        return self.get_ip_on_interface_by_index(interface_name=interface_name,
                                                 index=-2,
                                                 exit_on_failure=exit_on_failure)

    def get_random_ip_on_interface(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get random IPv4 address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.123') or None in case of error
        """
        try:
            network = IPNetwork(self.get_interface_network(interface_name, exit_on_failure))
            random_index = randint(2, len(network) - 3)
            result_address = str(network[random_index])

        except KeyError:
            result_address = None

        except ValueError:
            result_address = None

        except TypeError:
            result_address = None

        if result_address is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have IPv4 address or network mask!')
                exit(1)
        return result_address

    def get_interface_broadcast(self,
                                interface_name: str = 'eth0',
                                exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv4 broadcast address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.255') or None in case of error
        """
        try:
            broadcast = str(ifaddresses(interface_name)[AF_INET][0]['broadcast'])

        except KeyError:
            broadcast = None

        except ValueError:
            broadcast = None

        if broadcast is None:
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have broadcast address!')
                exit(1)
        return broadcast

    def get_interface_gateway(self,
                              interface_name: str = 'eth0',
                              exit_on_failure: bool = True,
                              network_type: int = AF_INET) -> Union[None, str]:
        """
        Get gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :param network_type: Set network type AF_INET for IPv4 network or AF_INET6 for IPv6 (default: AF_INET)
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
            if exit_on_failure:
                self.print_error('Network interface: ', interface_name, ' does not have IPv4 gateway!')
                exit(1)
        return gateway_address

    def get_interface_ipv4_gateway(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv4 gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv4 address string (example: '192.168.1.254') or None in case of error
        """
        return self.get_interface_gateway(interface_name=interface_name,
                                          exit_on_failure=exit_on_failure,
                                          network_type=AF_INET)

    def get_interface_ipv6_gateway(self,
                                   interface_name: str = 'eth0',
                                   exit_on_failure: bool = True) -> Union[None, str]:
        """
        Get IPv6 gateway address on network interface
        :param interface_name: Network interface name (default: 'eth0')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: IPv6 address string (example: 'fd00::1') or None in case of error
        """
        return self.get_interface_gateway(interface_name=interface_name,
                                          exit_on_failure=exit_on_failure,
                                          network_type=AF_INET6)

    # endregion

    # region Check installed software
    def apt_list_installed_packages(self,
                                    exit_on_failure: bool = True) -> Union[None, bytes]:
        """
        Get output of bash command: apt list --installed
        :param exit_on_failure: Exit in case of error (default: True)
        :return: result bytes
        """
        apt_list_out = None
        try:
            apt_list = sub.Popen(['apt list --installed'], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            apt_list_out, apt_list_err = apt_list.communicate()
        except OSError:
            if exit_on_failure:
                self.print_error('Something else went wrong while trying to run ', '`apt list --installed`')
                exit(1)
        if apt_list_out is not None:
            self.os_installed_packages_list = apt_list_out
        return apt_list_out

    def check_installed_software(self,
                                 software_name: str = 'apache2',
                                 exit_on_failure: bool = True) -> bool:
        """
        Check software is installed or not
        :param software_name: Name of software (default: 'apache2')
        :param exit_on_failure: Exit in case of error (default: True)
        :return: True or False
        """
        self.check_platform()

        if 'Kali' or 'Ubuntu' or 'Debian' in linux_distribution():

            if self.os_installed_packages_list is None:
                self.apt_list_installed_packages(exit_on_failure)

            if self.os_installed_packages_list is None:
                if exit_on_failure:
                    self.print_error('Unable to verify OS installed software.')
                    exit(1)

            else:
                if software_name.encode(encoding='utf-8') in self.os_installed_packages_list:
                    return True
                else:
                    if isfile('/bin/' + software_name) or isfile('/sbin/' + software_name) or \
                            isfile('/usr/bin/' + software_name) or isfile('/usr/sbin/' + software_name) or \
                            isfile('/usr/local/bin/' + software_name) or isfile('/usr/local/sbin/' + software_name):
                        return True
                    else:
                        return False

        else:
            self.print_warning('Unable to verify OS installed software. ' +
                               'This function works normal only in Debian, Ubuntu or Kali linux.')

            if isfile('/bin/' + software_name) or isfile('/sbin/' + software_name) or \
                    isfile('/usr/bin/' + software_name) or isfile('/usr/sbin/' + software_name) or \
                    isfile('/usr/local/bin/' + software_name) or isfile('/usr/local/sbin/' + software_name):
                return True
            else:
                return False
    # endregion

    # region Process control functions
    @staticmethod
    def check_process(process_name: str = 'apache2') -> int:
        """
        Check process is running
        :param process_name: Process name string (default: 'apache2')
        :return: Process ID integer (example: 1234)
        """
        for process in ps.process_iter():
            if 'python' in process.name():
                for argument in process.cmdline():
                    if process_name in argument:
                        return int(process.pid)
            if process.name() == process_name:
                return int(process.pid)
        return -1

    def get_process_pid(self, process_name: str = 'apache2') -> int:
        """
        Get process ID
        :param process_name: Process name string (default: 'apache2')
        :return: Process ID integer (example: 1234)
        """
        return self.check_process(process_name)

    @staticmethod
    def get_process_pid_by_listen_port(listen_port: int = 80,
                                       listen_address: Union[None, str] = None,
                                       listen_proto: str = 'tcp') -> List[int]:
        """
        Get list of processes ID by listen TCP or UDP port
        :param listen_port: Listening TCP or UDP port integer (default: 80)
        :param listen_address: Listening IPv4 or IPv6 address string (default: None)
        :param listen_proto: Listening protocol string 'tcp' or 'udp' (default: 'tcp')
        :return: List of processes ID by listen TCP or UDP port
        """
        pids: List[int] = list()
        try:
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
            return self.kill_process(process_pid)
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
        pids: List[int] = self.get_process_pid_by_listen_port(listen_port, listen_address, listen_proto)
        if len(pids) > 0:
            for pid in pids:
                self.kill_process(pid)

        pids: List[int] = self.get_process_pid_by_listen_port(listen_port, listen_address, listen_proto)
        if len(pids) > 0:
            return False
        else:
            return True
    # endregion

    # region Others functions
    @staticmethod
    def ipv6_address_validation(ipv6_address):
        try:
            sock.inet_pton(sock.AF_INET6, ipv6_address)
            return True
        except sock.error:
            return False

    @staticmethod
    def ip_address_validation(ip_address):
        try:
            sock.inet_aton(ip_address)
            return True
        except sock.error:
            return False

    @staticmethod
    def mac_address_validation(mac_address):
        if match(r'^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$', mac_address):
            return True
        else:
            return False

    @staticmethod
    def ip_address_in_range(ip_address, first_ip_address, last_ip_address):
        if IPv4Address(first_ip_address) <= IPv4Address(ip_address) <= IPv4Address(last_ip_address):
            return True
        else:
            return False

    @staticmethod
    def ip_address_in_network(ip_address, network):
        return IPAddress(ip_address) in IPNetwork(network)

    @staticmethod
    def ip_address_increment(ip_address):
        return str(IPv4Address(ip_address) + 1)

    @staticmethod
    def ip_address_compare(first_ip_address: str, second_ip_address: str, operator: str = 'eq') -> bool:
        """
        Compare IPv4 addresses
        :param first_ip_address: First IPv4 address for compare (example: 192.168.0.1)
        :param second_ip_address: Second IPv4 address for compare (example: 192.168.0.2)
        :param operator: eq - equal; ne - not equal; gt - greater; ge - greater or equal; lt - less; le - less or equal (default: eq)
        :return: True or False
        """

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

        else:
            return False

    def make_random_string(self, length: int = 8) -> str:
        """
        Make random string from lowercase letter, uppercase letter and digits
        :param length: Length of string (default: 8)
        :return: Random string (example: d1dfJ3a032)
        """
        return ''.join(choice(self.lowercase_letters + self.uppercase_letters + self.digits) for _ in range(length))

    @staticmethod
    def get_mac_prefixes(prefixes_filename: str = 'mac-prefixes.txt') -> List[Dict[str, str]]:
        """
        Get MAC address prefixes from file
        :param prefixes_filename: Name of file with MAC address prefixes (content example: 0050BA D-Link\n00179A D-Link)
        :return: MAC prefixes list (example: [{'prefix': '0050BA', 'vendor': 'D-Link'}])
        """

        current_path: str = dirname(abspath(__file__))
        vendor_list: List[Dict[str, str]] = list()

        with open(join(current_path, prefixes_filename), 'r') as mac_prefixes_descriptor:
            for string in mac_prefixes_descriptor.readlines():
                string_list = string.split(' ', 1)
                vendor_list.append({
                    'prefix': string_list[0],
                    'vendor': string_list[1][:-1]
                })
        return vendor_list
    # endregion

# endregion
