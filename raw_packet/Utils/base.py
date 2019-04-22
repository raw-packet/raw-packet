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
from string import lowercase, uppercase, digits
from netifaces import interfaces, ifaddresses, AF_LINK, AF_INET, AF_INET6
from netifaces import gateways
from netaddr import IPNetwork, IPAddress
from struct import pack, error
from ipaddress import IPv4Address
from os import errno
from re import match
import subprocess as sub
import psutil as ps
import socket as sock
from prettytable import PrettyTable
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Main class - Base
class Base:

    # region Set variables
    cINFO = None
    cERROR = None
    cSUCCESS = None
    cWARNING = None
    cEND = None

    c_info = None
    c_error = None
    c_success = None
    c_warning = None

    os_installed_packages_list = None
    # endregion

    # region Init
    def __init__(self):
        self.cINFO = '\033[1;34m'
        self.cERROR = '\033[1;31m'
        self.cSUCCESS = '\033[1;32m'
        self.cWARNING = '\033[1;33m'
        self.cEND = '\033[0m'

        self.c_info = self.cINFO + '[*]' + self.cEND + ' '
        self.c_error = self.cERROR + '[-]' + self.cEND + ' '
        self.c_success = self.cSUCCESS + '[+]' + self.cEND + ' '
        self.c_warning = self.cWARNING + '[!]' + self.cEND + ' '
    # endregion

    # region Output functions
    @staticmethod
    def print_banner():
        with open(dirname(abspath(__file__)) + '/version.txt', 'r') as version_file:
            current_version = version_file.read()
        greenc = '\033[1;32m'
        yellowc = '\033[1;33m'
        endc = '\033[0m'
        print greenc + "                                          _        _   " + endc
        print greenc + " _ __ __ ___      __     _ __   __ _  ___| | _____| |_ " + endc
        print greenc + "| '__/ _` \ \ /\ / /___ | '_ \ / _` |/ __| |/ / _ \ __|" + endc
        print greenc + "| | | (_| |\ V  V /|___|| |_) | (_| | (__|   <  __/ |_ " + endc
        print greenc + "|_|  \__,_| \_/\_/      | .__/ \__,_|\___|_|\_\___|\__|" + endc
        print greenc + "                        |_|                      v" + current_version + endc
        print yellowc + "\r\n             https://raw-packet.github.io/\r\n" + endc

    def color_print(self, color, *strings):
        if color == "blue":
            stdout.write(self.c_info)
        if color == "red":
            stdout.write(self.c_error)
        if color == "orange":
            stdout.write(self.c_warning)
        if color == "green":
            stdout.write(self.c_success)
        for index in range(len(strings)):
            if index % 2 == 0:
                stdout.write(strings[index])
            else:
                if color == "blue":
                    stdout.write(self.cINFO)
                if color == "red":
                    stdout.write(self.cERROR)
                if color == "orange":
                    stdout.write(self.cWARNING)
                if color == "green":
                    stdout.write(self.cSUCCESS)
                stdout.write(strings[index] + self.cEND)
        stdout.write("\n")

    def print_info(self, *strings):
        self.color_print("blue", *strings)

    def print_error(self, *strings):
        self.color_print("red", *strings)

    def print_warning(self, *strings):
        self.color_print("orange", *strings)

    def print_success(self, *strings):
        self.color_print("green", *strings)
    # endregion

    # region Check platform and user functions
    @staticmethod
    def check_platform():
        if system() != "Linux":
            print "This script can run only in Linux platform!"
            print "Your platform: " + str(system()) + " " + str(release()) + " not supported!"
            exit(1)

    @staticmethod
    def check_user():
        if getuid() != 0:
            print "Only root can run this script!"
            print "You: " + str(getpwuid(getuid())[0]) + " can not run this script!"
            exit(1)
    # endregion

    # region Pack functions
    @staticmethod
    def pack8(data):
        try:
            return pack("B", data)
        except error:
            print "Bad value for 8 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack16(data):
        try:
            return pack("!H", data)
        except error:
            print "Bad value for 16 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack32(data):
        try:
            return pack("<I", data)
        except error:
            print "Bad value for 32 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack64(data):
        try:
            return pack("<Q", data)
        except error:
            print "Bad value for 64 bit pack: " + str(data)
            exit(1)
    # endregion

    # region Network interface functions
    def netiface_selection(self, interface_name=None):
        netiface_index = 1
        current_netifaces = interfaces()

        if interface_name is not None:
            if interface_name in current_netifaces:
                return interface_name
            else:
                self.print_error("Network interface: ", interface_name, " does not exist!")
                exit(1)
        else:
            if 'lo' in current_netifaces:
                current_netifaces.remove('lo')

            if len(current_netifaces) > 1:
                self.print_info("Your interface list:")

                iface_pretty_table = PrettyTable([self.cINFO + 'Index' + self.cEND,
                                                  self.cINFO + 'Interface name' + self.cEND])

                for netiface in current_netifaces:
                    iface_pretty_table.add_row([str(netiface_index), netiface])
                    netiface_index += 1

                print iface_pretty_table

                netiface_index -= 1
                current_netiface_index = raw_input(self.c_warning + 'Set network interface from range (1-' +
                                                   str(netiface_index) + '): ')

                if not current_netiface_index.isdigit():
                    self.print_error("Your input data: ", current_netiface_index, " is not digit!")
                    exit(1)

                if any([int(current_netiface_index) < 1, int(current_netiface_index) > netiface_index]):
                    self.print_error("Your number: ", current_netiface_index,
                                     " is not within range (", "1-" + str(netiface_index), ")")
                    exit(1)

                current_network_interface = ""
                try:
                    current_network_interface = str(current_netifaces[int(current_netiface_index) - 1])
                except:
                    self.print_error("This network interface has some problem!")
                    exit(1)
                return current_network_interface

            if len(current_netifaces) == 1:
                self.print_info("You have only one network interface: ", current_netifaces[0])
                return current_netifaces[0]

            if len(current_netifaces) == 0:
                self.print_error("Network interfaces not found!")
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

    @staticmethod
    def get_netiface_mac_address(interface_name):
        try:
            mac_address = str(ifaddresses(interface_name)[AF_LINK][0]['addr'])
        except:
            mac_address = None
        return mac_address

    @staticmethod
    def get_netiface_ip_address(interface_name):
        try:
            ip_address = str(ifaddresses(interface_name)[AF_INET][0]['addr'])
        except:
            ip_address = None
        return ip_address

    @staticmethod
    def get_netiface_ipv6_address(interface_name, address_number=0):
        try:
            ipv6_address = str(ifaddresses(interface_name)[AF_INET6][address_number]['addr'])
            ipv6_address = ipv6_address.replace("%" + interface_name, "", 1)
        except:
            ipv6_address = None
        return ipv6_address

    def get_netiface_ipv6_link_address(self, interface_name):
        for index in range(10):
            ipv6_address = self.get_netiface_ipv6_address(interface_name, index)
            if ipv6_address.startswith("fe80::"):
                return ipv6_address
        return None

    def get_netiface_ipv6_glob_address(self, interface_name):
        for index in range(10):
            ipv6_address = self.get_netiface_ipv6_address(interface_name, index)
            try:
                if ipv6_address.startswith("fe80::"):
                    pass
                else:
                    return ipv6_address

            except AttributeError:
                return None
        return None

    def get_netiface_ipv6_glob_addresses(self, interface_name):
        ipv6_addresses = []
        for index in range(10):
            try:
                ipv6_address = self.get_netiface_ipv6_address(interface_name, index)
                if ipv6_address.startswith("fe80::"):
                    pass
                else:
                    ipv6_addresses.append(ipv6_address)
            except AttributeError:
                break
        return ipv6_addresses

    @staticmethod
    def create_ipv6_link_address(mac_address):
        try:
            parts = mac_address.split(":")
            parts.insert(3, "ff")
            parts.insert(4, "fe")
            parts[0] = "%x" % (int(parts[0], 16) ^ 2)
            ipv6Parts = []
            for i in range(0, len(parts), 2):
                ipv6Parts.append("".join(parts[i:i + 2]))
            ipv6_address = "fe80::%s" % (":".join(ipv6Parts))
        except:
            ipv6_address = None
        return ipv6_address

    @staticmethod
    def get_netiface_netmask(interface_name):
        try:
            netmask = str(ifaddresses(interface_name)[AF_INET][0]['netmask'])
        except:
            netmask = None
        return netmask

    def get_netiface_first_ip(self, interface_name):
        try:
            netmask = self.get_netiface_netmask(interface_name)
            ip_address = self.get_netiface_ip_address(interface_name)
            ip = IPNetwork(ip_address + '/' + netmask)
            first_ip = str(ip[2])
        except:
            first_ip = None
        return first_ip

    def get_netiface_last_ip(self, interface_name):
        try:
            netmask = self.get_netiface_netmask(interface_name)
            ip_address = self.get_netiface_ip_address(interface_name)
            ip = IPNetwork(ip_address + '/' + netmask)
            first_ip = str(ip[-3])
        except:
            first_ip = None
        return first_ip

    def get_netiface_random_ip(self, interface_name):
        try:
            netmask = self.get_netiface_netmask(interface_name)
            ip_address = self.get_netiface_ip_address(interface_name)
            ip = IPNetwork(ip_address + '/' + netmask)
            random_index = randint(2, len(ip) - 3)
            random_ip = str(ip[random_index])
        except:
            random_ip = None
        return random_ip

    def get_netiface_net(self, interface_name):
        try:
            netmask = self.get_netiface_netmask(interface_name)
            ip_address = self.get_netiface_ip_address(interface_name)
            ip = IPNetwork(ip_address + '/' + netmask)
            network = str(ip[0]) + "/" + str(IPAddress(netmask).netmask_bits())
        except:
            network = None
        return network

    @staticmethod
    def get_netiface_broadcast(interface_name):
        try:
            broadcast = str(ifaddresses(interface_name)[AF_INET][0]['broadcast'])
        except:
            broadcast = None
        return broadcast

    @staticmethod
    def get_netiface_gateway(interface_name):
        try:
            gateway = None
            gws = gateways()
            for gw in gws:
                gateway_iface = gws[gw][AF_INET]
                gateway_ip, iface = gateway_iface[0], gateway_iface[1]
                if iface == interface_name:
                    gateway = gateway_ip
                    break
        except:
            gateway = None
        return gateway

    # endregion

    # region Check installed software
    def debian_list_installed_packages(self):
        apt_list_out = None
        try:
            apt_list = sub.Popen(['apt list --installed'], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            apt_list_out, apt_list_err = apt_list.communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                self.print_error("Program: ", "apt", " is not installed!")
                exit(1)
            else:
                self.print_error("Something else went wrong while trying to run ", "`apt list --installed`")
                exit(2)
        if apt_list_out is not None:
            self.os_installed_packages_list = apt_list_out
        return apt_list_out

    def check_installed_software(self, software_name):
        self.check_platform()

        if "Kali" or "Ubuntu" or "Debian" in dist():

            if self.os_installed_packages_list is None:
                self.debian_list_installed_packages()

            if self.os_installed_packages_list is None:
                self.print_warning("Unable to verify OS installed software.")
                return True

            else:
                if software_name == 'dnschef':
                    if isfile("/bin/" + software_name) or isfile("/sbin/" + software_name) or \
                            isfile("/usr/bin/" + software_name) or isfile("/usr/sbin/" + software_name) or \
                            isfile("/usr/local/bin/" + software_name) or isfile("/usr/local/sbin/" + software_name):
                        return True
                    else:
                        return False
                else:
                    if software_name in self.os_installed_packages_list:
                        return True
                    else:
                        self.print_error("Software: " + software_name + " is not installed!")
                        return False

        else:
            self.print_warning("Unable to verify OS installed software. This function works only in Kali or Ubuntu")
            return True
    # endregion

    # region Process control functions
    @staticmethod
    def check_process(process_name):
        for process in ps.process_iter():
            if 'python' in process.name():
                for argument in process.cmdline():
                    if process_name in argument:
                        return process.pid
            if process.name() == process_name:
                return process.pid
        return -1

    def get_process_pid(self, process_name):
        return self.check_process(process_name)

    @staticmethod
    def get_process_pid_by_listen_port(listen_port, proto='tcp'):
        pids = []
        try:
            for process in ps.process_iter():
                connections = process.connections()
                for connection in connections:
                    (listen_address, port) = connection.laddr
                    if listen_address != "127.0.0.1":
                        if connection.type == sock.SOCK_STREAM and connection.status == ps.CONN_LISTEN:
                            connection_proto = 'tcp'
                        elif connection.type == sock.SOCK_DGRAM:
                            connection_proto = 'udp'
                        else:
                            continue
                        if proto == connection_proto:
                            if connection.type == sock.SOCK_STREAM and connection.status == ps.CONN_LISTEN:
                                if port == listen_port and process.pid is not None:
                                    pids.append(process.pid)
            return pids
        except ps.NoSuchProcess:
            return []

    @staticmethod
    def kill_process(process_pid):
        try:
            process = ps.Process(process_pid)
            process.terminate()
        except ps.NoSuchProcess:
            pass

    def kill_process_by_name(self, process_name):
        process_pid = self.get_process_pid(process_name)
        if process_pid != -1:
            self.kill_process(process_pid)

    def kill_process_by_listen_port(self, listen_port, proto='tcp'):
        pids = self.get_process_pid_by_listen_port(listen_port, proto)
        if len(pids) > 0:
            for pid in pids:
                self.kill_process(pid)
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
        if match(r"^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$", mac_address):
            return True
        else:
            return False

    @staticmethod
    def ip_address_in_range(ip_address, first_ip_address, last_ip_address):
        if IPv4Address(unicode(first_ip_address)) <= IPv4Address(unicode(ip_address)) <= IPv4Address(unicode(last_ip_address)):
            return True
        else:
            return False

    @staticmethod
    def make_random_string(length):
        return ''.join(choice(lowercase + uppercase + digits) for _ in range(length))

    @staticmethod
    def get_mac_prefixes(prefixes_filename="mac-prefixes.txt"):
        current_path = dirname(abspath(__file__))
        vendor_list = []
        with open(join(current_path, prefixes_filename), 'r') as mac_prefixes_descriptor:
            for string in mac_prefixes_descriptor.readlines():
                string_list = string.split(" ", 1)
                vendor_list.append({
                    "prefix": string_list[0],
                    "vendor": string_list[1][:-1]
                })
        return vendor_list
    # endregion

# endregion

# 500th commit!!!
