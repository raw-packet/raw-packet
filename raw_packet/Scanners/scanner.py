#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
# endregion

# region Import libraries
from os import errno
import xml.etree.ElementTree as ET
import subprocess as sub
from prettytable import PrettyTable
from os.path import dirname, abspath
current_path = dirname((abspath(__file__)))
# endregion

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


# region Main class - Scanner
class Scanner:

    # region Variables
    Base = None
    ArpScan = None
    ICMPv6Scan = None
    # endregion

    # region Init
    def __init__(self):
        self.Base = Base()
        self.ArpScan = ArpScan()
        self.ICMPv6Scan = ICMPv6Scan()

        if not self.Base.check_installed_software("nmap"):
            exit(2)
    # endregion

    # region Apple device selection
    def apple_device_selection(self, apple_devices):
        try:
            apple_device = None
            if len(apple_devices) > 0:
                if len(apple_devices) == 1:
                    apple_device = apple_devices[0]
                    self.Base.print_info("Only one Apple device found:")
                    self.Base.print_success(apple_device[0] + " (" + apple_device[1] + ") ", apple_device[2])
                if len(apple_devices) > 1:
                    self.Base.print_info("Apple devices found:")
                    device_index = 1
                    apple_devices_pretty_table = PrettyTable([self.Base.cINFO + 'Index' + self.Base.cEND,
                                                              self.Base.cINFO + 'IP address' + self.Base.cEND,
                                                              self.Base.cINFO + 'MAC address' + self.Base.cEND,
                                                              self.Base.cINFO + 'Vendor' + self.Base.cEND])

                    for apple_device in apple_devices:
                        apple_devices_pretty_table.add_row([str(device_index), apple_device[0],
                                                            apple_device[1], apple_device[2]])
                        device_index += 1

                    print apple_devices_pretty_table
                    device_index -= 1
                    current_device_index = raw_input(self.Base.c_info + 'Set device index from range (1-' +
                                                     str(device_index) + '): ')

                    if not current_device_index.isdigit():
                        self.Base.print_error("Your input data is not digit!")
                        exit(1)

                    if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                        self.Base.print_error("Your number is not within range (1-" + str(device_index) + ")")
                        exit(1)

                    current_device_index = int(current_device_index) - 1
                    apple_device = apple_devices[current_device_index]
            else:
                self.Base.print_error("Could not find Apple devices!")
                exit(1)
            return apple_device

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)
    # endregion

    # region IPv6 device selection
    def ipv6_device_selection(self, ipv6_devices):
        try:
            ipv6_device = None
            if len(ipv6_devices) > 0:
                if len(ipv6_devices) == 1:
                    ipv6_device = ipv6_devices[0]
                    self.Base.print_info("Only one IPv6 device found:")
                    self.Base.print_success(ipv6_device[0] + " (" + ipv6_device[1] + ") ", ipv6_device[2])
                if len(ipv6_devices) > 1:
                    self.Base.print_info("IPv6 devices found:")
                    device_index = 1
                    for ipv6_device in ipv6_devices:
                        self.Base.print_success(
                            str(device_index) + ") " + ipv6_device[0] + " (" + ipv6_device[1] + ") ",
                            ipv6_device[2]
                        )
                        device_index += 1

                    device_index -= 1
                    current_device_index = raw_input(self.Base.c_info + 'Set device index from range (1-' +
                                                     str(device_index) + '): ')

                    if not current_device_index.isdigit():
                        self.Base.print_error("Your input data is not digit!")
                        exit(1)

                    if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                        self.Base.print_error("Your number is not within range (1-" + str(device_index) + ")")
                        exit(1)

                    current_device_index = int(current_device_index) - 1
                    ipv6_device = ipv6_devices[current_device_index]
            else:
                self.Base.print_error("Could not find IPv6 devices!")
                exit(1)
            return ipv6_device

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)
    # endregion

    # region Find all devices in local network
    def find_ip_in_local_network(self, network_interface, timeout=3, retry=3):
        try:
            local_network_ip_addresses = []
            arp_scan_results = self.ArpScan.scan(network_interface, timeout, retry)

            if len(arp_scan_results) > 0:
                for device in arp_scan_results:
                    if self.Base.ip_address_validation(device['ip-address']):
                        local_network_ip_addresses.append(device['ip-address'])

            return local_network_ip_addresses

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)
    # endregion

    # region Find Apple devices in local network with ArpScan
    def find_apple_devices_by_mac(self, network_interface, timeout=3, retry=3):
        try:
            apple_devices = []
            arp_scan_results = self.ArpScan.scan(network_interface, timeout, retry)

            if len(arp_scan_results) > 0:
                for device in arp_scan_results:
                    if "Apple" in device['vendor']:
                        apple_devices.append([device['ip-address'], device['mac-address'], device['vendor']])
            else:
                self.Base.print_error("Could not find devices in local network on interface: ", network_interface)
                exit(2)

            return apple_devices

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)
    # endregion

    # region Find IPv6 devices in local network with ICMPv6Scan
    def find_ipv6_devices(self, network_interface, timeout=5, retry=3, exclude_ipv6_address=None):
        try:
            ipv6_devices = []
            ipv6_scan_results = self.ICMPv6Scan.scan(network_interface, timeout, retry, None, True)

            if len(ipv6_scan_results) > 0:
                for device in ipv6_scan_results:
                    if exclude_ipv6_address is not None:
                        if exclude_ipv6_address != device['ip-address']:
                            ipv6_devices.append([device['ip-address'], device['mac-address'], device['vendor']])
                    else:
                        ipv6_devices.append([device['ip-address'], device['mac-address'], device['vendor']])
            else:
                self.Base.print_error("Could not find devices with IPv6 link local address " +
                                      "in local network on interface: ", network_interface)
                exit(2)

            return ipv6_devices

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)
    # endregion

    # region Find Apple devices in local network with nmap
    def find_apple_devices_with_nmap(self, network_interface):
        try:
            local_network_devices = []
            apple_devices = []

            local_network = self.Base.get_netiface_first_ip(network_interface) + "-" + \
                            self.Base.get_netiface_last_ip(network_interface).split('.')[3]

            nmap_process = sub.Popen(['nmap ' + local_network + ' -n -O --osscan-guess -T5 -e ' +
                                     network_interface + ' -oX ' + current_path + '/nmap_local_network.xml'],
                                     shell=True, stdout=sub.PIPE)
            nmap_process.wait()

            nmap_report = ET.parse(current_path + "/nmap_local_network.xml")
            root_tree = nmap_report.getroot()
            for element in root_tree:
                if element.tag == "host":
                    state = element.find('status').attrib['state']
                    if state == 'up':
                        ip_address = ""
                        mac_address = ""
                        description = ""
                        for address in element.findall('address'):
                            if address.attrib['addrtype'] == 'ipv4':
                                ip_address = address.attrib['addr']
                            if address.attrib['addrtype'] == 'mac':
                                mac_address = address.attrib['addr']
                                try:
                                    description = address.attrib['vendor'] + " device"
                                except KeyError:
                                    pass
                        for os_info in element.find('os'):
                            if os_info.tag == 'osmatch':
                                try:
                                    description += ", " + os_info.attrib['name']
                                except TypeError:
                                    pass
                                break
                        local_network_devices.append([ip_address, mac_address, description])

            for network_device in local_network_devices:
                if "Apple" or "Mac OS" or "iOS" in network_device[2]:
                    apple_devices.append(network_device)

            return apple_devices

        except OSError as e:
            if e.errno == errno.ENOENT:
                self.Base.print_error("Program: ", "nmap", " is not installed!")
                exit(1)
            else:
                self.Base.print_error("Something went wrong while trying to run ", "`nmap`")
                exit(2)

        except KeyboardInterrupt:
            self.Base.print_info("Exit")
            exit(0)

    # endregion

# endregion
