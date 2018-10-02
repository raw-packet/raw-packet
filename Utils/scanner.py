#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath

current_path = dirname((abspath(__file__)))
path.append(current_path)

from base import Base
from os import errno
import xml.etree.ElementTree as ET
import subprocess as sub
import re
# endregion


# region Main class - Scanner
class Scanner:

    # region Variables
    Base = None
    ScriptDir = None
    ip_pattern = None
    # endregion

    # region Init
    def __init__(self):
        self.Base = Base()
        self.ScriptDir = dirname((abspath(__file__)))
        self.ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        if not self.Base.check_installed_software("arp-scan"):
            exit(1)
        if not self.Base.check_installed_software("nmap"):
            exit(2)
    # endregion

    # region Apple device selection
    def apple_device_selection(self, apple_devices):
        apple_device = None
        if len(apple_devices) > 0:
            if len(apple_devices) == 1:
                apple_device = apple_devices[0]
                self.Base.print_info("One Apple device found:")
                self.Base.print_success(apple_device[0] + " (" + apple_device[1] + ") ", apple_device[2])
            if len(apple_devices) > 1:
                self.Base.print_info("Apple devices found:")
                device_index = 1
                for apple_device in apple_devices:
                    self.Base.print_success(str(device_index) + ") " + apple_device[0] + " (" + apple_device[1] + ") ",
                                            apple_device[2])
                    device_index += 1

                device_index -= 1
                current_device_index = raw_input('Set device index from range (1-' + str(device_index) + '): ')

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
    # endregion

    # region Find all devices in local network
    def find_ip_in_local_network(self, network_interface):
        arp_scan_out = None
        local_network_ip_addresses = []
        try:
            arp_scan = sub.Popen(['arp-scan  -I ' + network_interface + ' --localnet'],
                                 shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            arp_scan_out, arp_scan_err = arp_scan.communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                self.Base.print_error("Program: ", "arp-scan", " is not installed!")
                exit(1)
            else:
                self.Base.print_error("Something else went wrong while trying to run ",
                                      "`arp-scan -I " + network_interface + " --localnet`")
                exit(2)

        if arp_scan_out is not None:
            for device in arp_scan_out.splitlines():
                try:
                    if self.ip_pattern.match(device.split()[0]):
                        local_network_ip_addresses.append(device.split()[0])
                except IndexError:
                    pass

        return local_network_ip_addresses
    # endregion

    # region Find Apple devices in local network with arp-scan
    def find_apple_devices_by_mac(self, network_interface):
        arp_scan_out = None
        apple_devices = []
        try:
            arp_scan = sub.Popen(['arp-scan --macfile=' + self.ScriptDir + '/apple_mac_prefixes.txt -I ' +
                                  network_interface + ' --localnet --ignoredups --retry=3 --timeout=1000'],
                                 shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            arp_scan_out, arp_scan_err = arp_scan.communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                self.Base.print_error("Program: ", "arp-scan", " is not installed!")
                exit(1)
            else:
                self.Base.print_error("Something else went wrong while trying to run ", "`arp-scan`")
                exit(2)

        if arp_scan_out is not None:
            for device in arp_scan_out.splitlines():
                if "Apple" in device:
                    ip_address = device.split()[0]
                    mac_address = device.split()[1]
                    description = ' '.join(device.split()[2:])
                    apple_devices.append([ip_address, mac_address, description])
        else:
            self.Base.print_error("Something else went wrong while trying to run ", "`arp-scan`", "")
            exit(2)

        return apple_devices
    # endregion

    # region Find Apple devices in local network with nmap
    def find_apple_devices_with_nmap(self, network_interface):
        local_network_devices = []
        apple_devices = []

        local_network = self.Base.get_netiface_first_ip(network_interface) + "-" + \
                        self.Base.get_netiface_last_ip(network_interface).split('.')[3]
        nmap_process = sub.Popen(['nmap ' + local_network + ' -n -O --osscan-guess -T5 -e ' +
                                  network_interface + ' -oX ' + self.ScriptDir + '/nmap_local_network.xml'],
                                 shell=True, stdout=sub.PIPE)
        nmap_process.wait()

        nmap_report = ET.parse(self.ScriptDir + "/nmap_local_network.xml")
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
            if "Apple" in network_device[2] or "Mac OS" in network_device[2] or "iOS" in network_device[2]:
                apple_devices.append(network_device)

        return apple_devices
    # endregion

# endregion
