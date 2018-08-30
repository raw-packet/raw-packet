#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath

current_path = dirname((abspath(__file__)))
path.append(current_path)

from base import Base
from os import errno
from libnmap.process import NmapProcess
import xml.etree.ElementTree as ET
import subprocess as sub
import re
# endregion


# region Main class - Scanner
class Scanner:
    Base = None
    ScriptDir = None
    ip_pattern = None

    def __init__(self):
        self.Base = Base()
        self.ScriptDir = dirname((abspath(__file__)))
        self.ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    # region Find Apple devices by MAC address
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

    # region Find devices in local network
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
                self.Base.print_error("Something else went wrong while trying to run ", "`arp-scan`")
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

    # region Find Apple devices in local network with nmap
    def find_apple_devices_with_nmap(self, network_interface):
        local_network_devices = []
        apple_devices = []

        local_network = self.Base.get_netiface_first_ip(network_interface) + "-" + \
                        self.Base.get_netiface_last_ip(network_interface).split('.')[3]
        nmap = NmapProcess(local_network, "-n -O --osscan-guess -T5 -e " +
                           network_interface + " -oX " + self.ScriptDir + "/nmap_local_network.xml", None, False)
        nmap.run()

        nmap_report = ET.parse(self.ScriptDir + "/nmap_local_network.xml")
        root_tree = nmap_report.getroot()
        for element in root_tree:
            if element.tag == "host":
                state = element.find('status').attrib['state']
                if state == 'up':
                    ip_address = None
                    mac_address = None
                    description = None
                    for address in element.findall('address'):
                        if address.attrib['addrtype'] == 'ipv4':
                            ip_address = address.attrib['addr']
                        if address.attrib['addrtype'] == 'mac':
                            mac_address = address.attrib['addr']
                            description = address.attrib['vendor'] + " device"
                    for os_info in element.find('os'):
                        if os_info.tag == 'osmatch':
                            description += ", " + os_info.attrib['name']
                            break
                    local_network_devices.append([ip_address, mac_address, description])

        for network_device in local_network_devices:
            if "Apple" in network_device[2] or "Mac OS" in network_device[2] or "iOS" in network_device[2]:
                apple_devices.append(network_device)

        return apple_devices
    # endregion

# endregion
