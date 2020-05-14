# region Description
"""
nmap_scanner.py: Scan local network with NMAP
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
import xml.etree.ElementTree as ET
import subprocess as sub
from tempfile import gettempdir
from os.path import isfile, join
from os import remove
from typing import Union, List, Dict, NamedTuple
from collections import namedtuple
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


# region Main class - NmapScanner
class NmapScanner:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    try:
        Info = namedtuple(typename='Info', field_names='vendor, os, mac_address, ipv4_address, ports',
                          defaults=('', '', '', '', []))
    except TypeError:
        Info = namedtuple(typename='Info', field_names='vendor, os, mac_address, ipv4_address, ports')
    # endregion

    # region Init
    def __init__(self, network_interface: str):
        self._your: Dict[str, Union[None, str]] = \
            self._base.get_interface_settings(interface_name=network_interface,
                                              required_parameters=['mac-address', 'ipv4-address',
                                                                   'first-ipv4-address', 'last-ipv4-address'])
        self.local_network: str = \
            self._your['first-ipv4-address'] + '-' + \
            self._your['last-ipv4-address'].split('.')[3]
        if self._base.get_platform().startswith('Darwin'):
            self._nmap_scan_result: str = '/tmp/nmap_scan.xml'
        else:
            self._nmap_scan_result: str = join(gettempdir(), 'nmap_scan.xml')
    # endregion

    # region Find devices in local network with nmap
    def scan(self, 
             exit_on_failure: bool = True,
             quiet: bool = False) -> Union[None, List[NamedTuple]]:
        try:
            # region Variables
            network_devices: List[NamedTuple] = list()
            ipv4_address: str = ''
            mac_address: str = ''
            vendor: str = ''
            os: str = ''
            ports: List[int] = list()
            # endregion

            nmap_command: str = 'nmap ' + self.local_network + \
                                ' --open -n -O --osscan-guess -T5 -oX ' + self._nmap_scan_result
            if not quiet:
                self._base.print_info('Start nmap scan: ', nmap_command)
            if self._base.get_platform().startswith('Windows'):
                nmap_process = sub.Popen(nmap_command, shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
            else:
                nmap_process = sub.Popen([nmap_command], shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
            nmap_process.wait()
            assert isfile(self._nmap_scan_result), \
                'Not found nmap scan result file: ' + self._base.error_text(self._nmap_scan_result)

            nmap_report = ET.parse(self._nmap_scan_result)
            root_tree = nmap_report.getroot()
            for element in root_tree:
                try:
                    assert element.tag == 'host'
                    state = element.find('status').attrib['state']
                    assert state == 'up'

                    # region Address
                    for address in element.findall('address'):
                        if address.attrib['addrtype'] == 'ipv4':
                            ipv4_address = address.attrib['addr']
                        if address.attrib['addrtype'] == 'mac':
                            mac_address = address.attrib['addr'].lower()
                            try:
                                vendor = address.attrib['vendor']
                            except KeyError:
                                pass
                    # endregion

                    # region Open TCP ports
                    for ports_info in element.find('ports'):
                        if ports_info.tag == 'port':
                            ports.append(ports_info.attrib['portid'])
                    # endregion

                    # region OS
                    for os_info in element.find('os'):
                        if os_info.tag == 'osmatch':
                            try:
                                os = os_info.attrib['name']
                            except TypeError:
                                pass
                            break
                    # endregion

                    network_devices.append(self.Info(vendor=vendor, os=os, mac_address=mac_address,
                                                     ipv4_address=ipv4_address, ports=ports))
                except AssertionError:
                    pass

            remove(self._nmap_scan_result)
            assert len(network_devices) != 0, \
                'Could not find any devices on interface: ' + self._base.error_text(self._your['network-interface'])
            return network_devices

        except OSError:
            self._base.print_error('Something went wrong while trying to run ', 'nmap')
            if exit_on_failure:
                exit(2)

        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            if exit_on_failure:
                exit(1)

        return None
    # endregion

# endregion
