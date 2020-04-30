# region Description
"""
utils.py: Script utils
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Scanners.scanner import Scanner
from typing import List, Dict, Union
from prettytable import PrettyTable
from re import search, IGNORECASE
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


# region class Utils
class Utils:

    # region Variables
    _base: Base = Base()
    # endregion

    # region Set Target MAC- and IPv4-address
    def set_ipv4_target(self,
                        network_interface: str,
                        target_ipv4_address: Union[None, str] = None,
                        target_mac_address: Union[None, str] = None,
                        target_vendor: Union[None, str] = None,
                        target_ipv4_address_required: bool = False,
                        exclude_ipv4_addresses: List[str] = []) -> Dict[str, str]:

        # region Variables
        target: Dict[str, str] = {'mac-address': None, 'ipv6-address': None, 'vendor': None}
        arp_scan: ArpScan = ArpScan(network_interface=network_interface)
        # endregion

        # region Target IPv4 address is Set
        if target_ipv4_address is not None:
            target['ipv4-address'] = self.check_local_ipv4_address(network_interface=network_interface,
                                                                   ipv4_address=target_ipv4_address,
                                                                   parameter_name='target IPv4 address')
        # endregion

        # region Target IPv4 address not Set
        else:
            assert not target_ipv4_address_required, 'Please set target IPv4 address!'
            self._base.print_info('Start ARP scan ...')
            results: List[Dict[str, str]] = arp_scan.scan(timeout=3, retry=3,
                                                          target_ip_address=None, check_vendor=True,
                                                          exclude_ip_addresses=exclude_ipv4_addresses,
                                                          exit_on_failure=True,
                                                          show_scan_percentage=True)

            if target_vendor is not None:
                results_with_vendor: List[Dict[str, str]] = list()
                for result in results:
                    if search(target_vendor, result['vendor'], IGNORECASE):
                        results_with_vendor.append(result)
                results = results_with_vendor

            if len(results) == 1:
                target['ipv4-address'] = results[0]['ip-address']
                target['mac-address'] = results[0]['mac-address']
                target['vendor'] = results[0]['vendor']
                return target
            else:
                if target_vendor is not None:
                    self._base.print_success('Found ', str(len(results)), ' ' + target_vendor.capitalize() +
                                             ' devices on interface: ', network_interface)
                else:
                    self._base.print_success('Found ', str(len(results)), ' alive hosts on interface: ',
                                             network_interface)
                hosts_pretty_table: PrettyTable = PrettyTable([self._base.cINFO + 'Index' + self._base.cEND,
                                                               self._base.cINFO + 'IP address' + self._base.cEND,
                                                               self._base.cINFO + 'MAC address' + self._base.cEND,
                                                               self._base.cINFO + 'Vendor' + self._base.cEND])
                device_index: int = 1
                for device in results:
                    hosts_pretty_table.add_row([str(device_index), device['ip-address'],
                                                device['mac-address'], device['vendor']])
                    device_index += 1

                print(hosts_pretty_table)
                device_index -= 1
                print(self._base.c_info + 'Select target from range (1-' + str(device_index) + '): ', end='')
                current_device_index = input()

                if not current_device_index.isdigit():
                    self._base.print_error('Your input data: ' + str(current_device_index) + ' is not digit!')
                    exit(1)

                if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                    self._base.print_error('Your number is not within range (1-' + str(device_index) + ')')
                    exit(1)

                current_device_index = int(current_device_index) - 1
                device: Dict[str, str] = results[current_device_index]
                target['ipv4-address'] = device['ip-address']
                target['mac-address'] = device['mac-address']
                target['vendor'] = device['vendor']
                self._base.print_info('Your choose target: ',
                                      target['ipv4-address'] + ' (' +
                                      target['mac-address'] + ')')
                return target
        # endregion

        # region Target MAC address not Set
        if target_mac_address is None:
            self._base.print_info('Find MAC address of device with IP address: ', target['ipv4-address'], ' ...')
            target['mac-address'] = arp_scan.get_mac_address(target_ip_address=target['ipv4-address'],
                                                             exit_on_failure=True,
                                                             show_scan_percentage=False)
        # endregion

        # region Target MAC address is Set
        else:
            assert self._base.mac_address_validation(target_mac_address), \
                'Bad target MAC address: ' + self._base.error_text(target_mac_address) + \
                '; example MAC address: ' + self._base.info_text('12:34:56:78:90:ab')
            target['mac-address'] = target_mac_address.lower()
        # endregion

        # region Return target
        return target
        # endregion

    # endregion

    # region Set Target MAC- and IPv6-address
    def set_ipv6_target(self,
                        network_interface: str,
                        target_ipv6_address: Union[None, str] = None,
                        target_mac_address: Union[None, str] = None,
                        target_vendor: Union[None, str] = None,
                        target_ipv6_address_is_local: bool = True,
                        exclude_ipv6_addresses: List[str] = []) -> Dict[str, str]:

        # region Variables
        target: Dict[str, str] = {'mac-address': None, 'ipv6-address': None, 'vendor': None}
        scanner: Scanner = Scanner(network_interface=network_interface)
        # endregion

        # region Target MAC address is Set
        if target_mac_address is not None:
            target['mac-address'] = self.check_mac_address(mac_address=target_mac_address,
                                                           parameter_name='target MAC address')
        # endregion

        # region Target IPv6 address not Set
        if target_ipv6_address is None:
            self._base.print_info('Search IPv6 alive hosts ....')
            ipv6_devices = scanner.find_ipv6_devices(network_interface=network_interface, timeout=3, retry=3,
                                                     exclude_ipv6_addresses=exclude_ipv6_addresses)
            # Target IPv6 and MAC address is not set
            if target['mac-address'] is None:
                target = scanner.ipv6_device_selection(ipv6_devices)
                target['ipv6-address'] = target['ip-address']
                target['mac-address'] = target['mac-address']
                return target

            # Target MAC address is set but target IPv6 is not set
            else:
                for ipv6_device in ipv6_devices:
                    if ipv6_device['mac-address'] == target['mac-address']:
                        target['ipv6-address'] = ipv6_device['ip-address']
                assert target['ipv6-address'] is not None, \
                    'Could not found IPv6 device with MAC address: ' + \
                    self._base.error_text(target['mac-address'])
                return target
        # endregion

        # region Target IPv6 address is Set
        else:
            assert target['mac-address'] is not None, \
                'Target IPv6 address is set: ' + \
                self._base.info_text(target_ipv6_address) + \
                '; Please set target MAC address'

            target['ipv6-address'] = self.check_ipv6_address(network_interface=network_interface,
                                                             ipv6_address=target_ipv6_address,
                                                             is_local_ipv6_address=target_ipv6_address_is_local,
                                                             parameter_name='target IPv6 address')
        # endregion

        # region Return target
        return target
        # endregion

    # endregion

    # region Check IPv4 address in local network
    def check_local_ipv4_address(self,
                                 network_interface: str,
                                 ipv4_address: str,
                                 parameter_name: str = 'target IPv4 address') -> str:
        network_interface_settings = \
            self._base.get_interface_settings(interface_name=network_interface,
                                              required_parameters=['first-ipv4-address',
                                                                   'last-ipv4-address'])
        first_ip_address: str = network_interface_settings['first-ipv4-address']
        last_ip_address: str = network_interface_settings['last-ipv4-address']
        assert self._base.ip_address_in_range(ipv4_address, first_ip_address, last_ip_address), \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(ipv4_address) + \
            '; ' + parameter_name.capitalize() + ' must be in range: ' + \
            self._base.info_text(first_ip_address + ' - ' + last_ip_address)
        return ipv4_address
    # endregion

    # region Check IPv6 address
    def check_ipv6_address(self,
                           network_interface: str,
                           ipv6_address: str,
                           is_local_ipv6_address: bool = True,
                           parameter_name: str = 'target IPv6 address') -> str:

        example_ipv6_address: str = '2001:4860:4860::8888'
        if is_local_ipv6_address:
            example_ipv6_address = 'fe80::1234:5678:90ab:cdef'

        network_interface_settings = \
            self._base.get_interface_settings(interface_name=network_interface,
                                              required_parameters=['mac-address'])

        if network_interface_settings['ipv6-link-address'] is None:
            network_interface_settings['ipv6-link-address'] = \
                self._base.make_ipv6_link_address(mac_address=network_interface_settings['mac-address'])

        assert ipv6_address != network_interface_settings['ipv6-link-address'], \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(ipv6_address) + \
            '; ' + parameter_name.capitalize() + ' is your link local IPv6 address!'

        assert ipv6_address not in network_interface_settings['ipv6-global-addresses'], \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(ipv6_address) + \
            '; ' + parameter_name.capitalize() + ' is your global IPv6 address!'

        assert self._base.ipv6_address_validation(ipv6_address), \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(ipv6_address) + \
            '; example IPv6 link local address: ' + self._base.info_text(example_ipv6_address)

        if is_local_ipv6_address:
            assert not str(ipv6_address).startswith('fe80::'), \
                'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(ipv6_address) + \
                '; example IPv6 link local address: ' + self._base.info_text(example_ipv6_address)

        return ipv6_address
    # endregion

    # region Check MAC address
    def check_mac_address(self,
                          mac_address: str,
                          parameter_name: str = 'target MAC address') -> str:
        assert self._base.mac_address_validation(mac_address), \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(mac_address) + \
            '; example MAC address: ' + self._base.info_text('12:34:56:78:90:ab')
        return str(mac_address).lower()
    # endregion

    # region Check value in range
    def check_value_in_range(self, value: int,
                             first_value: int = 1,
                             last_value: int = 65535,
                             parameter_name: str = 'destination port') -> int:
        assert first_value < value < last_value, \
            'Bad ' + parameter_name.capitalize() + ': ' + self._base.error_text(str(value)) + \
            ' ' + parameter_name.capitalize() + ' must be in range: ' + \
            self._base.info_text(str(first_value) + ' - ' + str(last_value))
        return value
    # endregion

# endregion
