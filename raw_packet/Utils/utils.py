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
        target: Dict[str, str] = dict()
        arp_scan: ArpScan = ArpScan(network_interface=network_interface)
        network_interface_settings = self._base.get_interface_settings(interface_name=network_interface)
        first_ip_address: str = network_interface_settings['first-ipv4-address']
        last_ip_address: str = network_interface_settings['last-ipv4-address']
        # endregion

        # region Target IPv4 address is Set
        if target_ipv4_address is not None:
            assert self._base.ip_address_in_range(ip_address=target_ipv4_address,
                                                  first_ip_address=first_ip_address,
                                                  last_ip_address=last_ip_address), \
                'Bad target IPv4 address: ' + self._base.error_text(target_ipv4_address) + \
                '; IPv4 address must be in range: ' + self._base.info_text(first_ip_address + ' - ' + last_ip_address)
            target['ipv4-address'] = target_ipv4_address
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
            target['mac-address'] = target_mac_address
        # endregion

        return target
    # endregion

# endregion
