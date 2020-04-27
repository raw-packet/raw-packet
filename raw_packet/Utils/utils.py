from raw_packet.Utils.base import Base
from raw_packet.Scanners.arp_scanner import ArpScan
from typing import List, Dict, Union
from prettytable import PrettyTable


class Utils:

    base: Base = Base()

    def set_ipv4_target(self,
                        network_interface: str,
                        target_ipv4_address: Union[None, str] = None,
                        target_mac_address: Union[None, str] = None,
                        target_vendor: Union[None, str] = None,
                        target_ipv4_address_required: bool = False,
                        exclude_ipv4_addresses: List[str] = []) -> Dict[str, str]:
        target: Dict[str, str] = dict()
        arp_scan: ArpScan = ArpScan(network_interface=network_interface)
        network_interface_settings = self.base.get_interface_settings(interface_name=network_interface)
        first_ip_address: str = network_interface_settings['first-ipv4-address']
        last_ip_address: str = network_interface_settings['last-ipv4-address']

        if target_ipv4_address is not None:
            assert self.base.ip_address_in_range(ip_address=target_ipv4_address,
                                                 first_ip_address=first_ip_address,
                                                 last_ip_address=last_ip_address), \
                'Bad target IPv4 address: ' + self.base.error_text(target_ipv4_address) + \
                '; IPv4 address must be in range: ' + self.base.info_text(first_ip_address + ' - ' + last_ip_address)
            target['ipv4-address'] = target_ipv4_address
        else:
            assert not target_ipv4_address_required, 'Please set target IPv4 address!'
            self.base.print_info('Start ARP scan ...')
            results: List[Dict[str, str]] = arp_scan.scan(timeout=3, retry=3,
                                                          target_ip_address=None, check_vendor=True,
                                                          exclude_ip_addresses=exclude_ipv4_addresses,
                                                          exit_on_failure=True,
                                                          show_scan_percentage=True)
            if len(results) == 1:
                target['ipv4-address'] = results[0]['ip-address']
                target['mac-address'] = results[0]['mac-address']
                target['vendor'] = results[0]['vendor']
                return target
            else:
                self.base.print_success('Found ', str(len(results)), ' alive hosts on interface: ', network_interface)
                hosts_pretty_table: PrettyTable = PrettyTable([self.base.cINFO + 'Index' + self.base.cEND,
                                                               self.base.cINFO + 'IP address' + self.base.cEND,
                                                               self.base.cINFO + 'MAC address' + self.base.cEND,
                                                               self.base.cINFO + 'Vendor' + self.base.cEND])
                device_index: int = 1
                for device in results:
                    hosts_pretty_table.add_row([str(device_index), device['ip-address'],
                                                device['mac-address'], device['vendor']])
                    device_index += 1

                print(hosts_pretty_table)
                device_index -= 1
                current_device_index = input(self.base.c_info + 'Set device index from range (1-' +
                                             str(device_index) + '): ')

                if not current_device_index.isdigit():
                    self.base.print_error('Your input data: ' + str(current_device_index) + ' is not digit!')
                    exit(1)

                if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                    self.base.print_error('Your number is not within range (1-' + str(device_index) + ')')
                    exit(1)

                current_device_index = int(current_device_index) - 1
                device: Dict[str, str] = results[current_device_index]
                target['ipv4-address'] = device['ip-address']
                target['mac-address'] = device['mac-address']
                target['vendor'] = device['vendor']
                return target

        if target_mac_address is None:
            self.base.print_info('Find MAC address of device with IP address: ', target['ipv4-address'], ' ...')
            target['mac-address'] = arp_scan.get_mac_address(target_ip_address=target['ipv4-address'],
                                                             exit_on_failure=True,
                                                             show_scan_percentage=False)
        else:
            assert self.base.mac_address_validation(target_mac_address), \
                'Bad target MAC address: ' + self.base.error_text(target_mac_address) + \
                '; example MAC address: ' + self.base.info_text('12:34:56:78:90:ab')
            target['mac-address'] = target_mac_address

        return target
