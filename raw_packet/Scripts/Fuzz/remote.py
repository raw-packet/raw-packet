# region Description
"""
remote.py: Remote Test for fuzzers (remote)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from time import sleep
from typing import Union, List, Any
from dataclasses import dataclass
from re import compile, sub
from paramiko import SSHClient, RSAKey, ssh_exception, AutoAddPolicy
from pathlib import Path
from os.path import isfile
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
__script_name__ = 'Remote Test for fuzzers (remote)'
# endregion


# region class RemoteTest
class RemoteTest:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'MacOS', 'Windows'])
    _windows_mac_address_regex = compile(r'([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})')
    _ssh_client: Union[None, SSHClient] = None

    @dataclass
    class Settings:
        network_interface: Union[None, str] = None
        mac_address: Union[None, str] = None
        ipv4_address: Union[None, str] = None
        new_ipv4_address: Union[None, str] = None
        ipv6_address: Union[None, str] = None
        os: Union[None, str] = None
        ssh_user: Union[None, str] = None
        ssh_password: Union[None, str] = None
        ssh_private_key: Union[None, str] = None
    # endregion

    # region Init
    def __init__(self,
                 target: Settings,
                 test_parameters: Any,
                 gateway: Union[None, Settings] = None,
                 your: Union[None, Settings] = None):

        self._test_parameters = test_parameters
        self._target = target
        self._gateway = gateway
        self._your = your

        if self._gateway is not None:
            if self._target.os == 'MacOS':
                self._real_gateway_mac_address = self._base.macos_encode_mac_address(self._gateway.mac_address)
            else:
                self._real_gateway_mac_address = self._gateway.mac_address
        else:
            self._real_gateway_mac_address = None

        if not self._connect_to_ssh():
            exit(2)
    # endregion

    # region Connect to target over SSH
    def _connect_to_ssh(self) -> bool:
        """
        Connect to SSH server on target
        :return: True if success or False if error
        """

        _private_key: Union[None, RSAKey] = None
        self._ssh_client = SSHClient()
        self._ssh_client.set_missing_host_key_policy(AutoAddPolicy)

        if self._target.ssh_password is None:
            _private_key_file: str = str(Path.home()) + '/.ssh/id_rsa'
            if self._target.ssh_private_key is not None:
                _private_key_file = self._target.ssh_private_key

            assert isfile(_private_key_file), \
                'Could not found file with private SSH key: ' + self._base.error_text(_private_key_file)

            try:
                _private_key = RSAKey.from_private_key_file(_private_key_file)
            except ssh_exception.SSHException:
                self._base.print_error('Paramiko exception: private SSH key from file: ',
                                       _private_key_file, ' is not a valid format')
                return False

        try:
            if self._target.ssh_password is not None:
                self._ssh_client.connect(hostname=self._target.ipv4_address,
                                         username=self._target.ssh_user,
                                         password=self._target.ssh_password)
            if _private_key is not None:
                self._ssh_client.connect(hostname=self._target.ipv4_address,
                                         username=self._target.ssh_user,
                                         pkey=_private_key)

        except ssh_exception.AuthenticationException:
            self._base.print_error('SSH Authentication error to host: ',
                                   self._target.ssh_user + '@' + self._target.ipv4_address)
            return False

        return True
    # endregion

    # region Start tshark over ssh
    def start_tshark_over_ssh(self) -> bool:
        """
        Start tshark over ssh
        :return: True if success or False if error
        """
        if self._target.os == 'Linux' or self._target.os == 'MacOS':
            start_tshark_command: str = 'rm -f /tmp/dhcp.pcap; tshark -i ' + \
                                        self._target.network_interface + \
                                        ' -w /tmp/dhcp.pcap -f "ether src ' + \
                                        self._your.mac_address + '"'
        else:
            start_tshark_command: str = 'cd C:\Windows\Temp && del /f dhcp.pcap && tshark -i ' + \
                                        self._target.network_interface + \
                                        ' -w dhcp.pcap -f "ether src ' + \
                                        self._your.mac_address + '"'
        try:
            self._ssh_client.exec_command(start_tshark_command)
            return True
        except ssh_exception:
            return False
    # endregion

    # region Stop tshark over ssh
    def stop_tshark_over_ssh(self) -> bool:
        """
        Stop tshark over ssh
        :return: True if success or False if error
        """
        if self._target.os == 'Linux' or self._target.os == 'MacOS':
            stop_tshark_command: str = 'pkill tshark'
        else:
            stop_tshark_command: str = 'taskkill /IM "tshark.exe" /F'

        try:
            self._ssh_client.exec_command(stop_tshark_command)
            return True
        except ssh_exception:
            return False
    # endregion

    # region Start DHCP client over ssh
    def dhcp_client_over_ssh(self) -> bool:
        """
        Start DHCPv4 client over ssh
        :return: True if success or False if error
        """
        if self._target.os == 'MacOS':
            dhcp_client_command: str = 'ipconfig set ' + self._target.network_interface + ' DHCP'
        elif self._target.os == 'Linux':
            dhcp_client_command: str = 'rm -f /var/lib/dhcp/dhclient.leases; dhclient ' + self._target.network_interface
        else:
            dhcp_client_command: str = 'ipconfig /release && ipconfig /renew'

        try:
            self._ssh_client.exec_command(dhcp_client_command)
            return True
        except ssh_exception:
            return False
    # endregion

    # region Get address of IPv4 gateway over ssh
    def get_ipv4_gateway_over_ssh(self) -> Union[None, str]:
        """
        Get IPv4 gateway address over SSH
        :return: IPv4 gateway address or None if error
        """
        gateway_ipv4_address: Union[None, str] = None
        try:
            if self._target.os == 'MacOS':
                route_table_command: str = 'netstat -nr | grep default | grep ' + self._target.network_interface + \
                                           ' | awk \'{print $2}\''
            elif self._target.os == 'Linux':
                route_table_command: str = 'route -n | grep UG | grep ' + self._target.network_interface + \
                                           ' | awk \'{print $2}\''
            else:
                route_table_command: str = 'ipconfig | findstr /i "Gateway"'

            stdin, stdout, stderr = self._ssh_client.exec_command(route_table_command)
            route_table: bytes = stdout.read()
            route_table_result: str = route_table.decode('utf-8')

            if self._target.os == 'Windows':
                route_table_result: str = route_table_result.replace(' .', '').replace(' :', '')
                route_table_result: str = sub(r' +', ' ', route_table_result)
                route_table_result: List[str] = route_table_result.split()
                route_table_result: str = route_table_result[2]

            assert self._base.ip_address_validation(route_table_result), \
                'Bad IPv4 address: ' + self._base.error_text(route_table_result)
            # assert self._base.ip_address_in_range(route_table_result, first_ip_address, last_ip_address), \
            #     'Router IPv4 address: ' + self._base.error_text(route_table_result) + \
            #     ' not in range: ' + self._base.info_text(first_ip_address + ' - ' + last_ip_address)
            return route_table_result.rstrip()

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            return gateway_ipv4_address

        except IndexError:
            return gateway_ipv4_address

    # endregion

    # region Get MAC address of IPv4 gateway over ssh
    def get_ipv4_gateway_mac_address_over_ssh(self) -> Union[None, str]:
        """
        Get MAC address of IPv4 gateway in target host over SSH
        :return: None if error or MAC address string
        """
        gateway_mac_address: Union[None, str] = None
        try:
            if self._target.os == 'Windows':
                arp_table_command: str = 'arp -a | findstr ' + self._gateway.ipv4_address
            else:
                arp_table_command: str = 'arp -an | grep ' + self._gateway.ipv4_address

            stdin, stdout, stderr = self._ssh_client.exec_command(arp_table_command)
            arp_table: bytes = stdout.read()
            arp_table: str = arp_table.decode('utf-8')

            assert 'No route to host' not in arp_table, \
                'No route to host' + self._base.error_text(self._target.ipv4_address)
            assert arp_table != '', \
                'Not found host: ' + self._base.error_text(self._gateway.ipv4_address) + \
                ' in ARP table in host: ' + self._base.error_text(self._target.ipv4_address)

            if self._target.os == 'Windows':
                assert self._windows_mac_address_regex.search(arp_table), \
                    'Not found host: ' + self._base.error_text(self._gateway.ipv4_address) + \
                    ' in ARP table in host: ' + self._base.error_text(self._target.ipv4_address)
                mac_address = self._windows_mac_address_regex.search(arp_table)
                return mac_address.group(1).replace('-', ':').lower()

            else:
                target_arp_table: List[str] = arp_table.split(' ')
                if self._target.os == 'Linux':
                    assert self._base.mac_address_validation(target_arp_table[3]), \
                        'Invalid MAC address: ' + self._base.error_text(target_arp_table[3])
                return target_arp_table[3]

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            return gateway_mac_address

        except IndexError:
            return gateway_mac_address

    # endregion

    # region Update ARP table over ssh
    def update_ipv4_gateway_mac_address_over_ssh(self) -> bool:
        """
        Update ARP table on target host over SSH after spoofing
        :return: True if MAC address is changed or False if error
        """
        self._ssh_client.exec_command('arp -d ' + self._gateway.ipv4_address)

        if self._target.os == 'MacOS' or self._target.os == 'Linux':
            self._ssh_client.exec_command('ping -c 1 ' + self._gateway.ipv4_address)
        else:
            self._ssh_client.exec_command('ping -n 1 ' + self._gateway.ipv4_address)

        current_gateway_mac_address = self.get_ipv4_gateway_mac_address_over_ssh()

        if current_gateway_mac_address == self._real_gateway_mac_address:
            return True
        else:
            return False

    # endregion

    # region Check MAC address of IPv4 gateway over ssh
    def check_ipv4_gateway_mac_address_over_ssh(self, test_parameters_index: int = 0) -> None:
        """
        Check MAC address of IPv4 gateway in target host over SSH
        :param test_parameters_index: Index of current test
        :return: None
        """
        current_gateway_mac_address = self.get_ipv4_gateway_mac_address_over_ssh()

        # region Disconnect
        if current_gateway_mac_address is None:
            self._base.print_warning('index: ', str(test_parameters_index),
                                     ' parameters: ', str(self._test_parameters[test_parameters_index].__dict__))
            with open('disconnect_packets.txt', 'a') as result_file:
                result_file.write('index: ' + str(test_parameters_index) +
                                  ' parameters: ' + str(self._test_parameters[test_parameters_index].__dict__) + '\n')
            sleep(5)
            self.check_ipv4_gateway_mac_address_over_ssh()
        # endregion

        # region Gateway MAC address is not change
        if current_gateway_mac_address == self._real_gateway_mac_address:
            self._base.print_info('index: ', str(test_parameters_index),
                                  ' gateway: ', current_gateway_mac_address,
                                  ' parameters: ', str(self._test_parameters[test_parameters_index].__dict__))
        # endregion

        # region Gateway MAC address is changed (Spoofing sucsess)
        else:
            self._base.print_success('index: ', str(test_parameters_index),
                                     ' gateway: ', current_gateway_mac_address,
                                     ' parameters: ', str(self._test_parameters[test_parameters_index].__dict__))
            with open('mitm_packets.txt', 'a') as result_file:
                result_file.write('index: ' + str(test_parameters_index) +
                                  ' gateway: ' + current_gateway_mac_address +
                                  ' parameters: ' + str(self._test_parameters[test_parameters_index].__dict__) + '\n')

            while True:
                if self.update_ipv4_gateway_mac_address_over_ssh():
                    break
                else:
                    sleep(1)
        # endregion

    # endregion

# endregion
