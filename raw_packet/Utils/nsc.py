# region Description
"""
nsc.py: Network Security Check (nsc)
        Checking network security mechanisms such as: Dynamic ARP Inspection, DHCP snooping, etc.
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawSend, RawARP, RawICMPv4, RawICMPv6, RawDHCPv4, RawDHCPv6
from os.path import join
from typing import Union, Dict, List
from paramiko import RSAKey, SSHException
from pathlib import Path
from os.path import isfile
from os import remove
from subprocess import run, Popen, check_output, PIPE, STDOUT
from scapy.all import rdpcap, Ether, Dot3, LLC, STP, ARP, IP, UDP, BOOTP, DHCP, ICMP, IPv6
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect
from scapy.all import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
from time import sleep
from random import randint
from re import findall, MULTILINE
from time import time
from sys import stdout
from getmac import get_mac_address
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


# region class NetworkSecurityCheck
class NetworkSecurityCheck:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    _utils: Utils = Utils()
    _arp: RawARP = RawARP()
    _icmpv4: RawICMPv4 = RawICMPv4()
    _icmpv6: RawICMPv6 = RawICMPv6()
    _dhcpv4: RawDHCPv4 = RawDHCPv4()
    _dhcpv6: RawDHCPv6 = RawDHCPv6()
    # endregion

    def check(self,
              send_interface: str,
              listen_interface: Union[None, str] = None,
              gateway_ipv4_address: Union[None, str] = None,
              gateway_mac_address: Union[None, str] = None,
              test_host_os: str = 'Linux',
              test_host_interface: Union[None, str] = None,
              test_host_ipv4_address: Union[None, str] = None,
              test_host_mac_address: Union[None, str] = None,
              test_host_ssh_user: str = 'root',
              test_host_ssh_pass: Union[None, str] = None,
              test_host_ssh_pkey: Union[None, str] = None,
              number_of_packets: int = 10,
              listen_time: int = 10,
              quiet: bool = False) -> Dict[str, Union[bool, List[str]]]:
        """
        Check network security mechanisms
        :param send_interface: Network interface name for send spoofing packets (example: 'eth0')
        :param listen_interface: Network interface name for listen spoofing packets (example: 'eth1')
        :param gateway_ipv4_address: Gateway IPv4 address (example: '192.168.0.254')
        :param gateway_mac_address: Gateway MAC address (example: '12:34:56:78:90:ab')
        :param test_host_os: Test host OS for ssh connection (default: 'Linux')
        :param test_host_interface: Network interface name on test host for listen spoofing packets (example: 'eth0')
        :param test_host_ipv4_address: Test host IPv4 address for ssh connection (example: '192.168.0.123')
        :param test_host_mac_address: Test host MAC address for ssh connection (example: '12:34:56:78:90:ac')
        :param test_host_ssh_user: Test host user name for ssh connection (default: 'root')
        :param test_host_ssh_pass: Test host password for ssh connection (example: '12345678')
        :param test_host_ssh_pkey: SSH Private key file path for ssh connection to test host (example: '/root/.ssh/id_rsa')
        :param number_of_packets: Number of spoofing packets for each test (default: 10)
        :param listen_time: Time to listen spoofing packets in seconds (default: 60)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Result dictionary (example: {'ARP protection': True,
                                              'ICMPv4 Redirect protection': True,
                                              'DHCPv4 protection': True,
                                              'ICMPv6 Redirect protection': True,
                                              'ICMPv6 Router Advertisement protection': True,
                                              'ICMPv6 Neighbor Advertisement protection': True,
                                              'DHCPv6 protection': True,
                                              'Sniff STP packets from': [192.168.0.1]})
        """

        # region Variables
        network_security_mechanisms: Dict[str, Union[bool, List[str]]] = {
            'ARP protection': True,
            'ICMPv4 Redirect protection': True,
            'DHCPv4 protection': True,
            'ICMPv6 Redirect protection': True,
            'ICMPv6 Router Advertisement protection': True,
            'ICMPv6 Neighbor Advertisement protection': True,
            'DHCPv6 protection': True,
            'STP packets': list()
        }

        your_platform: str = self._base.get_platform()
        listen_network_interface: Union[None, str] = None
        test_interface_ipv4_address: Union[None, str] = None

        test_mac_address: Union[None, str] = None
        test_ipv4_address: Union[None, str] = None
        test_ipv6_address: Union[None, str] = None
        test_interface: Union[None, str] = None
        test_os: Union[None, str] = None

        ssh_user: Union[None, str] = None
        ssh_password: Union[None, str] = None
        ssh_private_key: Union[None, RSAKey] = None

        local_pcap_file: Union[None, str] = None
        remote_pcap_file: Union[None, str] = None
        # endregion

        try:

            # region Get network interface for send spoofing packets, your IP and MAC address
            list_of_network_interfaces: List[str] = self._base.list_of_network_interfaces()

            assert send_interface in list_of_network_interfaces, \
                'Network interface for send spoofing packets: ' + \
                self._base.error_text(send_interface) + ' does not exist!'

            send_network_interface = send_interface
            list_of_network_interfaces.remove(send_network_interface)

            send_network_interface_settings: Dict = \
                self._base.get_interface_settings(interface_name=send_network_interface,
                                                  required_parameters=['mac-address',
                                                                       'ipv4-address',
                                                                       'first-ipv4-address',
                                                                       'last-ipv4-address',
                                                                       'ipv4-network'])
            raw_send: RawSend = RawSend(network_interface=send_network_interface)
            your_mac_address: str = send_network_interface_settings['mac-address']
            your_ipv4_address: str = send_network_interface_settings['ipv4-address']
            if send_network_interface_settings['ipv6-link-address'] is None:
                your_ipv6_address = self._base.make_ipv6_link_address(your_mac_address)
            else:
                your_ipv6_address = send_network_interface_settings['ipv6-link-address']
            your_ipv4_network: str = send_network_interface_settings['ipv4-network']
            # endregion

            # region Set local_pcap_file variable
            if your_platform.startswith('Windows'):
                local_temp_directory: bytes = check_output('echo %temp%', shell=True)
                local_temp_directory: str = local_temp_directory.decode().splitlines()[0]
                local_pcap_file: str = join(local_temp_directory, 'spoofing.pcap')
            else:
                local_pcap_file: str = '/tmp/spoofing.pcap'
            if isfile(local_pcap_file):
                remove(local_pcap_file)
            # endregion

            # region Check gateway IP and MAC address
            if gateway_ipv4_address is not None:
                gateway_ipv4_address: str = \
                    self._utils.check_ipv4_address(network_interface=send_network_interface,
                                                   ipv4_address=gateway_ipv4_address,
                                                   is_local_ipv4_address=True,
                                                   parameter_name='gateway IPv4 address')
            else:
                gateway_ipv4_address: str = \
                    self._base.get_interface_gateway(interface_name=send_network_interface,
                                                     exit_on_failure=True)
            scan_gateway_mac_address: str = get_mac_address(ip=gateway_ipv4_address, network_request=True)
            # scan_gateway_mac_address: str = arp_scan.get_mac_address(target_ip_address=gateway_ipv4_address,
            #                                                          exit_on_failure=True,
            #                                                          show_scan_percentage=False)
            if gateway_mac_address is not None:
                self._utils.check_mac_address(mac_address=gateway_mac_address,
                                              parameter_name='gateway MAC address')
                assert gateway_mac_address == scan_gateway_mac_address, \
                    'Gateway MAC address in argument: ' + self._base.error_text(gateway_mac_address) + \
                    ' is not real gateway MAC address: ' + self._base.info_text(scan_gateway_mac_address)
            gateway_mac_address: str = scan_gateway_mac_address
            gateway_ipv6_address: str = self._base.make_ipv6_link_address(gateway_mac_address)
            # endregion

            # region Set listen interface or test host
            if listen_interface is None and test_host_ipv4_address is None:

                # region Make list of available network interfaces
                if len(list_of_network_interfaces) > 0:
                    for test_interface in list_of_network_interfaces:
                        # Check IPv4 address for all available network interfaces
                        test_interface_ipv4_address = \
                            self._base.get_interface_ip_address(interface_name=test_interface,
                                                                exit_on_failure=False, quiet=True)
                        # IPv4 address of test network interface in your IPv4 network
                        # Set this interface as Listen network interface
                        if self._base.ip_address_in_network(test_interface_ipv4_address, your_ipv4_network):
                            listen_network_interface = test_interface
                            break
                # endregion

                # region Not found network interface with IP address in test network
                # set test host IP address for SSH connection
                assert listen_network_interface is not None, \
                    'Please set test host IP address!'
                # endregion

                # region Found network interface with IP address in test network
                while test_ipv4_address is None:
                    print(self._base.c_info + 'Use network interface: ' +
                          self._base.info_text(listen_network_interface + ' (' +
                                               test_interface_ipv4_address + ')') +
                          ' for listen traffic [Yes|No]: ', end='')
                    use_listen_interface = input()
                    if use_listen_interface == 'No' or use_listen_interface == 'N':
                        while True:
                            print(self._base.c_info + 'Please set test host IP address for SSH connect: ')
                            test_ipv4_address = input()
                            if self._base.ip_address_in_network(test_ipv4_address, your_ipv4_network):
                                break
                            else:
                                self._base.print_error('Test host IP address: ',
                                                       test_ipv4_address, ' not in network: ' +
                                                       self._base.info_text(your_ipv4_network))
                    elif use_listen_interface == 'Yes' or use_listen_interface == 'Y':
                        break
                    else:
                        self._base.print_error('Unknown answer: ', use_listen_interface,
                                               ' please use answer "Yes" or "No"')
                # endregion

            # endregion

            # region Check test host
            if test_host_ipv4_address is not None or test_ipv4_address is not None:

                # region Check test host IP and MAC address
                if test_ipv4_address is not None and test_mac_address is not None:
                    test_mac_address = self._utils.check_mac_address(mac_address=test_mac_address,
                                                                     parameter_name='test host MAC address')
                    test_ipv6_address = self._base.make_ipv6_link_address(test_mac_address)
                else:
                    if test_host_ipv4_address is not None:
                        test_ipv4_address = \
                            self._utils.check_ipv4_address(network_interface=send_network_interface,
                                                           ipv4_address=test_host_ipv4_address,
                                                           is_local_ipv4_address=True,
                                                           parameter_name='test host IPv4 address')
                    scan_test_mac_address: str = get_mac_address(ip=test_ipv4_address, network_request=True)
                    # scan_test_mac_address: str = arp_scan.get_mac_address(target_ip_address=test_ipv4_address,
                    #                                                       exit_on_failure=True,
                    #                                                       show_scan_percentage=False)
                    if test_host_mac_address is not None:
                        self._utils.check_mac_address(mac_address=test_host_mac_address,
                                                      parameter_name='test host MAC address')
                        assert test_host_mac_address == scan_test_mac_address, \
                            'Test host MAC address in argument: ' + self._base.error_text(test_host_mac_address) + \
                            ' is not real test host MAC address: ' + self._base.info_text(scan_test_mac_address)
                    test_mac_address = scan_test_mac_address
                    test_ipv6_address = self._base.make_ipv6_link_address(test_mac_address)
                # endregion

                # region Check test host SSH user, password and private key
                ssh_user = test_host_ssh_user
                ssh_password = test_host_ssh_pass
                ssh_private_key = None
                test_os = str(test_host_os).lower()

                if test_host_ssh_pkey is None and ssh_password is None:
                    default_ssh_private_key_file: str = join(str(Path.home()), '.ssh', 'id_rsa')
                    assert isfile(default_ssh_private_key_file), \
                        'Could not found private SSH key: ' + self._base.error_text(default_ssh_private_key_file)
                    try:
                        ssh_private_key = RSAKey.from_private_key_file(default_ssh_private_key_file)
                    except SSHException as Error:
                        self._base.print_error('Paramiko SSH exception: ', Error.args[0])
                        self._base.print_error('Private SSH key file: ', default_ssh_private_key_file)
                        exit(2)

                if test_host_ssh_pkey is not None:
                    try:
                        ssh_private_key = RSAKey.from_private_key_file(test_host_ssh_pkey)
                    except SSHException as Error:
                        self._base.print_error('Paramiko SSH exception: ', Error.args[0])
                        self._base.print_error('Private SSH key file: ', test_host_ssh_pkey)
                        exit(2)

                assert ssh_private_key is not None or ssh_password is not None, \
                    'Password and private key file for SSH is None!' + \
                    ' Please set SSH password: ' + self._base.info_text('--test_ssh_pass <ssh_password>') + \
                    ' or SSH private key file: ' + self._base.info_text('--test_ssh_pkey <ssh_private_key_path>')

                if test_os == 'linux' or test_os == 'macos':
                    command: str = 'ifconfig'
                else:
                    command: str = 'netsh interface show interface'
                test_host_network_interfaces: str = \
                    self._base.exec_command_over_ssh(command=command,
                                                     ssh_user=ssh_user,
                                                     ssh_password=ssh_password,
                                                     ssh_pkey=ssh_private_key,
                                                     ssh_host=test_ipv4_address)

                if test_os == 'linux' or test_os == 'macos':
                    test_host_network_interfaces_list = findall(r'^([a-zA-Z0-9]{2,32})\:\ ',
                                                                test_host_network_interfaces,
                                                                MULTILINE)
                else:
                    test_host_network_interfaces_list = test_host_network_interfaces.split()

                if test_host_interface is None:
                    self._base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)
                    test_interface = input('Please set network interface on test host: ')
                else:
                    test_interface = test_host_interface
                    if test_interface not in test_host_network_interfaces_list:
                        self._base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)

                while True:
                    if test_interface not in test_host_network_interfaces_list:
                        self._base.print_warning('Network interface: ', test_interface,
                                                 ' not in network interfaces list on test host')
                        test_interface = input('Please set network interface on test host: ')
                    else:
                        break
                # endregion

            # endregion

            # region Check listen network interface
            if (listen_interface is not None or listen_network_interface is not None) and test_ipv4_address is None:
                if listen_interface is not None:
                    assert listen_interface in list_of_network_interfaces, \
                        'Network interface: ' + self._base.error_text(listen_interface) + \
                        ' not in available network interfaces list: ' + \
                        self._base.info_text(str(list_of_network_interfaces))
                    _test_ipv4_address = self._base.get_interface_ip_address(listen_interface)
                    assert _test_ipv4_address is not None, \
                        'Listen network interface: ' + self._base.error_text(listen_interface) + \
                        ' does not have IPv4 address!'
                    assert self._base.ip_address_in_network(_test_ipv4_address, your_ipv4_network), \
                        'IPv4 address: ' + self._base.error_text(_test_ipv4_address) + \
                        ' of Listen network interface: ' + self._base.error_text(listen_interface) + \
                        ' not in your IPv4 network: ' + self._base.info_text(your_ipv4_network)
                    listen_network_interface = listen_interface
                test_ipv4_address = self._base.get_interface_ip_address(listen_network_interface)
                test_mac_address = self._base.get_interface_mac_address(listen_network_interface)
                test_ipv6_address = self._base.get_interface_ipv6_link_address(listen_network_interface, False)
                if test_ipv6_address is None:
                    test_ipv6_address = self._base.make_ipv6_link_address(test_mac_address)
                test_interface = listen_network_interface
                
                if your_platform.startswith('Windows'):
                    test_os = 'windows'
                elif your_platform.startswith('Linux'):
                    test_os = 'linux'
                elif your_platform.startswith('Darwin'):
                    test_os = 'macos'
                else:
                    assert False, 'Your platform: ' + self._base.info_text(your_platform) + ' is not supported!'
            # endregion

            # region Output
            if not quiet:
                self._base.print_info('Send network interface: ', send_network_interface)
                self._base.print_info('Send network interface IPv4 address: ', your_ipv4_address)
                self._base.print_info('Send network interface IPv4 address: ', your_ipv6_address)
                self._base.print_info('Send network interface MAC address: ', your_mac_address)

                if listen_network_interface is not None:
                    self._base.print_info('Listen network interface: ', listen_network_interface)
                    self._base.print_info('Listen network interface IPv4 address: ', test_ipv4_address)
                    self._base.print_info('Listen network interface IPv6 address: ', test_ipv6_address)
                    self._base.print_info('Listen network interface MAC address: ', test_mac_address)

                if ssh_user is not None:
                    self._base.print_info('Test host IPv4 address: ', test_ipv4_address)
                    self._base.print_info('Test host IPv6 address: ', test_ipv6_address)
                    self._base.print_info('Test host MAC address: ', test_mac_address)
                    self._base.print_info('Test host OS: ', test_os)
                    self._base.print_info('Test host network interface: ', test_interface)

                self._base.print_info('Gateway IPv4 address: ', gateway_ipv4_address)
                self._base.print_info('Gateway IPv6 address: ', gateway_ipv6_address)
                self._base.print_info('Gateway MAC address: ', gateway_mac_address)
            # endregion

            # region Start dump traffic
            
            # region Set dump traffic command
            if test_os == 'linux' or test_os == 'macos':
                dumpcap_command = 'tcpdump'
                start_dumpcap_command: str = \
                    dumpcap_command + \
                    ' -i "' + test_interface + '"' + \
                    ' -w "__pcap_file__"' + \
                    ' "stp or ether src ' + your_mac_address + '" >/dev/null 2>&1'
            else:
                dumpcap_command = '"C:\\Program Files\\Wireshark\\dumpcap.exe"'
                start_dumpcap_command: str = \
                    dumpcap_command + \
                    ' -i "' + test_interface + '"' + \
                    ' -w "__pcap_file__"' + \
                    ' -f "stp or ether src ' + your_mac_address + '"'
            # endregion
            
            # region Remote dump traffic
            if ssh_user is not None:
                if not quiet:
                    self._base.print_info('Start dump traffic on test host: ', test_ipv4_address)

                # region Linux or MacOS
                if test_os == 'linux' or test_os == 'macos':
                    remote_pcap_file = '/tmp/spoofing.pcap'
                    start_dumpcap_command = start_dumpcap_command.replace('__pcap_file__', remote_pcap_file)
                    start_dumpcap_retry: int = 1
                    while self._base.exec_command_over_ssh(command='pgrep ' + dumpcap_command,
                                                           ssh_user=ssh_user,
                                                           ssh_password=ssh_password,
                                                           ssh_pkey=ssh_private_key,
                                                           ssh_host=test_ipv4_address) == '':
                        self._base.exec_command_over_ssh(command=start_dumpcap_command,
                                                         ssh_user=ssh_user,
                                                         ssh_password=ssh_password,
                                                         ssh_pkey=ssh_private_key,
                                                         ssh_host=test_ipv4_address,
                                                         need_output=False)
                        sleep(1)
                        start_dumpcap_retry += 1
                        if start_dumpcap_retry == 5:
                            self._base.print_error('Failed to start dump traffic on test host: ', test_ipv4_address)
                            exit(1)
                # endregion
                
                # region Windows
                else:
                    windows_temp_directory = self._base.exec_command_over_ssh(command='echo %temp%',
                                                                              ssh_user=ssh_user,
                                                                              ssh_password=ssh_password,
                                                                              ssh_pkey=ssh_private_key,
                                                                              ssh_host=test_ipv4_address)
                    assert windows_temp_directory is not None or windows_temp_directory != '', \
                        'Can not get variable %temp% on Windows host: ' + self._base.error_text(test_ipv4_address)
                    if windows_temp_directory.endswith('\n'):
                        windows_temp_directory = windows_temp_directory[:-1]
                    if windows_temp_directory.endswith('\r'):
                        windows_temp_directory = windows_temp_directory[:-1]
                    remote_pcap_file = windows_temp_directory + '\\spoofing.pcap'
                    start_dumpcap_command = start_dumpcap_command.replace('__pcap_file__', remote_pcap_file)
                    self._base.exec_command_over_ssh(command=start_dumpcap_command,
                                                     ssh_user=ssh_user,
                                                     ssh_password=ssh_password,
                                                     ssh_pkey=ssh_private_key,
                                                     ssh_host=test_ipv4_address,
                                                     need_output=False)
                # endregion
                
            # endregion
            
            # region Local dump traffic
            else:
                if not quiet:
                    self._base.print_info('Dump traffic on listen interface: ', listen_network_interface)
                start_dumpcap_command = start_dumpcap_command.replace('__pcap_file__', local_pcap_file)
                Popen(start_dumpcap_command, shell=True, stdout=PIPE, stderr=PIPE)
            # endregion
            
            start_time = time()
            sleep(3)

            # endregion

            # region Send ARP packets
            self._base.print_info('Send ARP packets to: ',
                                  test_ipv4_address + ' (' +
                                  test_mac_address + ')', ' ....')
            arp_packet: bytes = \
                self._arp.make_response(ethernet_src_mac=your_mac_address,
                                        ethernet_dst_mac=test_mac_address,
                                        sender_mac=your_mac_address,
                                        sender_ip=gateway_ipv4_address,
                                        target_mac=test_mac_address,
                                        target_ip=test_ipv4_address)
            raw_send.send_packet(packet=arp_packet, count=number_of_packets, delay=0.5)
            # endregion

            # region Send ICMPv4 packets
            self._base.print_info('Send ICMPv4 packets to: ',
                                  test_ipv4_address + ' (' +
                                  test_mac_address + ')', ' ....')
            icmpv4_packet: bytes = \
                self._icmpv4.make_redirect_packet(ethernet_src_mac=your_mac_address,
                                                  ethernet_dst_mac=test_mac_address,
                                                  ip_src=gateway_ipv4_address,
                                                  ip_dst=test_ipv4_address,
                                                  gateway_address=your_ipv4_address,
                                                  payload_ip_src=test_ipv4_address,
                                                  payload_ip_dst='8.8.8.8')
            raw_send.send_packet(packet=icmpv4_packet, count=number_of_packets, delay=0.5)
            # endregion

            # region Send DHCPv4 packets
            self._base.print_info('Send DHCPv4 packets to: ',
                                  test_ipv4_address + ' (' +
                                  test_mac_address + ')', ' ....')

            # region Make random DHCPv4 transactions
            dhcpv4_transactions: Dict[str, int] = {
                'discover': randint(0, 0xffffffff),
                'offer': randint(0, 0xffffffff),
                'request': randint(0, 0xffffffff),
                'ack': randint(0, 0xffffffff)
            }
            # endregion

            # region Make DHCPv4 Discover packet
            discover_packet: bytes = \
                self._dhcpv4.make_discover_packet(ethernet_src_mac=your_mac_address,
                                                  client_mac=your_mac_address,
                                                  transaction_id=dhcpv4_transactions['discover'])
            # endregion

            # region Make DHCPv4 Offer packet
            offer_packet: bytes = \
                self._dhcpv4.make_offer_packet(ethernet_src_mac=your_mac_address,
                                               ethernet_dst_mac=test_mac_address,
                                               ip_src=your_ipv4_address,
                                               ip_dst=test_ipv4_address,
                                               transaction_id=dhcpv4_transactions['offer'],
                                               your_client_ip=test_ipv4_address,
                                               client_mac=test_mac_address,
                                               dhcp_server_id=your_ipv4_address,
                                               router=your_ipv4_address,
                                               dns=your_ipv4_address)
            # endregion

            # region Make DHCPv4 Request packet
            request_packet: bytes = \
                self._dhcpv4.make_request_packet(ethernet_src_mac=your_mac_address,
                                                 client_mac=your_mac_address,
                                                 transaction_id=dhcpv4_transactions['request'])
            # endregion

            # region Make DHCPv4 ACK packet
            ack_packet: bytes = \
                self._dhcpv4.make_ack_packet(ethernet_src_mac=your_mac_address,
                                             ethernet_dst_mac=test_mac_address,
                                             ip_src=your_ipv4_address,
                                             ip_dst=test_ipv4_address,
                                             transaction_id=dhcpv4_transactions['ack'],
                                             your_client_ip=test_ipv4_address,
                                             client_mac=test_mac_address,
                                             dhcp_server_id=your_ipv4_address,
                                             router=your_ipv4_address,
                                             dns=your_ipv4_address)
            # endregion

            # region Send DHCPv4 packets
            raw_send.send_packets(packets=[discover_packet, offer_packet, request_packet, ack_packet],
                                  count=number_of_packets, delay=0.1)
            # endregion

            # endregion

            # region Send ICMPv6 packets
            self._base.print_info('Send ICMPv6 packets to: ',
                                  test_ipv6_address + ' (' +
                                  test_mac_address + ')', ' ....')

            # region Make ICMPv6 Redirect packet
            rd_packet: bytes = \
                self._icmpv6.make_redirect_packet(ethernet_src_mac=your_mac_address,
                                                  ethernet_dst_mac=test_mac_address,
                                                  original_router_ipv6_address=gateway_ipv6_address,
                                                  victim_address_ipv6_address=test_ipv6_address,
                                                  new_router_ipv6_address=your_ipv6_address,
                                                  new_router_mac_address=your_mac_address,
                                                  redirected_ipv6_address='2001:4860:4860::8888')
            # endregion

            # region Make ICMPv6 Router Solicitation packet
            rs_packet: bytes = \
                self._icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                        ethernet_dst_mac=test_mac_address,
                                                        ipv6_src=gateway_ipv6_address,
                                                        ipv6_dst='ff02::2')
            # endregion

            # region Make ICMPv6 Router Advertisement packet
            ra_packet: bytes = \
                self._icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                              ethernet_dst_mac=test_mac_address,
                                                              ipv6_src=gateway_ipv6_address,
                                                              ipv6_dst='ff02::1',
                                                              dns_address=your_ipv6_address,
                                                              prefix='fd00::/64')
            # endregion

            # region Make ICMPv6 Neighbor Solicitation packet
            ns_packet: bytes = \
                self._icmpv6.make_neighbor_solicitation_packet(ethernet_src_mac=your_mac_address,
                                                               ethernet_dst_mac=test_mac_address,
                                                               ipv6_src=gateway_ipv6_address,
                                                               ipv6_dst=test_ipv6_address,
                                                               icmpv6_target_ipv6_address=test_ipv6_address,
                                                               icmpv6_source_mac_address=your_mac_address)
            # endregion

            # region Make ICMPv6 Neighbor Advertisement packet
            na_packet: bytes = \
                self._icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                ethernet_dst_mac=test_mac_address,
                                                                ipv6_src=gateway_ipv6_address,
                                                                ipv6_dst=test_ipv6_address,
                                                                target_ipv6_address=gateway_ipv6_address)
            # endregion

            # region Send ICMPv6 packets
            raw_send.send_packets(packets=[rd_packet, rs_packet, ra_packet, ns_packet, na_packet],
                                  count=number_of_packets, delay=0.1)
            # endregion

            # endregion

            # region Send DHCPv6 packets
            self._base.print_info('Send DHCPv6 packets to: ',
                                  test_ipv6_address + ' (' +
                                  test_mac_address + ')', ' ....')

            # region Make random DHCPv4 transactions
            dhcpv6_transactions: Dict[str, int] = {
                'solicit': randint(0, 0xffffff),
                'advertise': randint(0, 0xffffff),
                'request': randint(0, 0xffffff),
                'reply': randint(0, 0xffffff)
            }
            # endregion

            # region Make DHCPv6 Solicit packet
            solicit_packet: bytes = \
                self._dhcpv6.make_solicit_packet(ethernet_src_mac=your_mac_address,
                                                 ethernet_dst_mac=test_mac_address,
                                                 ipv6_src=your_ipv6_address,
                                                 transaction_id=dhcpv6_transactions['solicit'],
                                                 client_mac_address=your_mac_address)
            # endregion

            # region Make DHCPv6 Advertise packet
            advertise_packet: bytes = \
                self._dhcpv6.make_advertise_packet(ethernet_src_mac=your_mac_address,
                                                   ethernet_dst_mac=test_mac_address,
                                                   ipv6_src=your_ipv6_address,
                                                   ipv6_dst=test_ipv6_address,
                                                   transaction_id=dhcpv6_transactions['advertise'],
                                                   dns_address=your_ipv6_address,
                                                   ipv6_address='fd00::123',
                                                   client_duid_timeval=1)
            # endregion

            # region Make DHCPv6 Request packet
            request_packet: bytes = \
                self._dhcpv6.make_request_packet(ethernet_src_mac=your_mac_address,
                                                 ethernet_dst_mac=test_mac_address,
                                                 ipv6_src=your_ipv6_address,
                                                 transaction_id=dhcpv6_transactions['request'],
                                                 client_mac_address=your_mac_address)
            # endregion

            # region Make DHCPv6 Reply packet
            reply_packet: bytes = \
                self._dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                               ethernet_dst_mac=test_mac_address,
                                               ipv6_src=your_ipv6_address,
                                               ipv6_dst=test_ipv6_address,
                                               transaction_id=dhcpv6_transactions['reply'],
                                               dns_address=your_ipv6_address,
                                               ipv6_address='fd00::123',
                                               client_duid_timeval=1)
            # endregion

            # region Send DHCPv6 packets
            raw_send.send_packets(packets=[solicit_packet, advertise_packet, request_packet, reply_packet],
                                  count=number_of_packets, delay=0.1)
            # endregion

            # endregion

            # region Stop dump traffic

            # region Wait
            while int(time() - start_time) < listen_time:
                stdout.write('\r')
                if listen_time - int(time() - start_time) > 1:
                    print(self._base.c_info + 'Wait: ' +
                          self._base.info_text(str(listen_time - int(time() - start_time)) + ' sec.   '), end='')
                else:
                    stdout.write('')
                stdout.flush()
                sleep(1)
            # endregion

            if test_os == 'linux' or test_os == 'macos':
                stop_dumpcap_command: str = 'pkill tcpdump >/dev/null 2>&1'
            else:
                stop_dumpcap_command: str = 'taskkill /IM "dumpcap.exe" /F'

            if ssh_user is not None:
                if not quiet:
                    self._base.print_info('Stop dump traffic on test host: ', test_ipv4_address)
                self._base.exec_command_over_ssh(command=stop_dumpcap_command,
                                                 ssh_user=ssh_user,
                                                 ssh_password=ssh_password,
                                                 ssh_pkey=ssh_private_key,
                                                 ssh_host=test_ipv4_address,
                                                 need_output=False)
            else:
                if not quiet:
                    self._base.print_info('Stop dump traffic on listen interface: ', listen_network_interface)
                if test_os == 'linux' or test_os == 'macos':
                    run([stop_dumpcap_command], shell=True)
                else:
                    check_output(stop_dumpcap_command, shell=True)
            # endregion

            # region Download and analyze pcap file from test host
            if ssh_user is not None:
                if not quiet:
                    self._base.print_info('Download remote pcap file: ', remote_pcap_file,
                                          ' with test traffic over SSH to: ', local_pcap_file)
                self._base.download_file_over_ssh(remote_path=remote_pcap_file,
                                                  local_path=local_pcap_file,
                                                  ssh_user=ssh_user,
                                                  ssh_password=ssh_password,
                                                  ssh_pkey=ssh_private_key,
                                                  ssh_host=test_ipv4_address)
                assert isfile(local_pcap_file), \
                    'Can not download remote pcap file: ' + self._base.error_text(remote_pcap_file) + \
                    ' with test traffic over SSH!'
                if test_os == 'linux' or test_os == 'macos':
                    self._base.exec_command_over_ssh(command='rm -f "' + remote_pcap_file + '"',
                                                     ssh_user=ssh_user,
                                                     ssh_password=ssh_password,
                                                     ssh_pkey=ssh_private_key,
                                                     ssh_host=test_ipv4_address,
                                                     need_output=False)
                else:
                    self._base.exec_command_over_ssh(command='del /f "' + remote_pcap_file + '"',
                                                     ssh_user=ssh_user,
                                                     ssh_password=ssh_password,
                                                     ssh_pkey=ssh_private_key,
                                                     ssh_host=test_ipv4_address,
                                                     need_output=False)
            else:
                assert isfile(local_pcap_file), \
                    'Not found local pcap file: ' + self._base.error_text(local_pcap_file) + \
                    ' with test traffic!'
            # endregion

            # region Analyze pcap file from test host

            # region Variables
            sniff_arp_spoof_packets: bool = False

            sniff_icmpv4_redirect_packets: bool = False

            sniff_dhcpv4_discover_packets: bool = False
            sniff_dhcpv4_offer_packets: bool = False
            sniff_dhcpv4_request_packets: bool = False
            sniff_dhcpv4_ack_packets: bool = False

            sniff_icmpv6_rd_packets: bool = False
            sniff_icmpv6_rs_packets: bool = False
            sniff_icmpv6_ra_packets: bool = False
            sniff_icmpv6_ns_packets: bool = False
            sniff_icmpv6_na_packets: bool = False

            sniff_dhcpv6_solicit_packets: bool = False
            sniff_dhcpv6_advertise_packets: bool = False
            sniff_dhcpv6_request_packets: bool = False
            sniff_dhcpv6_reply_packets: bool = False

            packets = rdpcap(local_pcap_file)
            remove(local_pcap_file)
            # endregion

            # region Analyze packets
            for packet in packets:

                if packet.haslayer(STP):
                    if packet[Dot3].src not in network_security_mechanisms['STP packets']:
                        network_security_mechanisms['STP packets'].append(str(packet[Dot3].src))

                    # sniff_stp_fields['802.3'] = {'source': packet[Dot3].src,
                    #                              'destination': packet[Dot3].dst}
                    # sniff_stp_fields['Spanning Tree Protocol'] = {'bridge id': packet[STP].bridgeid,
                    #                                               'bridge mac': packet[STP].bridgemac,
                    #                                               'port id': packet[STP].portid,
                    #                                               'root id': packet[STP].rootid,
                    #                                               'root mac': packet[STP].rootmac}
                    # sniff_stp_packets = True

                if packet.haslayer(ARP):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[ARP].hwsrc == your_mac_address and \
                            packet[ARP].psrc == gateway_ipv4_address and \
                            packet[ARP].hwdst == test_mac_address and \
                            packet[ARP].pdst == test_ipv4_address:
                        sniff_arp_spoof_packets = True

                if packet.haslayer(ICMP):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[Ether].type == 2048 and \
                            packet[IP].src == gateway_ipv4_address and \
                            packet[IP].dst == test_ipv4_address and \
                            packet[IP].proto == 1 and \
                            packet[ICMP].code == 1 and \
                            packet[ICMP].type == 5 and \
                            packet[ICMP].gw == your_ipv4_address and \
                            packet[ICMP].payload.src == test_ipv4_address and \
                            packet[ICMP].payload.dst == '8.8.8.8' and \
                            packet[ICMP].payload.proto == 17:
                        sniff_icmpv4_redirect_packets = True

                if packet.haslayer(DHCP):

                    # region DHCPv4 Discover
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and \
                            packet[Ether].type == 2048 and \
                            packet[IP].src == '0.0.0.0' and \
                            packet[IP].dst == '255.255.255.255' and \
                            packet[IP].proto == 17 and \
                            packet[UDP].sport == 68 and \
                            packet[UDP].dport == 67 and \
                            packet[BOOTP].op == 1 and \
                            packet[BOOTP].ciaddr == '0.0.0.0' and \
                            packet[BOOTP].giaddr == '0.0.0.0' and \
                            packet[BOOTP].siaddr == '0.0.0.0' and \
                            packet[BOOTP].yiaddr == '0.0.0.0' and \
                            packet[BOOTP].xid == dhcpv4_transactions['discover'] and \
                            ('message-type', 1) in packet[DHCP].options:
                        sniff_dhcpv4_discover_packets = True
                    # endregion

                    # region DHCPv4 Offer
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[Ether].type == 2048 and \
                            packet[IP].src == your_ipv4_address and \
                            packet[IP].dst == test_ipv4_address and \
                            packet[IP].proto == 17 and \
                            packet[UDP].sport == 67 and \
                            packet[UDP].dport == 68 and \
                            packet[BOOTP].op == 2 and \
                            packet[BOOTP].ciaddr == '0.0.0.0' and \
                            packet[BOOTP].giaddr == '0.0.0.0' and \
                            packet[BOOTP].siaddr == '0.0.0.0' and \
                            packet[BOOTP].yiaddr == test_ipv4_address and \
                            packet[BOOTP].xid == dhcpv4_transactions['offer'] and \
                            ('message-type', 2) in packet[DHCP].options and \
                            ('server_id', your_ipv4_address) in packet[DHCP].options and \
                            ('subnet_mask', '255.255.255.0') in packet[DHCP].options and \
                            ('router', your_ipv4_address) in packet[DHCP].options and \
                            ('lease_time', 600) in packet[DHCP].options and \
                            ('name_server', your_ipv4_address) in packet[DHCP].options:
                        sniff_dhcpv4_offer_packets = True
                    # endregion

                    # region DHCPv4 Request
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and \
                            packet[Ether].type == 2048 and \
                            packet[IP].src == '0.0.0.0' and \
                            packet[IP].dst == '255.255.255.255' and \
                            packet[IP].proto == 17 and \
                            packet[UDP].sport == 68 and \
                            packet[UDP].dport == 67 and \
                            packet[BOOTP].op == 1 and \
                            packet[BOOTP].ciaddr == '0.0.0.0' and \
                            packet[BOOTP].giaddr == '0.0.0.0' and \
                            packet[BOOTP].siaddr == '0.0.0.0' and \
                            packet[BOOTP].yiaddr == '0.0.0.0' and \
                            packet[BOOTP].xid == dhcpv4_transactions['request'] and \
                            ('message-type', 3) in packet[DHCP].options:
                        sniff_dhcpv4_request_packets = True
                    # endregion

                    # region DHCPv4 ACK
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[Ether].type == 2048 and \
                            packet[IP].src == your_ipv4_address and \
                            packet[IP].dst == test_ipv4_address and \
                            packet[IP].proto == 17 and \
                            packet[UDP].sport == 67 and \
                            packet[UDP].dport == 68 and \
                            packet[BOOTP].op == 2 and \
                            packet[BOOTP].ciaddr == '0.0.0.0' and \
                            packet[BOOTP].giaddr == '0.0.0.0' and \
                            packet[BOOTP].siaddr == '0.0.0.0' and \
                            packet[BOOTP].yiaddr == test_ipv4_address and \
                            packet[BOOTP].xid == dhcpv4_transactions['ack'] and \
                            ('message-type', 5) in packet[DHCP].options and \
                            ('server_id', your_ipv4_address) in packet[DHCP].options and \
                            ('subnet_mask', '255.255.255.0') in packet[DHCP].options and \
                            ('router', your_ipv4_address) in packet[DHCP].options and \
                            ('lease_time', 600) in packet[DHCP].options and \
                            ('name_server', your_ipv4_address) in packet[DHCP].options:
                        sniff_dhcpv4_ack_packets = True
                    # endregion

                if packet.haslayer(IPv6):

                    if packet.haslayer(ICMPv6ND_Redirect):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == gateway_ipv6_address and \
                                packet[IPv6].dst == test_ipv6_address and \
                                packet[ICMPv6ND_Redirect].type == 137 and \
                                packet[ICMPv6ND_Redirect].tgt == your_ipv6_address and \
                                packet[ICMPv6ND_Redirect].dst == '2001:4860:4860::8888':
                            sniff_icmpv6_rd_packets = True

                    if packet.haslayer(ICMPv6ND_RS):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == gateway_ipv6_address and \
                                packet[IPv6].dst == 'ff02::2' and \
                                packet[ICMPv6ND_RS].type == 133:
                            sniff_icmpv6_rs_packets = True

                    if packet.haslayer(ICMPv6ND_RA):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == gateway_ipv6_address and \
                                packet[IPv6].dst == 'ff02::1' and \
                                packet[ICMPv6ND_RA].type == 134:
                            sniff_icmpv6_ra_packets = True

                    if packet.haslayer(ICMPv6ND_NS):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == gateway_ipv6_address and \
                                packet[IPv6].dst == test_ipv6_address and \
                                packet[ICMPv6ND_NS].type == 135 and \
                                packet[ICMPv6ND_NS].tgt == test_ipv6_address:
                            sniff_icmpv6_ns_packets = True

                    if packet.haslayer(ICMPv6ND_NA):
                        if packet[Ether].src == your_mac_address and \
                                packet[Ether].dst == test_mac_address and \
                                packet[IPv6].src == gateway_ipv6_address and \
                                packet[IPv6].dst == test_ipv6_address and \
                                packet[ICMPv6ND_NA].type == 136 and \
                                packet[ICMPv6ND_NA].tgt == gateway_ipv6_address:
                            sniff_icmpv6_na_packets = True

                    if packet.haslayer(UDP):

                        if packet.haslayer(DHCP6_Solicit):
                            if packet[Ether].src == your_mac_address and \
                                    packet[Ether].dst == test_mac_address and \
                                    packet[IPv6].src == your_ipv6_address and \
                                    packet[IPv6].dst == 'ff02::1:2' and \
                                    packet[UDP].sport == 546 and \
                                    packet[UDP].dport == 547 and \
                                    packet[DHCP6_Solicit].msgtype == 1 and \
                                    packet[DHCP6_Solicit].trid == dhcpv6_transactions['solicit']:
                                sniff_dhcpv6_solicit_packets = True

                        if packet.haslayer(DHCP6_Advertise):
                            if packet[Ether].src == your_mac_address and \
                                    packet[Ether].dst == test_mac_address and \
                                    packet[IPv6].src == your_ipv6_address and \
                                    packet[IPv6].dst == test_ipv6_address and \
                                    packet[UDP].sport == 547 and \
                                    packet[UDP].dport == 546 and \
                                    packet[DHCP6_Advertise].msgtype == 2 and \
                                    packet[DHCP6_Advertise].trid == dhcpv6_transactions['advertise']:
                                sniff_dhcpv6_advertise_packets = True

                        if packet.haslayer(DHCP6_Request):
                            if packet[Ether].src == your_mac_address and \
                                    packet[Ether].dst == test_mac_address and \
                                    packet[IPv6].src == your_ipv6_address and \
                                    packet[IPv6].dst == 'ff02::1:2' and \
                                    packet[UDP].sport == 546 and \
                                    packet[UDP].dport == 547 and \
                                    packet[DHCP6_Request].msgtype == 3 and \
                                    packet[DHCP6_Request].trid == dhcpv6_transactions['request']:
                                sniff_dhcpv6_request_packets = True

                        if packet.haslayer(DHCP6_Reply):
                            if packet[Ether].src == your_mac_address and \
                                    packet[Ether].dst == test_mac_address and \
                                    packet[IPv6].src == your_ipv6_address and \
                                    packet[IPv6].dst == test_ipv6_address and \
                                    packet[UDP].sport == 547 and \
                                    packet[UDP].dport == 546 and \
                                    packet[DHCP6_Reply].msgtype == 7 and \
                                    packet[DHCP6_Reply].trid == dhcpv6_transactions['reply']:
                                sniff_dhcpv6_reply_packets = True

            # endregion

            # endregion

            # region Make results
            if sniff_arp_spoof_packets:
                network_security_mechanisms['ARP protection'] = False
            else:
                network_security_mechanisms['ARP protection'] = True

            if sniff_icmpv4_redirect_packets:
                network_security_mechanisms['ICMPv4 Redirect protection'] = False
            else:
                network_security_mechanisms['ICMPv4 Redirect protection'] = True

            if sniff_dhcpv4_discover_packets and \
                    sniff_dhcpv4_offer_packets and \
                    sniff_dhcpv4_request_packets and \
                    sniff_dhcpv4_ack_packets:
                network_security_mechanisms['DHCPv4 protection'] = False
            else:
                network_security_mechanisms['DHCPv4 protection'] = True

            if sniff_icmpv6_rd_packets:
                network_security_mechanisms['ICMPv6 Redirect protection'] = False
            else:
                network_security_mechanisms['ICMPv6 Redirect protection'] = True

            if sniff_icmpv6_rs_packets and sniff_icmpv6_ra_packets:
                network_security_mechanisms['ICMPv6 Router Advertisement protection'] = False
            else:
                network_security_mechanisms['ICMPv6 Router Advertisement protection'] = True

            if sniff_icmpv6_ns_packets and sniff_icmpv6_na_packets:
                network_security_mechanisms['ICMPv6 Neighbor Advertisement protection'] = False
            else:
                network_security_mechanisms['ICMPv6 Neighbor Advertisement protection'] = True

            if sniff_dhcpv6_solicit_packets and \
                    sniff_dhcpv6_advertise_packets and \
                    sniff_dhcpv6_request_packets and \
                    sniff_dhcpv6_reply_packets:
                network_security_mechanisms['DHCPv6 protection'] = False
            else:
                network_security_mechanisms['DHCPv6 protection'] = True

            return network_security_mechanisms
            # endregion

        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)

# endregion
