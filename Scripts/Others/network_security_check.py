#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
network_security_check.py: Checking network security mechanisms such as: Dynamic ARP Inspection, DHCP snooping, etc.
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath, join
from argparse import ArgumentParser
from typing import Union, Dict, List
from paramiko import RSAKey
from pathlib import Path
from os.path import isfile
from os import remove
from subprocess import run, Popen, check_output, PIPE, STDOUT
from scapy.all import sendp, rdpcap, Ether, Dot3, LLC, STP, ARP, IP, UDP, BOOTP, DHCP, ICMP, IPv6
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect
from scapy.all import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo
from scapy.layers.inet6 import ICMPv6NDOptMTU, ICMPv6NDOptRDNSS, ICMPv6NDOptDNSSL
from scapy.layers.inet6 import ICMPv6NDOptAdvInterval
from scapy.layers.dhcp6 import DHCP6OptIA_NA, DHCP6OptRapidCommit, DHCP6OptElapsedTime
from scapy.layers.dhcp6 import DHCP6OptClientId, DHCP6OptUnknown, DUID_LL, DUID_LLT
from scapy.layers.dhcp6 import DHCP6OptServerId, DHCP6OptReconfAccept, DHCP6OptDNSServers
from scapy.layers.dhcp6 import DHCP6OptDNSDomains, DHCP6OptIAAddress, DHCP6OptOptReq
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


if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    base: Base = Base()
    # endregion

    try:

        # region Check user
        base.check_user()
        # endregion

        # region Parse script arguments
        parser: ArgumentParser = ArgumentParser(description='Checking network security mechanisms')
        parser.add_argument('-s', '--send_interface', help='Set interface name for send packets', default=None)
        parser.add_argument('-l', '--listen_interface', help='Set interface name for listen packets', default=None)
        parser.add_argument('-n', '--test_host_interface', help='Set test host network interface for listen packets',
                            default=None)
        parser.add_argument('-t', '--test_host', help='Set test host IP address for ssh connection', default=None)
        parser.add_argument('-m', '--test_mac', help='Set test host MAC address for ssh connection', default=None)
        parser.add_argument('-o', '--test_os', help='Set test host OS (MacOS, Linux, Windows)', default='Linux')
        parser.add_argument('-u', '--test_ssh_user', help='Set test host user name for ssh connection', default='root')
        parser.add_argument('-p', '--test_ssh_pass', help='Set test host password for ssh connection', default=None)
        parser.add_argument('-k', '--test_ssh_pkey', help='Set test host private key for ssh connection', default=None)
        parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', default=None)
        parser.add_argument('-g', '--gateway_mac', help='Set gateway MAC address', default=None)
        parser.add_argument('-r', '--number_of_packets', type=int, default=10,
                            help='Set number of network packets for each test (default: 10)')
        parser.add_argument('-L', '--listen_time', type=int, default=60,
                            help='Set time to listen broadcast packets in seconds (default: 60)')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get network interface, your IP and MAC address
        if args.send_interface is None:
            base.print_warning('Please set a network interface for send packets ...')
        send_network_interface: str = base.network_interface_selection(args.send_interface)
        your_mac_address: str = base.get_interface_mac_address(send_network_interface)
        your_ip_address: str = base.get_interface_ip_address(send_network_interface)
        your_ipv6_address: Union[None, str] = base.get_interface_ipv6_link_address(send_network_interface,
                                                                                   exit_on_failure=False,
                                                                                   quiet=True)
        if your_ipv6_address is None:
            your_ipv6_address = base.make_ipv6_link_address(your_mac_address)
        your_network: str = base.get_interface_network(send_network_interface)
        # endregion

        # region Variables
        your_platform: str = base.get_platform()

        list_of_network_interfaces: List[str] = base.list_of_network_interfaces()
        list_of_network_interfaces.remove(send_network_interface)

        listen_network_interface: Union[None, str] = None
        test_interface_ip_address: Union[None, str] = None
        use_listen_interface: str = 'No'

        test_ip_address: Union[None, str] = None
        test_mac_address: Union[None, str] = None
        test_ipv6_address: Union[None, str] = None
        test_interface: Union[None, str] = None
        test_os: Union[None, str] = None

        ssh_user: Union[None, str] = None
        ssh_password: Union[None, str] = None
        ssh_private_key: Union[None, RSAKey] = None

        windows_temp_directory: Union[None, str] = None
        if your_platform.startswith('Windows'):
            local_temp_directory: bytes = check_output('echo %temp%', shell=True)
            local_temp_directory: str = local_temp_directory.decode().splitlines()[0]
            pcap_file = join(local_temp_directory, 'spoofing.pcap')
        else:
            pcap_file: str = '/tmp/spoofing.pcap'
        if isfile(pcap_file):
            remove(pcap_file)
        # endregion

        # region Check gateway IP and MAC address
        if args.gateway_ip is not None:
            assert base.ip_address_in_network(args.gateway_ip, your_network), \
                'Gateway IP address: ' + base.error_text(args.gateway_ip) + \
                ' not in your network: ' + base.info_text(your_network)
            gateway_ip_address: str = str(args.gateway_ip)
        else:
            gateway_ip_address: str = base.get_interface_gateway(send_network_interface)
        scan_gateway_mac_address: str = get_mac_address(ip=gateway_ip_address, network_request=True)
        if args.gateway_mac is not None:
            assert base.mac_address_validation(args.gateway_mac), \
                'Bad gateway MAC address: ' + base.error_text(args.gateway_mac)
            assert args.gateway_mac == scan_gateway_mac_address, \
                'Gateway MAC address in argument: ' + base.error_text(args.gateway_mac) + \
                ' is not real gateway MAC address: ' + base.info_text(scan_gateway_mac_address)
        gateway_mac_address: str = scan_gateway_mac_address
        gateway_ipv6_address: str = base.make_ipv6_link_address(gateway_mac_address)
        # endregion

        # region Set listen interface or test host
        if args.listen_interface is None and args.test_host is None:

            # region Make list of available network interfaces
            if len(list_of_network_interfaces) > 0:
                for test_interface in list_of_network_interfaces:
                    test_interface_ip_address = base.get_interface_ip_address(interface_name=test_interface,
                                                                              exit_on_failure=False, quiet=True)
                    if base.ip_address_in_network(test_interface_ip_address, your_network):
                        listen_network_interface = test_interface
                        break
            # endregion

            # region Found network interface with IP address in test network
            if listen_network_interface is not None:
                while test_ip_address is None:
                    print(base.c_info + 'Use network interface: ' +
                          base.info_text(listen_network_interface + ' (' + test_interface_ip_address + ')') +
                          ' for listen traffic [Yes|No]: ', end='')
                    use_listen_interface = input()
                    if use_listen_interface == 'No' or use_listen_interface == 'N':
                        while True:
                            print(base.c_info + 'Please set test host IP address for SSH connect: ')
                            test_ip_address = input()
                            if base.ip_address_in_network(test_ip_address, your_network):
                                break
                            else:
                                base.print_error('Test host IP address: ', test_ip_address,
                                                 ' not in network: ' + base.info_text(your_network))
                    elif use_listen_interface == 'Yes' or use_listen_interface == 'Y':
                        break
                    else:
                        base.print_error('Unknown answer: ', use_listen_interface, ' please use answer "Yes" or "No"')
            # endregion

            # region Not found network interface with IP address in test network, set test host IP address for SSH conn
            else:
                assert False, 'Please set test host IP address: ' + base.error_text('\'-t\', \'--test_host\'')
                # if not args.quiet:
                #     arp_scan_results = arp_scan.scan(network_interface=send_network_interface,
                #                                      timeout=5, retry=5, show_scan_percentage=True,
                #                                      exclude_ip_addresses=[gateway_ip_address])
                # else:
                #     arp_scan_results = arp_scan.scan(network_interface=send_network_interface,
                #                                      timeout=5, retry=5, show_scan_percentage=False,
                #                                      exclude_ip_addresses=[gateway_ip_address])
                # target = scanner.ipv4_device_selection(arp_scan_results)
                # test_ip_address = target['ip-address']
                # test_mac_address = target['mac-address']
            # endregion

        # endregion

        # region Check test host
        if args.test_host is not None or test_ip_address is not None:

            # region Check test host IP and MAC address
            if test_ip_address is not None and test_mac_address is not None:
                test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            else:
                if args.test_host is not None:
                    assert base.ip_address_in_network(args.test_host, your_network), \
                        'Test host IP address: ' + base.error_text(args.test_host) + \
                        ' not in your network: ' + base.info_text(your_network)
                    test_ip_address = str(args.test_host)
                scan_test_mac_address: str = get_mac_address(ip=test_ip_address, network_request=True)
                if args.test_mac is not None:
                    assert base.mac_address_validation(args.test_mac), \
                        'Bad test host MAC address: ' + base.error_text(args.test_mac)
                    assert args.test_mac == scan_test_mac_address, \
                        'Test host MAC address in argument: ' + base.error_text(args.test_mac) + \
                        ' is not real test host MAC address: ' + base.info_text(scan_test_mac_address)
                test_mac_address = scan_test_mac_address
                test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            # endregion

            # region Check test host SSH user, password and private key
            ssh_user = args.test_ssh_user
            ssh_password = args.test_ssh_pass
            ssh_private_key = None
            test_os = str(args.test_os).lower()

            if args.test_ssh_pkey is None and ssh_password is None:
                default_ssh_private_key_file: str = join(str(Path.home()), '.ssh', 'id_rsa')
                assert isfile(default_ssh_private_key_file), \
                    'Could not found private SSH key: ' + base.error_text(default_ssh_private_key_file)
                ssh_private_key = RSAKey.from_private_key_file(default_ssh_private_key_file)

            if args.test_ssh_pkey is not None:
                ssh_private_key = RSAKey.from_private_key_file(args.target_ssh_pkey)

            assert ssh_private_key is not None or ssh_password is not None, \
                'Password and private key file for SSH is None!' + \
                ' Please set SSH password: ' + base.info_text('--test_ssh_pass <ssh_password>') + \
                ' or SSH private key file: ' + base.info_text('--test_ssh_pkey <ssh_private_key_path>')

            if test_os == 'linux' or test_os == 'macos':
                command: str = 'ifconfig'
            else:
                command: str = 'netsh interface show interface'
            test_host_network_interfaces: str = base.exec_command_over_ssh(command=command,
                                                                           ssh_user=ssh_user,
                                                                           ssh_password=ssh_password,
                                                                           ssh_pkey=ssh_private_key,
                                                                           ssh_host=test_ip_address)

            if test_os == 'linux' or test_os == 'macos':
                test_host_network_interfaces_list = findall(r'^([a-zA-Z0-9]{2,32})\:\ ',
                                                            test_host_network_interfaces,
                                                            MULTILINE)
            else:
                test_host_network_interfaces_list = test_host_network_interfaces.split()

            if args.test_host_interface is None:
                base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)
                test_interface = input('Please set network interface on test host: ')
            else:
                test_interface = args.test_host_interface
                if test_interface not in test_host_network_interfaces_list:
                    base.print_info('Network interfaces list on test host: \n', test_host_network_interfaces)

            while True:
                if test_interface not in test_host_network_interfaces_list:
                    base.print_warning('Network interface: ', test_interface,
                                       ' not in network interfaces list on test host')
                    test_interface = input('Please set network interface on test host: ')
                else:
                    break
            # endregion

        # endregion

        # region Check listen network interface
        if (args.listen_interface is not None or listen_network_interface is not None) and test_ip_address is None:
            if args.listen_interface is not None:
                assert args.listen_interface in list_of_network_interfaces, \
                    'Network interface: ' + base.error_text(args.listen_interface) + \
                    ' not in available network interfaces list: ' + base.info_text(str(list_of_network_interfaces))
                listen_network_interface = args.listen_interface
            test_ip_address = base.get_interface_ip_address(listen_network_interface)
            test_mac_address = base.get_interface_mac_address(listen_network_interface)
            test_ipv6_address = base.make_ipv6_link_address(test_mac_address)
            test_interface = listen_network_interface
            if your_platform.startswith('Windows'):
                test_os = 'windows'
            elif your_platform.startswith('Linux'):
                test_os = 'linux'
            elif your_platform.startswith('Darwin'):
                test_os = 'macos'
            else:
                assert False, 'Your platform: ' + base.info_text(your_platform) + ' is not supported!'
        # endregion

        # region Output
        if not args.quiet:
            base.print_info('Send network interface: ', send_network_interface)
            base.print_info('Send network interface IP address: ', your_ip_address)
            base.print_info('Send network interface MAC address: ', your_mac_address)
            if listen_network_interface is not None:
                base.print_info('Listen network interface: ', listen_network_interface)
                base.print_info('Listen network interface IP address: ', test_ip_address)
                base.print_info('Listen network interface MAC address: ', test_mac_address)
            if ssh_user is not None:
                base.print_info('Test host IP address: ', test_ip_address)
                base.print_info('Test host MAC address: ', test_mac_address)
                base.print_info('Test host OS: ', test_os)
                base.print_info('Test host network interface: ', test_interface)
            base.print_info('Gateway IP address: ', gateway_ip_address)
            base.print_info('Gateway MAC address: ', gateway_mac_address)
        # endregion

        # region Start tshark
        if test_os == 'linux' or test_os == 'macos':
            start_tshark_command: str = 'tshark -i "' + test_interface + \
                                        '" -w /tmp/spoofing.pcap >/dev/null 2>&1'
        else:
            start_tshark_command: str = '"C:\\Program Files\\Wireshark\\tshark.exe" -i "' + test_interface + \
                                        '" -w "' + pcap_file + '"'
        if ssh_user is not None:
            if not args.quiet:
                base.print_info('Start tshark on test host: ', test_ip_address)
            base.exec_command_over_ssh(command=start_tshark_command,
                                       ssh_user=ssh_user,
                                       ssh_password=ssh_password,
                                       ssh_pkey=ssh_private_key,
                                       ssh_host=test_ip_address,
                                       need_output=False)

            if test_os == 'linux' or test_os == 'macos':
                start_tshark_retry: int = 1
                while base.exec_command_over_ssh(command='pgrep tshark',
                                                 ssh_user=ssh_user,
                                                 ssh_password=ssh_password,
                                                 ssh_pkey=ssh_private_key,
                                                 ssh_host=test_ip_address) == '':
                    base.exec_command_over_ssh(command=start_tshark_command,
                                               ssh_user=ssh_user,
                                               ssh_password=ssh_password,
                                               ssh_pkey=ssh_private_key,
                                               ssh_host=test_ip_address,
                                               need_output=False)
                    sleep(1)
                    start_tshark_retry += 1
                    if start_tshark_retry == 5:
                        base.print_error('Failed to start tshark on test host: ', test_ip_address)
                        exit(1)
            else:
                windows_temp_directory = base.exec_command_over_ssh(command='echo %temp%',
                                                                    ssh_user=ssh_user,
                                                                    ssh_password=ssh_password,
                                                                    ssh_pkey=ssh_private_key,
                                                                    ssh_host=test_ip_address)
                assert windows_temp_directory is not None or windows_temp_directory != '', \
                    'Can not get variable %temp% on Windows host: ' + base.error_text(test_ip_address)
                if windows_temp_directory.endswith('\n'):
                    windows_temp_directory = windows_temp_directory[:-1]
                if windows_temp_directory.endswith('\r'):
                    windows_temp_directory = windows_temp_directory[:-1]
        else:
            if isfile(pcap_file):
                remove(pcap_file)
            if not args.quiet:
                base.print_info('Start tshark on listen interface: ', listen_network_interface)
            if test_os == 'linux' or test_os == 'macos':
                Popen([start_tshark_command], shell=True, stdout=PIPE, stderr=STDOUT)
            else:
                Popen(start_tshark_command, shell=True, stdout=PIPE, stderr=STDOUT)
        start_time = time()
        sleep(5)
        # endregion

        # region Send ARP packets
        base.print_info('Send ARP packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        arp_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            ARP(op=2, hwsrc=your_mac_address, psrc=gateway_ip_address, hwdst=test_mac_address, pdst=test_ip_address)
        for _ in range(args.number_of_packets):
            sendp(arp_packet, iface=send_network_interface, count=1, verbose=False)
            sleep(0.5)
        # endregion

        # region Send ICMPv4 packets
        base.print_info('Send ICMPv4 packets to: ', test_ip_address + ' (' + test_mac_address + ')')
        icmpv4_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IP(src=gateway_ip_address, dst=test_ip_address) / \
            ICMP(type=5, code=1, gw=your_ip_address) / \
            IP(src=test_ip_address, dst='8.8.8.8') / \
            UDP(sport=53, dport=53)
        for _ in range(args.number_of_packets):
            sendp(icmpv4_packet, iface=send_network_interface, count=1, verbose=False)
            sleep(0.5)
        # endregion

        # region Send DHCPv4 packets
        base.print_info('Send DHCPv4 packets to: ', test_ip_address + ' (' + test_mac_address + ')')

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
            Ether(src=your_mac_address, dst='ff:ff:ff:ff:ff:ff') / \
            IP(src='0.0.0.0', dst='255.255.255.255') / \
            UDP(sport=68, dport=67) / \
            BOOTP(op=1, ciaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0', yiaddr='0.0.0.0',
                  chaddr=your_mac_address, xid=dhcpv4_transactions['discover']) / \
            DHCP(options=[('message-type', 1), ('param_req_list', [1, 121, 3, 6, 15, 119, 252]), 'end'])
        # endregion

        # region Make DHCPv4 Offer packet
        offer_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IP(src=your_ip_address, dst=test_ip_address) / \
            UDP(sport=67, dport=68) / \
            BOOTP(op=2, ciaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0', yiaddr=test_ip_address,
                  chaddr=test_mac_address, xid=dhcpv4_transactions['offer']) / \
            DHCP(options=[('message-type', 2),
                          ('server_id', your_ip_address),
                          ('lease_time', 600),
                          ('subnet_mask', '255.255.255.0'),
                          ('router', your_ip_address),
                          ('name_server', your_ip_address),
                          ('domain', 'test'),
                          'end'])
        # endregion

        # region Make DHCPv4 Request packet
        request_packet: bytes = \
            Ether(src=your_mac_address, dst='ff:ff:ff:ff:ff:ff') / \
            IP(src='0.0.0.0', dst='255.255.255.255') / \
            UDP(sport=68, dport=67) / \
            BOOTP(op=1, ciaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0', yiaddr='0.0.0.0',
                  chaddr=your_mac_address, xid=dhcpv4_transactions['request']) / \
            DHCP(options=[('message-type', 3), ('param_req_list', [1, 121, 3, 6, 15, 119, 252]), 'end'])
        # endregion

        # region Make DHCPv4 ACK packet
        ack_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IP(src=your_ip_address, dst=test_ip_address) / \
            UDP(sport=67, dport=68) / \
            BOOTP(op=2, ciaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0', yiaddr=test_ip_address,
                  chaddr=test_mac_address, xid=dhcpv4_transactions['ack']) / \
            DHCP(options=[('message-type', 5),
                          ('server_id', your_ip_address),
                          ('lease_time', 600),
                          ('subnet_mask', '255.255.255.0'),
                          ('router', your_ip_address),
                          ('name_server', your_ip_address),
                          ('domain', 'test'),
                          'end'])
        # endregion

        # region Send DHCPv4 packets
        for _ in range(args.number_of_packets):
            sendp(discover_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(offer_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(request_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(ack_packet, iface=send_network_interface, count=1, verbose=False)
            sleep(0.5)
        # endregion

        # endregion

        # region Send ICMPv6 packets
        base.print_info('Send ICMPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')

        # region Make ICMPv6 Redirect packet
        rd_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IPv6(src=gateway_ipv6_address, dst=test_ipv6_address) / \
            ICMPv6ND_Redirect(type=137, tgt=your_ipv6_address, dst='2001:4860:4860::8888') / \
            ICMPv6NDOptDstLLAddr(type=2, len=1, lladdr=your_mac_address)
        # endregion

        # region Make ICMPv6 Router Solicitation packet
        rs_packet: bytes = \
            Ether(src=your_mac_address, dst='33:33:00:00:00:02') / \
            IPv6(src=gateway_ipv6_address, dst='ff02::2') / \
            ICMPv6ND_RS(type=133, code=0, res=0)
        # endregion

        # region Make ICMPv6 Router Advertisement packet
        ra_packet: bytes = \
            Ether(src=your_mac_address, dst='33:33:00:00:00:01') / \
            IPv6(src=gateway_ipv6_address, dst='ff02::1') / \
            ICMPv6ND_RA(type=134, M=1, O=1, H=0, prf=0, P=0, res=0,
                        routerlifetime=0, reachabletime=0, retranstimer=0) / \
            ICMPv6NDOptPrefixInfo(prefixlen=64, prefix='fd00::') / \
            ICMPv6NDOptSrcLLAddr(lladdr=your_mac_address) / \
            ICMPv6NDOptMTU(res=0, mtu=1500) / \
            ICMPv6NDOptRDNSS(lifetime=6000, dns=[your_ipv6_address]) / \
            ICMPv6NDOptDNSSL(lifetime=6000, searchlist=['test.local.']) / \
            ICMPv6NDOptAdvInterval(advint=60000)
        # endregion

        # region Make ICMPv6 Neighbor Solicitation packet
        ns_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IPv6(src=gateway_ipv6_address, dst=test_ipv6_address) / \
            ICMPv6ND_NS(type=135, code=0, res=0, tgt=test_ipv6_address) / \
            ICMPv6NDOptDstLLAddr(lladdr=your_mac_address)
        # endregion

        # region Make ICMPv6 Neighbor Advertisement packet
        na_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IPv6(src=gateway_ipv6_address, dst=test_ipv6_address) / \
            ICMPv6ND_NA(type=136, code=0, R=0, S=0, O=1, res=0, tgt=gateway_ipv6_address) / \
            ICMPv6NDOptDstLLAddr(lladdr=your_mac_address)
        # endregion

        # region Send ICMPv6 packets
        for _ in range(args.number_of_packets):
            sendp(rd_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(rs_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(ra_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(ns_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(na_packet, iface=send_network_interface, count=1, verbose=False)
            sleep(0.5)
        # endregion

        # endregion

        # region Send DHCPv6 packets
        base.print_info('Send DHCPv6 packets to: ', test_ipv6_address + ' (' + test_mac_address + ')')

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
            Ether(src=your_mac_address, dst='33:33:00:01:00:02') / \
            IPv6(src=your_ipv6_address, dst='ff02::1:2') / \
            UDP(sport=546, dport=547) / \
            DHCP6_Solicit(msgtype=1, trid=dhcpv6_transactions['solicit']) / \
            DHCP6OptIA_NA(ianaopts=[DHCP6OptUnknown(optcode=0, optlen=0, data=b'')]) / \
            DHCP6OptRapidCommit() / \
            DHCP6OptElapsedTime(elapsedtime=0) / \
            DHCP6OptClientId(duid=DUID_LL(type=3, hwtype=1, lladdr=your_mac_address))
        # endregion

        # region Make DHCPv6 Advertise packet
        advertise_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IPv6(src=your_ipv6_address, dst=test_ipv6_address) / \
            UDP(sport=547, dport=546) / \
            DHCP6_Advertise(msgtype=2, trid=dhcpv6_transactions['advertise']) / \
            DHCP6OptClientId(duid=DUID_LLT(type=1, hwtype=1, timeval=1, lladdr=test_mac_address)) / \
            DHCP6OptServerId(duid=DUID_LL(type=3, hwtype=1, lladdr=your_mac_address)) / \
            DHCP6OptReconfAccept() / \
            DHCP6OptDNSServers(dnsservers=[your_ipv6_address]) / \
            DHCP6OptDNSDomains(dnsdomains=['test.local.']) / \
            DHCP6OptIA_NA(iaid=1, T1=3000, T2=4800,
                          ianaopts=[DHCP6OptIAAddress(addr='fd00::123', preflft=4294967295, validlft=4294967295)])
        # endregion

        # region Make DHCPv6 Request packet
        request_packet: bytes = \
            Ether(src=your_mac_address, dst='33:33:00:01:00:02') / \
            IPv6(src=your_ipv6_address, dst='ff02::1:2') / \
            UDP(sport=546, dport=547) / \
            DHCP6_Request(msgtype=3, trid=dhcpv6_transactions['request']) / \
            DHCP6OptIA_NA(ianaopts=[DHCP6OptUnknown(optcode=0, optlen=0, data=b'')]) / \
            DHCP6OptRapidCommit() / \
            DHCP6OptElapsedTime(elapsedtime=0) / \
            DHCP6OptClientId(duid=DUID_LL(type=3, hwtype=1, lladdr=your_mac_address)) / \
            DHCP6OptOptReq(reqopts=[23, 24])
        # endregion

        # region Make DHCPv6 Reply packet
        reply_packet: bytes = \
            Ether(src=your_mac_address, dst=test_mac_address) / \
            IPv6(src=your_ipv6_address, dst=test_ipv6_address) / \
            UDP(sport=547, dport=546) / \
            DHCP6_Reply(msgtype=7, trid=dhcpv6_transactions['reply']) / \
            DHCP6OptClientId(duid=DUID_LLT(type=1, hwtype=1, timeval=1, lladdr=test_mac_address)) / \
            DHCP6OptServerId(duid=DUID_LL(type=3, hwtype=1, lladdr=your_mac_address)) / \
            DHCP6OptReconfAccept() / \
            DHCP6OptDNSServers(dnsservers=[your_ipv6_address]) / \
            DHCP6OptDNSDomains(dnsdomains=['test.local.']) / \
            DHCP6OptIA_NA(iaid=1, T1=3000, T2=4800,
                          ianaopts=[DHCP6OptIAAddress(addr='fd00::123', preflft=4294967295, validlft=4294967295)])
        # endregion

        # region Send DHCPv6 packets
        for _ in range(args.number_of_packets):
            sendp(solicit_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(advertise_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(request_packet, iface=send_network_interface, count=1, verbose=False)
            sendp(reply_packet, iface=send_network_interface, count=1, verbose=False)
            sleep(0.5)
        # endregion

        # endregion

        # region Stop tshark
        while int(time() - start_time) < args.listen_time:
            stdout.write('\r')
            if args.listen_time - int(time() - start_time) > 1:
                print(base.c_info + 'Wait: ' +
                      base.info_text(str(args.listen_time - int(time() - start_time)) + ' sec.   '), end='')
            else:
                stdout.write('')
            stdout.flush()
            sleep(1)

        if test_os == 'linux' or test_os == 'macos':
            stop_tshark_command: str = 'pkill tshark >/dev/null 2>&1'
        else:
            stop_tshark_command: str = 'taskkill /IM "tshark.exe" /F'
        if ssh_user is not None:
            if not args.quiet:
                base.print_info('Stop tshark on test host: ', test_ip_address)
            base.exec_command_over_ssh(command=stop_tshark_command,
                                       ssh_user=ssh_user,
                                       ssh_password=ssh_password,
                                       ssh_pkey=ssh_private_key,
                                       ssh_host=test_ip_address,
                                       need_output=False)
        else:
            if not args.quiet:
                base.print_info('Stop tshark on listen interface: ', listen_network_interface)
            if test_os == 'linux' or test_os == 'macos':
                run([stop_tshark_command], shell=True)
            else:
                check_output(stop_tshark_command, shell=True)
        # endregion

        # region Download and analyze pcap file from test host
        if ssh_user is not None:
            if not args.quiet:
                base.print_info('Download pcap file with test traffic over SSH to: ', pcap_file)
            if test_os == 'windows':
                base.download_file_over_ssh(remote_path=windows_temp_directory + '\spoofing.pcap',
                                            local_path=pcap_file,
                                            ssh_user=ssh_user,
                                            ssh_password=ssh_password,
                                            ssh_pkey=ssh_private_key,
                                            ssh_host=test_ip_address)
            else:
                base.download_file_over_ssh(remote_path=pcap_file,
                                            local_path=pcap_file,
                                            ssh_user=ssh_user,
                                            ssh_password=ssh_password,
                                            ssh_pkey=ssh_private_key,
                                            ssh_host=test_ip_address)
            assert isfile(pcap_file), \
                'Can not download pcap file: ' + base.error_text(pcap_file) + ' with test traffic over SSH'
        else:
            assert isfile(pcap_file), \
                'Not found pcap file: ' + base.error_text(pcap_file) + ' with test traffic'
        # endregion

        # region Analyze pcap file from test host
        if not args.quiet:
            base.print_info('Analyze pcap file:')

        # region Variables
        sniff_stp_packets: bool = False
        sniff_stp_fields: Dict[str, Dict[str, str]] = dict()

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

        packets = rdpcap(pcap_file)
        # endregion

        # region Analyze packets
        for packet in packets:

            if packet.haslayer(STP):
                sniff_stp_fields['802.3'] = {'source': packet[Dot3].src,
                                             'destination': packet[Dot3].dst}
                sniff_stp_fields['Spanning Tree Protocol'] = {'bridge id': packet[STP].bridgeid,
                                                              'bridge mac': packet[STP].bridgemac,
                                                              'port id': packet[STP].portid,
                                                              'root id': packet[STP].rootid,
                                                              'root mac': packet[STP].rootmac}
                sniff_stp_packets = True

            if packet.haslayer(ARP):
                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[ARP].hwsrc == your_mac_address and \
                        packet[ARP].psrc == gateway_ip_address and \
                        packet[ARP].hwdst == test_mac_address and \
                        packet[ARP].pdst == test_ip_address:
                    sniff_arp_spoof_packets = True

            if packet.haslayer(ICMP):
                if packet[Ether].src == your_mac_address and \
                        packet[Ether].dst == test_mac_address and \
                        packet[Ether].type == 2048 and \
                        packet[IP].src == gateway_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[IP].proto == 1 and \
                        packet[ICMP].code == 1 and \
                        packet[ICMP].type == 5 and \
                        packet[ICMP].gw == your_ip_address and \
                        packet[ICMP].payload.src == test_ip_address and \
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
                        packet[IP].src == your_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[IP].proto == 17 and \
                        packet[UDP].sport == 67 and \
                        packet[UDP].dport == 68 and \
                        packet[BOOTP].op == 2 and \
                        packet[BOOTP].ciaddr == '0.0.0.0' and \
                        packet[BOOTP].giaddr == '0.0.0.0' and \
                        packet[BOOTP].siaddr == '0.0.0.0' and \
                        packet[BOOTP].yiaddr == test_ip_address and \
                        packet[BOOTP].xid == dhcpv4_transactions['offer'] and \
                        ('message-type', 2) in packet[DHCP].options and \
                        ('server_id', your_ip_address) in packet[DHCP].options and \
                        ('subnet_mask', '255.255.255.0') in packet[DHCP].options and \
                        ('router', your_ip_address) in packet[DHCP].options and \
                        ('lease_time', 600) in packet[DHCP].options and \
                        ('name_server', your_ip_address) in packet[DHCP].options:
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
                        packet[IP].src == your_ip_address and \
                        packet[IP].dst == test_ip_address and \
                        packet[IP].proto == 17 and \
                        packet[UDP].sport == 67 and \
                        packet[UDP].dport == 68 and \
                        packet[BOOTP].op == 2 and \
                        packet[BOOTP].ciaddr == '0.0.0.0' and \
                        packet[BOOTP].giaddr == '0.0.0.0' and \
                        packet[BOOTP].siaddr == '0.0.0.0' and \
                        packet[BOOTP].yiaddr == test_ip_address and \
                        packet[BOOTP].xid == dhcpv4_transactions['ack'] and \
                        ('message-type', 5) in packet[DHCP].options and \
                        ('server_id', your_ip_address) in packet[DHCP].options and \
                        ('subnet_mask', '255.255.255.0') in packet[DHCP].options and \
                        ('router', your_ip_address) in packet[DHCP].options and \
                        ('lease_time', 600) in packet[DHCP].options and \
                        ('name_server', your_ip_address) in packet[DHCP].options:
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
                            packet[ICMPv6ND_Redirect].dst == '2001:4860:4860::8888' and \
                            packet[ICMPv6NDOptDstLLAddr].lladdr == your_mac_address:
                        sniff_icmpv6_rd_packets = True

                if packet.haslayer(ICMPv6ND_RS):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == '33:33:00:00:00:02' and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == 'ff02::2' and \
                            packet[ICMPv6ND_RS].type == 133:
                        sniff_icmpv6_rs_packets = True

                if packet.haslayer(ICMPv6ND_RA):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == '33:33:00:00:00:01' and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == 'ff02::1' and \
                            packet[ICMPv6ND_RA].type == 134 and \
                            packet[ICMPv6NDOptPrefixInfo].prefix == 'fd00::' and \
                            packet[ICMPv6NDOptPrefixInfo].prefixlen == 64 and \
                            packet[ICMPv6NDOptSrcLLAddr].lladdr == your_mac_address and \
                            packet[ICMPv6NDOptRDNSS].dns == [your_ipv6_address] and \
                            packet[ICMPv6NDOptDNSSL].searchlist == ['test.local.'] and \
                            packet[ICMPv6NDOptAdvInterval].advint == 60000:
                        sniff_icmpv6_ra_packets = True

                if packet.haslayer(ICMPv6ND_NS):
                    if packet[Ether].src == your_mac_address and \
                            packet[Ether].dst == test_mac_address and \
                            packet[IPv6].src == gateway_ipv6_address and \
                            packet[IPv6].dst == test_ipv6_address and \
                            packet[ICMPv6ND_NS].type == 135 and \
                            packet[ICMPv6ND_NS].tgt == test_ipv6_address and \
                            packet[ICMPv6NDOptDstLLAddr].lladdr == your_mac_address:
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
                                packet[Ether].dst == '33:33:00:01:00:02' and \
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
                                packet[Ether].dst == '33:33:00:01:00:02' and \
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

        # region Print analyze pcap file results
        if sniff_arp_spoof_packets:
            base.print_success('ARP protection disabled')
        else:
            base.print_error('ARP protection enabled')

        if sniff_icmpv4_redirect_packets:
            base.print_success('ICMPv4 Redirect protection disabled')
        else:
            base.print_error('ICMPv4 Redirect protection enabled')

        if sniff_dhcpv4_discover_packets and \
                sniff_dhcpv4_offer_packets and \
                sniff_dhcpv4_request_packets and \
                sniff_dhcpv4_ack_packets:
            base.print_success('DHCPv4 protection disabled')
        else:
            base.print_error('DHCPv4 protection enabled')

        if sniff_icmpv6_rd_packets:
            base.print_success('ICMPv6 Redirect protection disabled')
        else:
            base.print_error('ICMPv6 Redirect protection enabled')

        if sniff_icmpv6_rs_packets and sniff_icmpv6_ra_packets:
            base.print_success('ICMPv6 Router Advertisement protection disabled')
        else:
            base.print_error('ICMPv6 Router Advertisement protection enabled')

        if sniff_icmpv6_ns_packets and sniff_icmpv6_na_packets:
            base.print_success('ICMPv6 Neighbor Advertisement protection disabled')
        else:
            base.print_error('ICMPv6 Neighbor Advertisement protection enabled')

        if sniff_dhcpv6_solicit_packets and \
                sniff_dhcpv6_advertise_packets and \
                sniff_dhcpv6_request_packets and \
                sniff_dhcpv6_reply_packets:
            base.print_success('DHCPv6 protection disabled')
        else:
            base.print_error('DHCPv6 protection enabled')

        if sniff_stp_packets:
            base.print_success('STP packets from: ', sniff_stp_fields['802.3']['source'],
                               ' possible STP (RSTP, PVSTP, MSTP) spoofing')
        else:
            base.print_error('STP packets not found')
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
