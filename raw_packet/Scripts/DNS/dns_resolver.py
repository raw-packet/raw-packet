#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dns_resolver.py: DNS resolver script
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath, isfile
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Senders.dns_resolver import RawDnsResolver
from raw_packet.Scanners.arp_scanner import ArpScan
# endregion

# region Import libraries
from argparse import ArgumentParser
from socket import getaddrinfo, AF_INET, AF_INET6, gaierror
from csv import DictWriter
from json import dump
from dicttoxml import dicttoxml
from xml.dom.minidom import parseString
from psycopg2 import connect, OperationalError
from psycopg2.extras import RealDictCursor
from typing import Union, Tuple, Dict, List
from yaml import load
from datetime import datetime
# endregion

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

# region Main function
if __name__ == '__main__':

    # region Init raw packet classes
    base: Base = Base()
    arp_scan: ArpScan = ArpScan()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform()
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='DNS resolver')

    parser.add_argument('-i', '--interface', help='Set interface name for send DNS request packets', default=None)

    parser.add_argument('-s', '--nsservers_name', type=str,
                        help='NS servers name (example: "ns1.test.com,ns2.test.com")', default=None)
    parser.add_argument('-n', '--nsservers_ip', type=str,
                        help='NS servers IP (default: "1.1.1.1,8.8.8.8,8.8.4.4,208.67.222.222,208.67.220.220,'
                             '84.200.69.80,84.200.70.40,77.88.8.8,77.88.8.1")',
                        default='1.1.1.1,8.8.8.8,8.8.4.4,208.67.222.222,208.67.220.220,84.200.69.80,84.200.70.40,'
                                '77.88.8.8,77.88.8.1')
    parser.add_argument('-p', '--port', type=int,
                        help='Set UDP port for listen DNS request packets (default: 53)', default=53)

    parser.add_argument('-d', '--domain', type=str, required=True, help='Set target domain name (example: test.com)')
    parser.add_argument('--subdomains_list', type=str,
                        help='Set list of subdomains (example: "admin,registry")', default=None)
    parser.add_argument('--subdomains_file', type=str,
                        help='Set file containing subdomains (example: "/tmp/subdomains.txt")', default=None)
    parser.add_argument('-b', '--subdomains_brute', action='store_true',
                        help='Brute all subdomains containing 1,2,3,4 symbols ' +
                             '(example: "a,b,c,d,.... aa,ab,ac,... ")')

    parser.add_argument('-t', '--max_threats', type=int, help='Maximum threats count (default: 10)', default=10)

    parser.add_argument('-o', '--file_name', type=str,
                        help='Set file name for save results (default: "dns_resolver_results")',
                        default='dns_resolver_results')
    parser.add_argument('-f', '--file_format', type=str,
                        help='Set file format for save results: csv, xml, json, txt (default: "csv")', default='csv')

    parser.add_argument('-m', '--msf', action='store_true', help='Save DNS resolve results to MSF database')
    parser.add_argument('--msf_workspace', type=str, help='Set MSF workspace name (default: "default")',
                        default='default')
    parser.add_argument('--msf_database_config', type=str,
                        help='Set file name with MSF database connection config ' +
                             '(default: "/usr/share/metasploit-framework/config/database.yml")',
                        default='/usr/share/metasploit-framework/config/database.yml')

    parser.add_argument('--timeout', type=int, help='Set timeout seconds (default: 10)', default=10)
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursive mode')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

    args = parser.parse_args()
    # endregion

    try:

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get your network settings
        current_network_interface = base.network_interface_selection(interface_name=args.interface)

        your_mac_address = base.get_interface_mac_address(interface_name=current_network_interface,
                                                          exit_on_failure=True)

        your_ipv4_address = base.get_interface_ip_address(interface_name=current_network_interface,
                                                          exit_on_failure=True)

        your_ipv4_network = base.get_interface_network(interface_name=current_network_interface,
                                                       exit_on_failure=True)

        your_ipv6_address = base.get_interface_ipv6_link_address(interface_name=current_network_interface,
                                                                 exit_on_failure=False)

        gateway_ipv4_address = base.get_interface_ipv4_gateway(interface_name=current_network_interface,
                                                               exit_on_failure=True)

        gateway_ipv6_address = base.get_interface_ipv6_gateway(interface_name=current_network_interface,
                                                               exit_on_failure=False)

        if not args.quiet:
            base.print_info('Find MAC addresses of IPv4 and IPv6 gateway on network interface: ',
                            current_network_interface, ' .... ')
        gateway_ipv4_mac_address = arp_scan.get_mac_address(current_network_interface, gateway_ipv4_address)
        gateway_ipv6_mac_address = 'ff:ff:ff:ff:ff:ff'
        # endregion

        # region Init DnsResolver class
        dns_resolver = RawDnsResolver(
            network_interface=current_network_interface,
            quiet=args.quiet
        )
        # endregion

        # region Variables
        subdomains = list()
        ns_servers = list()
        # endregion

        # region Parse arguments nsservers
        ns_servers_ip_addresses: List[str] = list()

        # region Parse nsservers_name
        if args.nsservers_name is not None:
            for name in str(args.nsservers_name).replace(' ', '').split(','):
                ns_server_ipv4_addresses = None
                ns_server_ipv6_addresses = None
                try:
                    ns_server_ipv4_addresses = getaddrinfo(name, None, AF_INET)
                    for address in ns_server_ipv4_addresses:
                        ipv4_address = str(address[4][0])
                        if ipv4_address not in ns_servers_ip_addresses and base.ip_address_validation(ipv4_address):
                            ns_servers_ip_addresses.append(ipv4_address)
                except gaierror:
                    base.print_warning('Could not resolve IPv4 address for name: ', name)
                assert not (ns_server_ipv4_addresses is None and ns_server_ipv6_addresses is None), \
                    'Could not resolve IPv4/IPv6 address for name: ' + base.error_text(name)
        # endregion

        # region Parse nsservers_ip
        if args.nsservers_ip is not None:
            for ip_address in str(args.nsservers_ip).replace(' ', '').split(','):
                assert (base.ip_address_validation(ip_address) or base.ipv6_address_validation(ip_address)), \
                    'Could not parse IPv4/IPv6 address: ' + base.error_text(ip_address)
                ns_servers_ip_addresses.append(ip_address)
        # endregion

        # region Get system DNS servers
        ns_servers_ip_addresses += base.get_system_name_servers()
        # endregion

        # region Make ns_server dictionary
        for ip_address in ns_servers_ip_addresses:
            if base.ip_address_in_network(ip_address, your_ipv4_network) and ip_address != gateway_ipv4_address:
                if not args.quit:
                    base.print_info('Get MAC address of NS server: ', ip_address)
                ns_servers.append({
                    'IPv4 address': ip_address,
                    'MAC address': arp_scan.get_mac_address(current_network_interface, ip_address)
                })
            else:
                ns_servers.append({
                    'IPv4 address': ip_address,
                    'MAC address': gateway_ipv4_mac_address
                })
        # endregion

        # region Get Name servers by domain
        ns_servers += dns_resolver.get_name_servers(ipv4_gateway_mac=gateway_ipv4_mac_address,
                                                    ipv6_gateway_mac=gateway_ipv6_mac_address,
                                                    domain=args.domain)
        # endregion

        # endregion

        # region Parse arguments with subdomains

        # region Parse subdomains list from argument
        if args.subdomains_list is not None:
            for subdomain in str(args.subdomains_list).replace(' ', '').split(','):
                subdomains.append(subdomain)
        # endregion

        # region Check file with subdomains list
        if args.subdomains_file is not None:
            assert isfile(args.subdomains_file), \
                'File with subdomains list: ' + base.error_text(args.subdomains_file) + ' not found!'
        # endregion

        # region Check arguments with subdomains
        assert not (args.subdomains_list is None and args.subdomains_file is None and not args.subdomains_brute), \
            'List containing subdomains is empty, please set any of this parameters: ' \
            + base.info_text('--subdomain_list') + ' or ' \
            + base.info_text('--subdomain_file') + ' or ' \
            + base.info_text('--subdomain_brute')
        # endregion

        # endregion

        # region General output
        if not args.quiet:

            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('Your IPv4 address: ', your_ipv4_address)

            if your_ipv6_address is not None:
                base.print_info('Your IPv6 address: ', your_ipv6_address)

            base.print_info('IPv4 Gateway address: ', gateway_ipv4_address)
            base.print_info('IPv4 Gateway MAC address: ', gateway_ipv4_mac_address)

            if gateway_ipv6_address is not None:
                base.print_info('IPv6 Gateway address: ', gateway_ipv6_address)
                base.print_info('IPv6 Gateway MAC address: ', gateway_ipv6_mac_address)

            base.print_info('Target domain: ', args.domain)
            base.print_info('Length of subdomains list: ', str(len(subdomains)))

            for ns_server in ns_servers:
                if 'IPv4 address' in ns_server.keys():
                    base.print_info('NS server IPv4 address: ', ns_server['IPv4 address'],
                                    ' MAC address: ', ns_server['MAC address'])
                if 'IPv6 address' in ns_server.keys():
                    base.print_info('NS server IPv6 address: ', ns_server['IPv6 address'],
                                    ' MAC address: ', ns_server['MAC address'])
        # endregion

        # region Start DNS resolver
        resolve_results_copy: List[Dict[str, str]] = list()
        resolve_results = dns_resolver.resolve(ns_servers=ns_servers,
                                               domain=args.domain,
                                               max_threats_count=args.max_threats,
                                               udp_destination_port=args.port,
                                               timeout=args.timeout,
                                               subdomains_list=subdomains,
                                               subdomains_file=args.subdomains_file,
                                               subdomains_brute=args.subdomains_brute)
        if args.recursive:
            uniq_domains: List[str] = list()
            resolve_results_copy = resolve_results.copy()
            for resolve_result in resolve_results_copy:
                if resolve_result['Domain'] not in uniq_domains:
                    uniq_domains.append(resolve_result['Domain'])
                    recursive_resolve_results = dns_resolver.resolve(ns_servers=ns_servers,
                                                                     domain=resolve_result['Domain'],
                                                                     max_threats_count=args.max_threats,
                                                                     udp_destination_port=args.port,
                                                                     timeout=args.timeout,
                                                                     subdomains_list=subdomains,
                                                                     subdomains_file=args.subdomains_file,
                                                                     subdomains_brute=args.subdomains_brute)
                    resolve_results_copy.extend(recursive_resolve_results)
            resolve_results = resolve_results_copy.copy()
        # endregion

        # region Save dns resolve results to file:
        # dns_resolver_results.csv or dns_resolver_results.txt or dns_resolver_results.json or dns_resolver_results.xml
        if args.file_format == 'csv':
            with open(args.file_name + '.csv', 'w') as results_csv_file:
                csv_writer = DictWriter(results_csv_file, fieldnames=['Domain', 'IPv4 address', 'IPv6 address'])
                csv_writer.writeheader()
                for resolve_result in resolve_results:
                    csv_writer.writerow(resolve_result)

        if args.file_format == 'txt':
            with open(args.file_name + '.txt', 'w') as results_txt_file:
                for resolve_result in resolve_results:
                    results_txt_file.write(resolve_result['Domain'] +
                                           ' ' + resolve_result['IPv4 address'] +
                                           ' ' + resolve_result['IPv6 address'] + '\n')

        if args.file_format == 'json':
            with open(args.file_name + '.json', 'w') as results_json_file:
                dump(resolve_results, results_json_file, indent=4)

        if args.file_format == 'xml':
            with open(args.file_name + '.xml', 'w') as results_xml_file:
                xml = dicttoxml(resolve_results, custom_root='resolve_results', attr_type=False)
                xml_dom = parseString(xml.decode('utf-8'))
                results_xml_file.write(xml_dom.toprettyxml())
        # endregion

        # region MSF
        if args.msf:
            assert isfile(args.msf_database_config), \
                'File with MSF database config: ' + base.error_text(str(args.msf_database_config)) + ' not found!'

            with open(args.msf_database_config, 'r') as msf_connection_config_file:
                msf_connection_config: Dict[str, Dict[str, Union[int, str]]] = load(msf_connection_config_file)

            assert 'production' in msf_connection_config.keys(), \
                'Not found "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert 'adapter' in msf_connection_config['production'].keys(), \
                'Not found "adapter" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert msf_connection_config['production']['adapter'] == 'postgresql', \
                'MSF adapter type: ' + base.error_text(str(msf_connection_config['production']['adapter'])) + \
                ' not support! Support only ' + base.info_text('postgresql') + ' MSF adapter'

            assert 'host' in msf_connection_config['production'].keys(), \
                'Not found "host" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert 'port' in msf_connection_config['production'].keys(), \
                'Not found "port" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert 'username' in msf_connection_config['production'].keys(), \
                'Not found "username" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert 'password' in msf_connection_config['production'].keys(), \
                'Not found "password" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            assert 'database' in msf_connection_config['production'].keys(), \
                'Not found "database" key in "production" config in MSF database config: ' + \
                base.error_text(str(args.msf_database_config))

            msf_connection = connect(host=msf_connection_config['production']['host'],
                                     port=msf_connection_config['production']['port'],
                                     user=msf_connection_config['production']['username'],
                                     password=msf_connection_config['production']['password'],
                                     dbname=msf_connection_config['production']['database'])
            msf_cursor = msf_connection.cursor(cursor_factory=RealDictCursor)
            msf_cursor.execute('SELECT id from workspaces WHERE name = %(workspace)s',
                               {'workspace': str(args.msf_workspace)})
            msf_workspace_id: Union[None, Dict[str, str]] = msf_cursor.fetchone()
            assert msf_workspace_id is not None, \
                'Not found MSF workspace with name: ' + base.error_text(str(args.msf_workspace))
            msf_workspace_id: str = str(msf_workspace_id['id'])

            for resolve_result in resolve_results:
                if resolve_result['IPv6 address'] == '-':
                    host_address: str = resolve_result['IPv4 address']
                else:
                    host_address: str = resolve_result['IPv6 address']

                msf_cursor.execute('SELECT id from hosts WHERE address = %(address)s '
                                   'AND workspace_id = %(workspace_id)s',
                                   {'address': str(host_address),
                                    'workspace_id': str(msf_workspace_id)})
                msf_hosts: Dict[str, str] = msf_cursor.fetchone()

                if msf_hosts is None:
                    msf_cursor.execute(
                        'INSERT into hosts (created_at, address, name, state, os_name, workspace_id) ' +
                        'VALUES (%(created)s,%(address)s,%(name)s,%(state)s,%(os)s,%(workspace_id)s)',
                        {
                            'created': datetime.now(),
                            'address': host_address,
                            'name': resolve_result['Domain'],
                            'state': 'alive',
                            'os': 'Unknown',
                            'workspace_id': msf_workspace_id
                        })
                    msf_connection.commit()

                else:
                    msf_cursor.execute('UPDATE hosts SET updated_at = %(update)s WHERE id =%(id)s',
                                       {
                                           'update': datetime.now(),
                                           'id': msf_hosts['id']
                                       })
                    msf_connection.commit()
            msf_connection.close()
        # endregion

    except AssertionError as Error:
        base.print_error(Error.args[0])

        if Error.args[0].startswith('Could not resolve IPv4/IPv6 address for name'):
            exit(1)

        if Error.args[0].startswith('Could not parse IPv4/IPv6 address'):
            exit(2)

        if Error.args[0].startswith('List containing NS server addresses is empty'):
            exit(3)

        if Error.args[0].startswith('File with subdomains list'):
            exit(4)

        if Error.args[0].startswith('List containing subdomains is empty'):
            exit(5)

    except KeyboardInterrupt:
        base.print_info('Exit ...')
        exit(0)

    except OperationalError as Error:
        base.print_error('Could not connect to MSF db! ', str(Error.args[0]))

# endregion
