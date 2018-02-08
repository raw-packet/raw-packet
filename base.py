from platform import system, release
from sys import exit
from os import getuid
from os.path import dirname, abspath
from pwd import getpwuid
from netifaces import interfaces
from random import choice
from string import lowercase, uppercase, digits
from netifaces import ifaddresses, gateways, AF_LINK, AF_INET, AF_INET6
from scapy.all import srp, Ether, ARP
from struct import pack, error


class Base:
    cINFO = None
    cERROR = None
    cSUCCESS = None
    cWARNING = None
    cEND = None

    c_info = None
    c_error = None
    c_success = None
    c_warning = None

    def __init__(self):
        self.cINFO = '\033[1;34m'
        self.cERROR = '\033[1;31m'
        self.cSUCCESS = '\033[1;32m'
        self.cWARNING = '\033[1;33m'
        self.cEND = '\033[0m'

        self.c_info = self.cINFO + '[*]' + self.cEND + ' '
        self.c_error = self.cERROR + '[-]' + self.cEND + ' '
        self.c_success = self.cSUCCESS + '[+]' + self.cEND + ' '
        self.c_warning = self.cWARNING + '[!]' + self.cEND + ' '

    @staticmethod
    def print_banner():
        with open(dirname(abspath(__file__)) + '/version.txt', 'r') as version_file:
            current_version = version_file.read()
        greenc = '\033[1;32m'
        yellowc = '\033[1;33m'
        endc = '\033[0m'
        print greenc + "                                          _        _   " + endc
        print greenc + " _ __ __ ___      __     _ __   __ _  ___| | _____| |_ " + endc
        print greenc + "| '__/ _` \ \ /\ / /___ | '_ \ / _` |/ __| |/ / _ \ __|" + endc
        print greenc + "| | | (_| |\ V  V /|___|| |_) | (_| | (__|   <  __/ |_ " + endc
        print greenc + "|_|  \__,_| \_/\_/      | .__/ \__,_|\___|_|\_\___|\__|" + endc
        print greenc + "                        |_|                      v" + current_version + endc
        print yellowc + "\r\nhttps://github.com/Vladimir-Ivanov-Git/raw-packet\r\n" + endc

    @staticmethod
    def check_platform():
        if system() != "Linux":
            print "This script can run only in Linux platform!"
            print "Your platform: " + str(system()) + " " + str(release()) + " not supported!"
            exit(1)

    @staticmethod
    def check_user():
        if getuid() != 0:
            print "Only root can run this script!"
            print "You: " + str(getpwuid(getuid())[0]) + " can not run this script!"
            exit(1)

    @staticmethod
    def pack8(data):
        try:
            return pack("B", data)
        except error:
            print "Bad value for 8 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack16(data):
        try:
            return pack("!H", data)
        except error:
            print "Bad value for 16 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack32(data):
        try:
            return pack("<I", data)
        except error:
            print "Bad value for 32 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def pack64(data):
        try:
            return pack("<Q", data)
        except error:
            print "Bad value for 64 bit pack: " + str(data)
            exit(1)

    @staticmethod
    def netiface_selection():
        netiface_index = 1
        current_netifaces = interfaces()

        print "Your interface list:"
        for netiface in current_netifaces:
            print " " + str(netiface_index) + ") " + netiface
            netiface_index += 1

        netiface_index -= 1
        current_netiface_index = raw_input('Set network interface from range (1-' + str(netiface_index) + '): ')

        if not current_netiface_index.isdigit():
            print "Your input data is not digit!"
            exit(1)

        if any([int(current_netiface_index) < 1, int(current_netiface_index) > netiface_index]):
            print "Your number is not within range (1-" + str(netiface_index) + ")"
            exit(1)

        current_network_interface = ""
        try:
            current_network_interface = str(current_netifaces[int(current_netiface_index) - 1])
        except:
            print "This network interface has some problem"
            exit(1)
        return current_network_interface

    @staticmethod
    def get_netiface_mac_address(interface_name):
        try:
            mac_address = str(ifaddresses(interface_name)[AF_LINK][0]['addr'])
        except:
            mac_address = None
        return mac_address

    @staticmethod
    def get_netiface_ip_address(interface_name):
        try:
            ip_address = str(ifaddresses(interface_name)[AF_INET][0]['addr'])
        except:
            ip_address = None
        return ip_address

    @staticmethod
    def get_netiface_ipv6_address(interface_name, address_number=0):
        try:
            ipv6_address = str(ifaddresses(interface_name)[AF_INET6][address_number]['addr'])
            ipv6_address = ipv6_address.replace("%" + interface_name, "", 1)
        except:
            ipv6_address = None
        return ipv6_address

    def get_netiface_ipv6_link_address(self, interface_name):
        for index in range(10):
            ipv6_address = self.get_netiface_ipv6_address(interface_name, index)
            if ipv6_address.startswith("fe80::"):
                return ipv6_address
        return None

    def get_netiface_ipv6_glob_address(self, interface_name):
        for index in range(10):
            ipv6_address = self.get_netiface_ipv6_address(interface_name, index)
            if ipv6_address.startswith("fe80::"):
                pass
            else:
                return ipv6_address
        return None

    @staticmethod
    def create_ipv6_link_address(mac_address):
        try:
            parts = mac_address.split(":")
            parts.insert(3, "ff")
            parts.insert(4, "fe")
            parts[0] = "%x" % (int(parts[0], 16) ^ 2)
            ipv6Parts = []
            for i in range(0, len(parts), 2):
                ipv6Parts.append("".join(parts[i:i + 2]))
            ipv6_address = "fe80::%s" % (":".join(ipv6Parts))
        except:
            ipv6_address = None
        return ipv6_address

    @staticmethod
    def get_netiface_netmask(interface_name):
        try:
            netmask = str(ifaddresses(interface_name)[AF_INET][0]['netmask'])
        except:
            netmask = None
        return netmask

    @staticmethod
    def get_netiface_broadcast(interface_name):
        try:
            broadcast = str(ifaddresses(interface_name)[AF_INET][0]['broadcast'])
        except:
            broadcast = None
        return broadcast


    @staticmethod
    def make_random_string(length):
        return ''.join(choice(lowercase + uppercase + digits) for _ in range(length))

    @staticmethod
    def get_mac(iface, ip):
        gw_ip = ""
        gws = gateways()
        for gw in gws.keys():
            try:
                if str(gws[gw][AF_INET][1]) == iface:
                    gw_ip = str(gws[gw][AF_INET][0])
            except IndexError:
                if str(gws[gw][0][1]) == iface:
                    gw_ip = str(gws[gw][0][0])
        try:
            alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=iface, timeout=10, verbose=0)
            return str(alive[0][1].hwsrc)
        except IndexError:
            try:
                alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw_ip), iface=iface, timeout=10, verbose=0)
                return str(alive[0][1].hwsrc)
            except:
                return "ff:ff:ff:ff:ff:ff"
        except:
            return "ff:ff:ff:ff:ff:ff"
