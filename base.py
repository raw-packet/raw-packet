from platform import system, release
from sys import exit
from os import getuid
from pwd import getpwuid
from netifaces import interfaces
from random import choice
from string import lowercase, uppercase, digits
from netifaces import ifaddresses, gateways, AF_LINK, AF_INET
from scapy.all import srp, Ether, ARP


class Base:

    def __init__(self):
        pass

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