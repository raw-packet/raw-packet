from platform import system, release
from sys import exit
from os import getuid
from pwd import getpwuid
from netifaces import interfaces


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

        try:
            current_network_interface = str(current_netifaces[int(current_netiface_index) - 1])
        except:
            print "This network interface has some problem"
            exit(1)

        print "You choosed interface: " + current_network_interface
        return current_network_interface
