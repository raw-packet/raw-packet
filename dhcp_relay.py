from base import Base
from argparse import ArgumentParser
from network import Ethernet_raw, DHCP_raw
from datetime import datetime
from time import sleep
from random import randint
from tm import ThreadManager
from scapy.all import sniff, DHCP, BOOTP, sendp
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)

Base.check_user()

_dhcp_option_value = None
_dhcp_option_code = 12
_transactions = {}
_current_network_interface = ""

parser = ArgumentParser(description='DHCP Relay agent script')
parser.add_argument('-i', '--interface', type=str, help='Set interface name for send discover packets')
parser.add_argument('-p', '--packets', type=int, help='Number of packets (default: 100000)', default=100000)
parser.add_argument('-m', '--client_mac', type=str, help='Set client MAC address', default=None)
parser.add_argument('-d', '--delay', type=int, help='Set delay time in seconds (default: 5)', default=5)
parser.add_argument('-n', '--not_send_hostname', action='store_true', help='Do not send hostname in DHCP request')
parser.add_argument('-v', '--dhcp_option_value', type=str, help='Set DHCP option value', default=None)
parser.add_argument('-c', '--dhcp_option_code', type=int, help='Set DHCP option code (default: 12)', default=12)
args = parser.parse_args()

if args.dhcp_option_value is not None:
    _dhcp_option_value = args.dhcp_option_value

if args.dhcp_option_code != 12:
    _dhcp_option_code = args.dhcp_option_code

_number_of_packets = int(args.packets)

if args.interface is None:
    _current_network_interface = Base.netiface_selection()
else:
    _current_network_interface = args.interface

_current_ip_address = Base.get_netiface_ip_address(_current_network_interface)
if _current_ip_address is None:
    print "This network interface does not have IP address!"
    exit(1)

_current_mac_address = Base.get_netiface_mac_address(_current_network_interface)
if _current_mac_address is None:
    print "This network interface does not have mac address!"
    exit(1)


def send_dhcp_discover():
    sleep(1)

    eth = Ethernet_raw()
    dhcp = DHCP_raw()

    print "\r\nSending discover packets..."
    print "Number of packets: " + str(_number_of_packets)
    print "Start sending packets: " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))

    count = 0
    while count < _number_of_packets:

        if args.client_mac is None:
            client_mac = eth.get_random_mac()
        else:
            client_mac = args.client_mac
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
        sleep(int(args.delay))
        count += 1

    print "All discover packets sent: " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))


def send_dhcp_request(request):
    if request.haslayer(DHCP):
        xid = request[BOOTP].xid
        yiaddr = request[BOOTP].yiaddr
        siaddr = request[BOOTP].siaddr

        if request[DHCP].options[0][1] == 2:
            print "[INFO] OFFER from: " + siaddr + " || transaction id: " + hex(xid) + " || your client ip: " + yiaddr

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
                print "[ERROR] Key error, this transaction id: " + hex(xid) + " not found in our array transactions!"
            except:
                print "[ERROR] Unknown error!"

        if request[DHCP].options[0][1] == 5:
            print "[INFO] ACK from:   " + siaddr + " || transaction id: " + hex(xid) + " || your client ip: " + yiaddr

        if request[DHCP].options[0][1] == 6:
            print "[INFO] NAK from:   " + siaddr + " || transaction id: " + hex(xid) + " || your client ip: " + yiaddr


if __name__ == "__main__":
    tm = ThreadManager(2)
    tm.add_task(send_dhcp_discover)
    print "Sniffing interface: " + str(_current_network_interface)
    sniff(filter="udp and src port 67 and dst port 67 and dst host " + _current_ip_address,
          prn=send_dhcp_request, iface=_current_network_interface)
