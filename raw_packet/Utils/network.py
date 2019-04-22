# region Description
"""
network.py: Class for creating and parsing network packets for Raw-packet project
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from base import Base
from random import choice, randint
from struct import pack, unpack, error as struct_error
from binascii import unhexlify, hexlify
from array import array
from socket import error as sock_error, inet_aton, inet_ntoa, inet_pton, htons, IPPROTO_TCP, IPPROTO_UDP, AF_INET6
from socket import socket, AF_PACKET, SOCK_RAW, inet_ntop, IPPROTO_ICMPV6
from re import search
from time import time
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Raw Ethernet
class Ethernet_raw:
    # +---------------------------------------------------------------+
    # |       Ethernet destination address (first 32 bits)            |
    # +-------------------------------+-------------------------------+
    # | Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
    # +-------------------------------+-------------------------------+
    # |       Ethernet source address (last 32 bits)                  |
    # +-------------------------------+-------------------------------+
    # |        Type code              |                               |
    # +-------------------------------+-------------------------------+

    header_length = 0
    macs = []

    def __init__(self):
        self.header_length = 14
        self.macs.append("3c:d9:2b")  # Hewlett Packard
        self.macs.append("9c:8e:99")  # Hewlett Packard
        self.macs.append("b4:99:ba")  # Hewlett Packard
        self.macs.append("00:50:ba")  # Hewlett Packard
        self.macs.append("00:11:0a")  # Hewlett Packard
        self.macs.append("00:11:85")  # Hewlett Packard
        self.macs.append("00:12:79")  # Hewlett Packard
        self.macs.append("00:13:21")  # Hewlett Packard
        self.macs.append("00:14:38")  # Hewlett Packard
        self.macs.append("00:14:c2")  # Hewlett Packard
        self.macs.append("00:15:60")  # Hewlett Packard
        self.macs.append("00:16:35")  # Hewlett Packard
        self.macs.append("00:17:08")  # Hewlett Packard
        self.macs.append("00:18:fe")  # Hewlett Packard
        self.macs.append("00:19:bb")  # Hewlett Packard
        self.macs.append("00:1a:4b")  # Hewlett Packard
        self.macs.append("00:1b:78")  # Hewlett Packard
        self.macs.append("00:1c:c4")  # Hewlett Packard
        self.macs.append("00:1e:0b")  # Hewlett Packard
        self.macs.append("00:1f:29")  # Hewlett Packard
        self.macs.append("00:21:5a")  # Hewlett Packard
        self.macs.append("00:22:64")  # Hewlett Packard
        self.macs.append("00:23:7d")  # Hewlett Packard
        self.macs.append("00:24:81")  # Hewlett Packard
        self.macs.append("00:25:b3")  # Hewlett Packard
        self.macs.append("00:26:55")  # Hewlett Packard
        self.macs.append("00:0d:88")  # D-Link Corporation
        self.macs.append("00:0f:3d")  # D-Link Corporation
        self.macs.append("00:13:46")  # D-Link Corporation
        self.macs.append("00:15:e9")  # D-Link Corporation
        self.macs.append("00:17:9a")  # D-Link Corporation
        self.macs.append("00:19:5b")  # D-Link Corporation
        self.macs.append("00:1b:11")  # D-Link Corporation
        self.macs.append("00:1c:f0")  # D-Link Corporation
        self.macs.append("00:1e:58")  # D-Link Corporation
        self.macs.append("00:21:91")  # D-Link Corporation
        self.macs.append("00:22:b0")  # D-Link Corporation
        self.macs.append("00:24:01")  # D-Link Corporation
        self.macs.append("00:26:5a")  # D-Link Corporation
        self.macs.append("00:0d:88")  # D-Link Corporation
        self.macs.append("00:0f:3d")  # D-Link Corporation
        self.macs.append("00:00:0c")  # Cisco Systems, Inc
        self.macs.append("00:01:42")  # Cisco Systems, Inc
        self.macs.append("00:01:43")  # Cisco Systems, Inc
        self.macs.append("00:01:63")  # Cisco Systems, Inc
        self.macs.append("00:01:64")  # Cisco Systems, Inc
        self.macs.append("00:01:96")  # Cisco Systems, Inc
        self.macs.append("00:01:97")  # Cisco Systems, Inc
        self.macs.append("00:01:c7")  # Cisco Systems, Inc
        self.macs.append("00:01:c9")  # Cisco Systems, Inc
        self.macs.append("00:02:16")  # Cisco Systems, Inc
        self.macs.append("00:02:17")  # Cisco Systems, Inc
        self.macs.append("00:02:4a")  # Cisco Systems, Inc
        self.macs.append("00:02:4b")  # Cisco Systems, Inc
        self.macs.append("00:02:7d")  # Cisco Systems, Inc
        self.macs.append("00:02:7e")  # Cisco Systems, Inc
        self.macs.append("d0:d0:fd")  # Cisco Systems, Inc
        self.macs.append("d4:8c:b5")  # Cisco Systems, Inc
        self.macs.append("d4:a0:2a")  # Cisco Systems, Inc
        self.macs.append("d4:d7:48")  # Cisco Systems, Inc
        self.macs.append("d8:24:bd")  # Cisco Systems, Inc
        self.macs.append("08:63:61")  # Huawei Technologies Co., Ltd
        self.macs.append("08:7a:4c")  # Huawei Technologies Co., Ltd
        self.macs.append("0c:37:dc")  # Huawei Technologies Co., Ltd
        self.macs.append("0c:96:bf")  # Huawei Technologies Co., Ltd
        self.macs.append("10:1b:54")  # Huawei Technologies Co., Ltd
        self.macs.append("10:47:80")  # Huawei Technologies Co., Ltd
        self.macs.append("10:c6:1f")  # Huawei Technologies Co., Ltd
        self.macs.append("20:f3:a3")  # Huawei Technologies Co., Ltd
        self.macs.append("24:69:a5")  # Huawei Technologies Co., Ltd
        self.macs.append("28:31:52")  # Huawei Technologies Co., Ltd
        self.macs.append("00:1b:63")  # Apple Inc
        self.macs.append("00:1c:b3")  # Apple Inc
        self.macs.append("00:1d:4f")  # Apple Inc
        self.macs.append("00:1e:52")  # Apple Inc
        self.macs.append("00:1e:c2")  # Apple Inc
        self.macs.append("00:1f:5b")  # Apple Inc
        self.macs.append("00:1f:f3")  # Apple Inc
        self.macs.append("00:21:e9")  # Apple Inc
        self.macs.append("00:22:41")  # Apple Inc
        self.macs.append("00:23:12")  # Apple Inc
        self.macs.append("00:23:32")  # Apple Inc
        self.macs.append("00:23:6c")  # Apple Inc
        self.macs.append("00:23:df")  # Apple Inc
        self.macs.append("00:24:36")  # Apple Inc
        self.macs.append("00:25:00")  # Apple Inc
        self.macs.append("00:25:4b")  # Apple Inc
        self.macs.append("00:25:bc")  # Apple Inc
        self.macs.append("00:26:08")  # Apple Inc
        self.macs.append("00:26:4a")  # Apple Inc
        self.macs.append("00:26:b0")  # Apple Inc
        self.macs.append("00:26:bb")  # Apple Inc
        self.macs.append("00:11:75")  # Intel Corporate
        self.macs.append("00:13:e8")  # Intel Corporate
        self.macs.append("00:13:02")  # Intel Corporate
        self.macs.append("00:02:b3")  # Intel Corporate
        self.macs.append("00:03:47")  # Intel Corporate
        self.macs.append("00:04:23")  # Intel Corporate
        self.macs.append("00:0c:f1")  # Intel Corporate
        self.macs.append("00:0e:0c")  # Intel Corporate
        self.macs.append("00:0e:35")  # Intel Corporate
        self.macs.append("00:12:f0")  # Intel Corporate
        self.macs.append("00:13:02")  # Intel Corporate
        self.macs.append("00:13:20")  # Intel Corporate
        self.macs.append("00:13:ce")  # Intel Corporate
        self.macs.append("00:13:e8")  # Intel Corporate
        self.macs.append("00:15:00")  # Intel Corporate
        self.macs.append("00:15:17")  # Intel Corporate
        self.macs.append("00:16:6f")  # Intel Corporate
        self.macs.append("00:16:76")  # Intel Corporate
        self.macs.append("00:16:ea")  # Intel Corporate
        self.macs.append("00:16:eb")  # Intel Corporate
        self.macs.append("00:18:de")  # Intel Corporate

    def __enter__(self):
        return self

    def get_random_mac(self):
        mac_prefix = choice(self.macs)
        mac_suffix = ':'.join('{0:02x}'.format(randint(0x00, 0xff), 'x') for _ in range(3))
        return mac_prefix + ':' + mac_suffix

    @staticmethod
    def convert_mac(mac_address):
        if len(mac_address) < 12:
            print "Too short mac address: " + mac_address
            exit(1)

        if len(mac_address) > 17:
            print "Too long mac address: " + mac_address
            exit(1)

        if len(mac_address) == 17:
            mac_address = mac_address[:17].lower()
            if search("([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", mac_address):
                return unhexlify(mac_address.replace(':', ''))
            else:
                print "Bad mac address: " + mac_address
                exit(1)

        elif len(mac_address) == 12:
            mac_address = mac_address[:12].lower()
            result_mac_address = ""
            for index in range(0, 12, 2):
                result_mac_address += mac_address[index] + mac_address[index + 1] + ":"
            return result_mac_address[:17]

        else:
            print "Bad mac address: " + mac_address
            exit(1)

    @staticmethod
    def get_mac_prefix(mac_address, prefix_length=6):
        if len(mac_address) < 12:
            print "Too short mac address: " + mac_address
            exit(1)

        if len(mac_address) > 17:
            print "Too long mac address: " + mac_address
            exit(1)

        if len(mac_address) == 17:
            mac_address = mac_address[:17].lower()
            if search("([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", mac_address):
                result_mac_address = mac_address.replace(':', '')
                return result_mac_address[:prefix_length].upper()
            else:
                print "Bad mac address: " + mac_address
                exit(1)

        elif len(mac_address) == 12:
            mac_address = mac_address[:12].lower()
            result_mac_address = ""
            for index in range(0, 12, 2):
                result_mac_address += mac_address[index] + mac_address[index + 1] + ":"
            return result_mac_address[:prefix_length].upper()

        else:
            print "Bad mac address: " + mac_address
            exit(1)

    def make_header(self, source_mac, destination_mac, network_type):
        return self.convert_mac(destination_mac) + self.convert_mac(source_mac) + pack("!" "H", network_type)

    def parse_header(self, packet):
        if len(packet) != 14:
            return None

        ethernet_detailed = unpack("!" "6s" "6s" "H", packet)

        try:
            return {
                "destination": self.convert_mac(hexlify(ethernet_detailed[0])),
                "source":      self.convert_mac(hexlify(ethernet_detailed[1])),
                "type":        int(ethernet_detailed[2])
            }
        except IndexError:
            return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self.macs[:]
# endregion


# region Raw IP
class IP_raw:
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-------+-------+---------------+-------------------------------+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-------+-------+---------------+-----+-------------------------+
    # |         Identification        |Flags|      Fragment Offset    |
    # +---------------+---------------+-----+-------------------------+
    # |  Time to Live |    Protocol   |         Header Checksum       |
    # +---------------+---------------+-------------------------------+
    # |                       Source Address                          |
    # +---------------------------------------------------------------+
    # |                    Destination Address                        |
    # +-----------------------------------------------+---------------+
    # |                    Options                    |    Padding    |
    # +-----------------------------------------------+---------------+

    header_type = 0

    def __init__(self):
        self.header_type = 2048

    @staticmethod
    def get_random_ip():
        return '.'.join(str(randint(0, 255)) for _ in range(4))

    @staticmethod
    def checksum(packet):
        if len(packet) % 2 == 1:
            packet += "\0"
        s = sum(array("H", packet))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    def make_header(self, source_ip, destination_ip, data_len, transport_protocol_len, transport_protocol, ttl=64):
        srcip = inet_aton(source_ip)       # Source port
        dstip = inet_aton(destination_ip)  # Destination port
        ver = 4       # IP protocol version
        ihl = 5       # Internet Header Length
        dscp_ecn = 0  # Differentiated Services Code Point and Explicit Congestion Notification

        tlen = data_len + transport_protocol_len + 20  # Packet length
        ident = htons(randint(1, 65535))  # Identification
        flg_frgoff = 0  # Flags and fragmentation offset
        ptcl = transport_protocol  # Protocol
        chksm = 0  # Checksum

        ip_header = pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                         (ver << 4) + ihl, dscp_ecn, tlen, ident,
                         flg_frgoff, ttl, ptcl, chksm, srcip, dstip)
        chksm = self.checksum(ip_header)
        return pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                    (ver << 4) + ihl, dscp_ecn, tlen, ident,
                    flg_frgoff, ttl, ptcl, chksm, srcip, dstip)

    @staticmethod
    def parse_header(packet):
        if len(packet) < 20:
            return None

        version_and_length = int(unpack("!B", packet[0])[0])
        version = int(int(version_and_length & 0b11110000) >> 4)
        length = int(int(version_and_length) & 0b00001111)
        
        if version != 4:
            return None

        ip_detailed = unpack("!" "B" "3H" "2B" "H" "4s" "4s", packet[1:20])

        try:
            return {
                "version":         version,
                "length":          length,
                "dscp_ecn":        int(ip_detailed[0]),
                "total-length":    int(ip_detailed[1]),
                "identification":  int(ip_detailed[2]),
                "flags":           int(int(int(ip_detailed[3]) & 0b1110000000000000) >> 3),
                "fragment-offset": int(int(ip_detailed[3]) & 0b0001111111111111),
                "time-to-live":    int(ip_detailed[4]),
                "protocol":        int(ip_detailed[5]),
                "checksum":        int(ip_detailed[6]),
                "source-ip":       inet_ntoa(ip_detailed[7]),
                "destination-ip":  inet_ntoa(ip_detailed[8])
            }
        except IndexError:
            return None

# endregion


# region Raw IPv6
class IPv6_raw:
    #           0 - 3     4 - 11                     12 - 31
    #         +-------+--------------+----------------------------------------+
    #    0-31 |Version|Traffic Class |              Flow Label                |
    #         +-------+--------------+-------------------+--------------------+
    #   32-63 |Payload Length (32-47)|Next Header (48-55)|  Hop Limit (56-63) |
    #         +----------------------+-------------------+--------------------+
    #  64-191 |                       Source Address                          |
    #         +---------------------------------------------------------------+
    # 192-288 |                    Destination Address                        |
    #         +---------------------------------------------------------------+

    header_type = 0
    header_length = 0

    def __init__(self):
        self.header_type = 34525
        self.header_length = 40

    @staticmethod
    def get_random_ip(octets=1, prefix=""):
        ip = prefix
        for index in range(0, octets):
            ip += str(hex(randint(1, 65535))[2:]) + ":"
        return ip[:-1]

    @staticmethod
    def pack_addr(ipv6_addr):
        if ipv6_addr == "::":
            return ''.join(pack("B", 0) for _ in range(16))
        else:
            return inet_pton(AF_INET6, ipv6_addr)

    def make_header(self, source_ip, destination_ip, flow_label, payload_len, next_header, hop_limit=64):
        src_ipv6 = self.pack_addr(source_ip)       # Source IPv6 address
        dst_ipv6 = self.pack_addr(destination_ip)  # Destination IPv6 address

        ver = 6             # IP protocol version
        traffic_class = 0   # Differentiated Services Code Point and Explicit Congestion Notification

        return pack("!" "2I",
                    (ver << 28) + (traffic_class << 20) + flow_label,
                    (payload_len << 16) + (next_header << 8) + hop_limit) + src_ipv6 + dst_ipv6

    @staticmethod
    def parse_header(packet):
        if len(packet) < 40:
            return None

        version_class_and_label = int(unpack("!L", packet[0:4])[0])
        version = int(int(version_class_and_label & 0b11110000000000000000000000000000) >> 28)
        traffic_class = int(int(version_class_and_label & 0b00001111111100000000000000000000) >> 20)
        flow_label = int(version_class_and_label & 0b00000000000011111111111111111111)

        if version != 6:
            return None

        ipv6_detailed = unpack("!" "H" "2B" "16s" "16s", packet[4:40])

        try:
            return {
                "version":        version,
                "traffic-class":  traffic_class,
                "flow-label":     flow_label,
                "payload-length": int(ipv6_detailed[0]),
                "next-header":    int(ipv6_detailed[1]),
                "hop-limit":      int(ipv6_detailed[2]),
                "source-ip":      inet_ntop(AF_INET6, ipv6_detailed[3]),
                "destination-ip": inet_ntop(AF_INET6, ipv6_detailed[4])
            }

        except IndexError:
            return None

        except sock_error:
            return None

# endregion


# region Raw ARP
class ARP_raw:

    eth = None
    packet_type = 0
    packet_length = 0

    def __init__(self):
        self.eth = Ethernet_raw()
        self.packet_type = 2054
        self.packet_length = 28

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac, sender_mac, sender_ip, target_mac, target_ip, opcode,
                    hardware_type=1, protocol_type=2048, hardware_size=6, protocol_size=4):
        sender_ip = inet_aton(sender_ip)
        target_ip = inet_aton(target_ip)
        sender_mac = self.eth.convert_mac(sender_mac)
        target_mac = self.eth.convert_mac(target_mac)
        arp_packet = pack("!" "2H" "2B" "H", hardware_type, protocol_type, hardware_size, protocol_size, opcode)
        arp_packet += sender_mac + pack("!" "4s", sender_ip)
        arp_packet += target_mac + pack("!" "4s", target_ip)

        eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 2054)
        return eth_header + arp_packet

    def parse_packet(self, packet):
        if len(packet) != 28:
            return None

        arp_detailed = unpack("!" "2H" "2B" "H" "6s" "4s" "6s" "4s", packet)

        try:
            return {
                "hardware-type": int(arp_detailed[0]),
                "protocol-type": int(arp_detailed[1]),
                "hardware-size": int(arp_detailed[2]),
                "protocol-size": int(arp_detailed[3]),
                "opcode":        int(arp_detailed[4]),
                "sender-mac":    self.eth.convert_mac(hexlify(arp_detailed[5])),
                "sender-ip":     inet_ntoa(arp_detailed[6]),
                "target-mac":    self.eth.convert_mac(hexlify(arp_detailed[7])),
                "target-ip":     inet_ntoa(arp_detailed[8])
            }
        except IndexError:
            return None

    def make_response(self, ethernet_src_mac, ethernet_dst_mac, sender_mac, sender_ip, target_mac, target_ip):
        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                sender_mac=sender_mac,
                                sender_ip=sender_ip,
                                target_mac=target_mac,
                                target_ip=target_ip,
                                opcode=2)

    def make_request(self, ethernet_src_mac, ethernet_dst_mac, sender_mac, sender_ip, target_mac, target_ip):
        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                sender_mac=sender_mac,
                                sender_ip=sender_ip,
                                target_mac=target_mac,
                                target_ip=target_ip,
                                opcode=1)
# endregion


# region Raw UDP
class UDP_raw:
    #  0                16               31
    #  +-----------------+-----------------+
    #  |     Source      |   Destination   |
    #  |      Port       |      Port       |
    #  +-----------------+-----------------+
    #  |                 |                 |
    #  |     Length      |    Checksum     |
    #  +-----------------+-----------------+
    #  |
    #  |          data octets ...
    #  +---------------- ...

    ipv6 = None
    header_type = 0
    header_length = 0

    def __init__(self):
        self.ipv6 = IPv6_raw()
        self.header_type = 17
        self.header_length = 8

    @staticmethod
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    @staticmethod
    def make_header(source_port, destination_port, data_length):
        if 0 < source_port < 65536 and 0 < destination_port < 65536:
            return pack("!4H", source_port, destination_port, data_length + 8, 0)
        else:
            return None

    @staticmethod
    def parse_header(packet):
        if len(packet) < 8:
            return None

        udp_detailed = unpack("!4H", packet[:8])

        try:
            return {
                "source-port":      int(udp_detailed[0]),
                "destination-port": int(udp_detailed[1]),
                "length":           int(udp_detailed[2]),
                "checksum":         int(udp_detailed[3]),
            }
        except IndexError:
            return None

    def make_header_with_ipv6_checksum(self, ipv6_src, ipv6_dst, port_src, port_dst, data_len, data):
        udp_header = self.make_header(port_src, port_dst, data_len)
        placeholder = 0
        protocol = IPPROTO_UDP
        data_length = data_len + self.header_length

        psh = self.ipv6.pack_addr(ipv6_src) + self.ipv6.pack_addr(ipv6_dst)
        psh += pack("!" "2B" "H", placeholder, protocol, data_length)
        chksum = self.checksum(psh + udp_header + data)

        return pack("!4H", port_src, port_dst, data_length, chksum)

# endregion


# region Raw TCP
class TCP_raw:
    timestamp_value = 0

    def __init__(self):
        with open('/proc/uptime', 'r') as uptime:
            self.timestamp_value = int(float(uptime.readline().split()[0]))

    def update_timestamp(self):
        with open('/proc/uptime', 'r') as uptime:
            self.timestamp_value = int(float(uptime.readline().split()[0]))

    @staticmethod
    def checksum(msg):
        s = 0
        if len(msg) % 2 == 1:
            msg += "\0"
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + (ord(msg[i + 1]))
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def make_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, flag, win, opt_exist=False, opt=None, data=""):

        reserved = 0
        window = win
        chksum = 0
        urg = 0

        if opt_exist:
            opt_len = len(opt) / 4
            offset = 5 + opt_len
        else:
            offset = 5

        tcp_header = pack("!" "2H" "2L" "2B" "3H",
                          port_src, port_dst, seq, ack, (offset << 4) + reserved, flag, window, chksum, urg)

        if opt_exist:
            tcp_header += opt

        source_address = inet_aton(ip_src)
        destination_address = inet_aton(ip_dst)
        placeholder = 0
        protocol = IPPROTO_TCP
        tcp_length = len(tcp_header) + len(data)
        psh = pack("!" "4s" "4s" "2B" "H", source_address, destination_address, placeholder, protocol, tcp_length)

        chksum = self.checksum(psh + tcp_header + data)

        tcp_header = pack("!" "2H" "2L" "2B" "3H",
                          port_src, port_dst, seq, ack, (offset << 4) + reserved, flag, window, chksum, urg)

        if opt_exist:
            return tcp_header + opt
        else:
            return tcp_header

    def make_syn_header(self, ip_src, ip_dst, port_src, port_dst, seq):
        option_mss = pack("!2B H", 2, 4, 1460)
        option_sack = pack("!2B", 4, 2)
        self.update_timestamp()
        option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, 0)
        option_nop = pack("!B", 1)
        option_scale = pack("!3B", 3, 3, 7)
        options = option_mss + option_sack + option_timestamp + option_nop + option_scale

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, 0, 2, 29200, True, options)

    def make_ack_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1):
        option_nop = pack("!B", 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 16, 29200, True, options)

    def make_psh_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1, data=""):
        option_nop = pack("!B", 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 24, 29200, False, options, data)

    def make_fin_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1):
        option_nop = pack("!B", 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 17, 29200, False, options)
# endregion


# region Raw ICMPv6
class ICMPv6_raw:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Type      |     Code      |          Checksum             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                         Message Body                          +
    # |                                                               |

    packet_type = 0
    eth = None
    ipv6 = None
    dns = None

    def __init__(self):
        self.packet_type = 58
        self.eth = Ethernet_raw()
        self.ipv6 = IPv6_raw()
        self.dns = DNS_raw()

    @staticmethod
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    @staticmethod
    def make_option(option_type, option_value):
        if (len(option_value) + 2) / 8 > 255:
            print "ICMPv6 option value too big!"
            return ""
        else:
            if (len(option_value) + 2) % 8 != 0:
                option_value = ''.join(pack("B", 0) for _ in range(8 - ((len(option_value) + 2) % 8))) + option_value
            return pack("!2B", option_type, (len(option_value) + 2) / 8) + option_value

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac,
                    ipv6_src, ipv6_dst, ipv6_flow, type, code, body):

        placeholder = 0
        protocol = IPPROTO_ICMPV6
        check_sum = 0
        icmp_packet = pack("!" "2B" "H", type, code, check_sum) + body

        psh = self.ipv6.pack_addr(ipv6_src) + self.ipv6.pack_addr(ipv6_dst)
        psh += pack("!" "2B" "H", placeholder, protocol, len(icmp_packet))
        check_sum = self.checksum(psh + icmp_packet)

        icmp_packet = pack("!" "2B" "H", type, code, check_sum) + body

        # 34525 = 0x86dd (IPv6)
        eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 34525)

        # 58 = 0x3a (ICMPv6)
        ipv6_header = self.ipv6.make_header(ipv6_src, ipv6_dst, ipv6_flow, len(icmp_packet), 58, 255)

        return eth_header + ipv6_header + icmp_packet

    def parse_packet(self, packet):
        if len(packet) < 4:
            return None

        offset = 4

        icmpv6_detailed = unpack("!" "2B" "H", packet[:offset])

        icmpv6_packet = {
            "type":     int(icmpv6_detailed[0]),
            "code":     int(icmpv6_detailed[1]),
            "checksum": int(icmpv6_detailed[2]),
        }

        # Type: 128 is Echo (ping) request, 129 is Echo (ping) reply
        if icmpv6_packet['type'] == 128 or icmpv6_packet['type'] == 129:
            if len(packet) >= offset + 4:
                icmpv6_ping_detailed = unpack("!2H", packet[offset:offset + 4])
                icmpv6_packet["identifier"] = int(icmpv6_ping_detailed[0])
                icmpv6_packet["sequence"] = int(icmpv6_ping_detailed[1])
                return icmpv6_packet

        if len(packet) <= offset + 4:
            return icmpv6_packet

        # 133 - Router Solicitation
        if icmpv6_packet['type'] == 133:
            return icmpv6_packet

        # 134 - Router Advertisement
        elif icmpv6_packet['type'] == 134:
            icmpv6_packet['hop-limit'] = int(unpack("B", packet[offset:offset + 1])[0])
            icmpv6_packet['flags'] = int(unpack("B", packet[offset + 1:offset + 2])[0])
            icmpv6_packet['router-lifetime'] = int(unpack("!H", packet[offset + 2:offset + 4])[0])
            icmpv6_packet['reachable-time'] = int(unpack("!I", packet[offset + 4:offset + 8])[0])
            icmpv6_packet['retrans-timer'] = int(unpack("!I", packet[offset + 8:offset + 12])[0])
            offset += 12

        # 135 - Neighbor Solicitation
        elif icmpv6_packet['type'] == 135:
            target_address = unpack("!16s", packet[offset + 4:offset + 20])[0]
            try:
                icmpv6_packet['target-address'] = inet_ntop(AF_INET6, target_address)
            except sock_error:
                icmpv6_packet['target-address'] = None
            return icmpv6_packet

        # Analyze ICMPv6 options
        if icmpv6_packet['type'] == 134:
            options = []

            while offset < len(packet):
                option_type = int(unpack("B", packet[offset:offset + 1])[0])
                option_length = int(unpack("B", packet[offset + 1:offset + 2])[0])

                if option_type == 1:
                    option_value = self.eth.convert_mac(hexlify(packet[offset + 2:offset + 8]))

                elif option_type == 3:
                    option_detailed = unpack("!" "2B" "3I" "16s", packet[offset + 2:offset + 32])
                    option_value = {
                        "prefix-length": int(option_detailed[0]),
                        "flag": int(option_detailed[1]),
                        "valid-lifetime": int(option_detailed[2]),
                        "reserved-lifetime": int(option_detailed[3]),
                        "prefix": inet_ntop(AF_INET6, option_detailed[5])
                    }

                elif option_type == 25:
                    option_detailed = unpack("!" "H" "I" "16s", packet[offset + 2:offset + 24])
                    option_value = {
                        "lifetime": int(option_detailed[1]),
                        "address": inet_ntop(AF_INET6, option_detailed[2])
                    }

                else:
                    option_value = hexlify(packet[offset + 2:offset + option_length * 8])

                offset += option_length * 8

                options.append({
                    'type': option_type,
                    'value': option_value
                })

            icmpv6_packet['options'] = options
            return icmpv6_packet

        else:
            return icmpv6_packet

    def make_router_solicit_packet(self, ethernet_src_mac, ipv6_src,
                                   need_source_link_layer_address=False, source_link_layer_address=""):

        body = pack("I", 0)             # 4 reserved bytes
        if need_source_link_layer_address:
            body += pack("!" "2B", 1, 1)    # 1 - Type: source link address, 1 - Length = 1 (8 bytes)

            if source_link_layer_address == "":
                body += self.eth.convert_mac(ethernet_src_mac)
            else:
                body += self.eth.convert_mac(source_link_layer_address)

        return self.make_packet(ethernet_src_mac, "33:33:00:00:00:02", ipv6_src, "ff02::2", 0x835d1, 133, 0, body)

    def make_router_advertisement_packet(self, ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst,
                                         dns_address, domain_search, prefix=None, ipv6_addr=None, mtu=1500,
                                         advertisement_interval=60000, src_link_layer_address=None,
                                         router_lifetime=0, reachable_time=0, retrans_timer=0):
        cur_hop_limit = 64  # Cur hop limit
        flags = 0xc0        # Managed address configuration, other configuration, PRF: Medium

        body = pack("!" "2B" "H" "2I", cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer)

        if src_link_layer_address is None:
            src_link_layer_address = ethernet_src_mac

        if prefix is not None:
            prefix_value = self.ipv6.pack_addr(str(prefix.split("/")[0]))
            prefix_len = int(prefix.split("/")[1])
            body += self.make_option(3, pack("!" "2B" "3I", prefix_len, 0xc0, 0xffffffff, 0xffffffff, 0) + prefix_value)
            if ipv6_addr is not None:
                body += self.make_option(17, pack("!" "2B" "I", 3, prefix_len, 0) + self.ipv6.pack_addr(ipv6_addr))

        body += self.make_option(1, self.eth.convert_mac(src_link_layer_address))
        body += self.make_option(5, pack("!H", mtu))
        body += self.make_option(25, pack("!H", 6000) + self.ipv6.pack_addr(dns_address))

        if len(domain_search) > 22:
            print "Too big domain search value!"
        else:
            domain_search = self.dns.make_dns_name(domain_search)
            padding = 24 - len(domain_search)
            domain_search += ''.join(pack("B", 0) for _ in range(padding))
            body += self.make_option(31, pack("!I", 6000) + domain_search)

        body += self.make_option(7, pack("!H", advertisement_interval))

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, 0xb4755, 134, 0, body)

    def make_neighbor_solicitation_packet(self, ethernet_src_mac, ipv6_src, target_ipv6_address=None,
                                          icmpv6_source_mac_address=None, ethernet_dst_mac=None, ipv6_dst=None):
        body = pack("!I", 0x00000000)  # Reserved

        if target_ipv6_address is not None:
            body += self.ipv6.pack_addr(target_ipv6_address)

        if icmpv6_source_mac_address is not None:
            body += self.make_option(2, self.eth.convert_mac(icmpv6_source_mac_address))  # Source link-layer address

        if ethernet_dst_mac is None:
            ethernet_dst_mac = "33:33:00:00:00:01"

        if ipv6_dst is None:
            ipv6_dst = "ff02::1"

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, 0, 135, 0, body)

    def make_neighbor_advertisement_packet(self, ethernet_src_mac, ipv6_src, target_ipv6_address,
                                           ethernet_dst_mac=None, ipv6_dst=None):
        body = pack("!I", 0x20000000)   # Flags: 0x20000000, Override
        body += self.ipv6.pack_addr(target_ipv6_address)
        body += self.make_option(2, self.eth.convert_mac(ethernet_src_mac))  # Target link-layer address

        if ethernet_dst_mac is None:
            ethernet_dst_mac = "33:33:00:00:00:01"

        if ipv6_dst is None:
            ipv6_dst = "ff02::1"

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, 0, 136, 0, body)

    def make_echo_request_packet(self, ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, id, sequence=1):
        body = pack("!2H", id, sequence)
        for index in range(0, 56, 1):
            body += pack("B", index)
        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, 0, 128, 0, body)

    def make_echo_reply_packet(self, ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, id, sequence=1, data=None):
        body = pack("!2H", id, sequence)
        if data is None:
            for index in range(0, 56, 1):
                body += pack("B", index)
        else:
            body += data
        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ipv6_src, ipv6_dst, 0, 129, 0, body)

    # def make_dad_packet(self, ethernet_src_mac, target_ipv6_address):
    #     body = pack("I", 0)             # 4 reserved bytes
    #     body += self.ipv6.pack_addr(target_ipv6_address)
    #     body += self.make_option(14, pack("!IH", 0x1f06928c, 0x6f45))
    #
    #     return self.make_packet(ethernet_src_mac, "33:33:ff:00:03:2e",
    #                             "::", "ff02::1:ff00:32e", 0, 135, 0, body)

# endregion


# region Raw DHCPv6
class DHCPv6_raw:
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |   Message   |                   Data :::                      |
    # +-------------+-------------------------------------------------+

    # DHCPv6 Message Types
    # 0	    Reserved
    # 1	    SOLICIT	            [RFC3315]
    # 2	    ADVERTISE	        [RFC3315]
    # 3	    REQUEST	            [RFC3315]
    # 4	    CONFIRM	            [RFC3315]
    # 5	    RENEW	            [RFC3315]
    # 6	    REBIND	            [RFC3315]
    # 7	    REPLY	            [RFC3315]
    # 8	    RELEASE	            [RFC3315]
    # 9	    DECLINE	            [RFC3315]
    # 10	RECONFIGURE	        [RFC3315]
    # 11	INFORMATION-REQUEST	[RFC3315]
    # 12	RELAY-FORW	        [RFC3315]
    # 13	RELAY-REPL	        [RFC3315]
    # 14	LEASEQUERY	        [RFC5007]
    # 15	LEASEQUERY-REPLY	[RFC5007]
    # 16	LEASEQUERY-DONE	    [RFC5460]
    # 17	LEASEQUERY-DATA	    [RFC5460]
    # 18	RECONFIGURE-REQUEST [RFC6977]
    # 19	RECONFIGURE-REPLY	[RFC6977]
    # 20	DHCPV4-QUERY	    [RFC7341]
    # 21	DHCPV4-RESPONSE	    [RFC7341]
    # 22	ACTIVELEASEQUERY	[RFC7653]
    # 23	STARTTLS	        [RFC7653]
    # 24	BNDUPD	            [RFC8156]
    # 25	BNDREPLY	        [RFC8156]
    # 26	POOLREQ	            [RFC8156]
    # 27	POOLRESP	        [RFC8156]
    # 28	UPDREQ	            [RFC8156]
    # 29	UPDREQALL	        [RFC8156]
    # 30	UPDDONE	            [RFC8156]
    # 31	CONNECT	            [RFC8156]
    # 32	CONNECTREPLY	    [RFC8156]
    # 33	DISCONNECT	        [RFC8156]
    # 34	STATE	            [RFC8156]
    # 35	CONTACT	            [RFC8156]
    # 36-255	Unassigned

    eth = None
    ipv6 = None
    udp = None
    dns = None

    def __init__(self):
        self.eth = Ethernet_raw()
        self.ipv6 = IPv6_raw()
        self.udp = UDP_raw()
        self.dns = DNS_raw()

    def get_duid(self, mac_address, timeval=None):
        Hardware_type = 1   # Ethernet
        if timeval is None:
            DUID_type = 3   # Link-Layer address
            return pack("!" "2H", DUID_type, Hardware_type) + self.eth.convert_mac(mac_address)
        else:
            DUID_type = 1   # Link-Layer address plus time
            return pack("!" "2H" "I", DUID_type, Hardware_type, timeval) + self.eth.convert_mac(mac_address)

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac,
                    ipv6_src, ipv6_dst, ipv6_flow, udp_src_port, udp_dst_port,
                    dhcp_message_type, packet_body, options, options_raw=""):
        dhcp_packet = pack("!B", dhcp_message_type)
        dhcp_packet += packet_body

        if options_raw == "":
            for option_code in options.keys():
                dhcp_packet += pack("!" "2H", int(option_code), len(options[option_code]))
                dhcp_packet += options[option_code]
        else:
            dhcp_packet += options_raw

        eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 34525)  # 34525 = 0x86dd (IPv6)
        ipv6_header = self.ipv6.make_header(ipv6_src, ipv6_dst, ipv6_flow, len(dhcp_packet) + 8, 17)  # 17 = 0x11 (UDP)
        udp_header = self.udp.make_header_with_ipv6_checksum(ipv6_src, ipv6_dst, udp_src_port, udp_dst_port,
                                                             len(dhcp_packet), dhcp_packet)

        return eth_header + ipv6_header + udp_header + dhcp_packet

    def parse_packet(self, packet):
        if len(packet) < 4:
            return None

        offset = 4

        type_and_id = int(unpack("!L", packet[:offset])[0])
        message_type = int(int(type_and_id & 0b11111111000000000000000000000000) >> 24)
        transaction_id = int(type_and_id & 0b00000000111111111111111111111111)

        dhcpv6_packet = {
            "message-type":   message_type,
            "transaction-id": transaction_id
        }

        options = []

        while offset < len(packet):
            option_type = int(unpack("!H", packet[offset:offset + 2])[0])
            option_length = int(unpack("!H", packet[offset + 2:offset + 4])[0])
            offset += 4

            if option_type == 1:
                option_detailed = unpack("!" "2H" "L" "6s", packet[offset:offset + 14])
                option_value = {
                    "duid-type": int(option_detailed[0]),
                    "hardware-type": int(option_detailed[1]),
                    "duid-time": int(option_detailed[2]),
                    "mac-address": self.eth.convert_mac(hexlify(option_detailed[3]))
                }

            elif option_type == 2:
                option_detailed = unpack("!" "2H" "6s", packet[offset:offset + 10])
                option_value = {
                    "duid-type": int(option_detailed[0]),
                    "duid-time": int(option_detailed[1]),
                    "mac-address": self.eth.convert_mac(hexlify(option_detailed[2]))
                }

            elif option_type == 3:
                try:
                    option_detailed = unpack("!" "16s", packet[offset + 16:offset + 32])
                    option_value = {
                        "ipv6-address": inet_ntop(AF_INET6, option_detailed[0])
                    }
                except struct_error:
                    option_value = {
                        "ipv6-address": None
                    }

            elif option_type == 8:
                option_detailed = unpack("!H", packet[offset:offset + 2])
                option_value = {
                    "elapsed-time": int(option_detailed[0]),
                }

            else:
                option_value = hexlify(packet[offset:offset + option_length])

            offset += option_length

            options.append({
                'type': option_type,
                'value': option_value
            })

        dhcpv6_packet['options'] = options

        return dhcpv6_packet

    def make_solicit_packet(self, ethernet_src_mac, ipv6_src, transaction_id, client_identifier, option_request_list):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack("!L", transaction_id)[1:]
        options = {}

        options[3] = pack("!" "3Q", 0, 0, 0)  # Identity Association for Non-temporary Address
        options[14] = ""                      # Rapid commit
        options[8] = pack("!H", 0)            # Elapsed time
        options[1] = client_identifier        # Client identifier

        option_request_string = ""
        for option_request in option_request_list:
            option_request_string += pack("!H", option_request)

        options[6] = option_request_string  # Options request

        return self.make_packet(ethernet_src_mac, "33:33:00:01:00:02",
                                ipv6_src, "ff02::1:2", 0, 546, 547,
                                1, packet_body, options)

    def make_relay_forw_packet(self, ethernet_src_mac, ethernet_dst_mac,
                               ipv6_src, ipv6_dst, ipv6_flow,
                               hop_count, link_addr, peer_addr, options, options_raw=""):
        packet_body = pack("!B", hop_count) + self.ipv6.pack_addr(link_addr) + self.ipv6.pack_addr(peer_addr)
        return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                ipv6_src, ipv6_dst, ipv6_flow, 546, 547,
                                12, packet_body, options, options_raw)

    def make_advertise_packet(self, ethernet_src_mac, ethernet_dst_mac,
                              ipv6_src, ipv6_dst, transaction_id, dns_address,
                              domain_search, ipv6_address, client_duid_timeval=None, server_duid_mac=None):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack("!L", transaction_id)[1:]
        options = {}

        if client_duid_timeval is None:
            options[1] = self.get_duid(ethernet_dst_mac)                       # Client Identifier
        else:
            options[1] = self.get_duid(ethernet_dst_mac, client_duid_timeval)  # Client Identifier

        if server_duid_mac is None:
            options[2] = self.get_duid(ethernet_src_mac)  # Server Identifier
        else:
            options[2] = self.get_duid(server_duid_mac)        # Server Identifier

        options[20] = ""                                     # Reconfigure Accept
        options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
        options[24] = self.dns.make_dns_name(domain_search)  # Domain search list
        options[82] = pack("!I", 0x3c)                       # SOL_MAX_RT

        options[3] = pack("!" "3I" "2H", 1, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
                     pack("!2I", 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                ipv6_src, ipv6_dst,
                                0xa1b82, 547, 546, 2,
                                packet_body, options)

    def make_reply_packet(self, ethernet_src_mac, ethernet_dst_mac,
                              ipv6_src, ipv6_dst, transaction_id, dns_address,
                              domain_search, ipv6_address, client_duid_timeval=None, server_duid_mac=None):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack("!L", transaction_id)[1:]
        options = {}

        if client_duid_timeval is None:
            options[1] = self.get_duid(ethernet_dst_mac)                       # Client Identifier
        else:
            options[1] = self.get_duid(ethernet_dst_mac, client_duid_timeval)  # Client Identifier

        if server_duid_mac is None:
            options[2] = self.get_duid(ethernet_src_mac)  # Server Identifier
        else:
            options[2] = self.get_duid(server_duid_mac)   # Server Identifier

        options[20] = ""                                     # Reconfigure Accept
        options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
        options[24] = self.dns.make_dns_name(domain_search)  # Domain search list
        options[82] = pack("!I", 0x3c)                       # SOL_MAX_RT

        options[3] = pack("!" "3I" "2H", 1, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
                     pack("!2I", 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                ipv6_src, ipv6_dst,
                                0xa1b82, 547, 546, 7,
                                packet_body, options)

    # def make_reconfigure_packet(self, ethernet_src_mac, ethernet_dst_mac,
    #                             ipv6_src, ipv6_dst, transaction_id, dns_address,
    #                             domain_search, ipv6_address):
    #     if 16777215 < transaction_id < 0:
    #         return None
    #
    #     packet_body = pack("!L", transaction_id)[1:]
    #     options = {}
    #
    #     options[1] = self.get_duid(ethernet_dst_mac)                       # Client Identifier
    #     options[2] = self.get_duid(ethernet_src_mac)  # Server Identifier
    #
    #     options[20] = ""                                     # Reconfigure Accept
    #     options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
    #     options[24] = self.dns.make_dns_name(domain_search)  # Domain search list
    #     options[82] = pack("!I", 0x3c)                       # SOL_MAX_RT
    #
    #     options[3] = pack("!" "3I" "2H", 1, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
    #                  pack("!2I", 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address
    #
    #     return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
    #                             ipv6_src, ipv6_dst,
    #                             0xa1b82, 547, 546, 10,
    #                             packet_body, options)
# endregion


# region Raw ICMP
class ICMP_raw:
    eth = None
    ip = None
    udp = None

    def __init__(self):
        self.eth = Ethernet_raw()
        self.ip = IP_raw()
        self.udp = UDP_raw()

    @staticmethod
    def checksum(msg):
        s = 0
        if len(msg) % 2 == 1:
            msg += "\0"
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + (ord(msg[i + 1]))
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, icmp_type, icmp_code, data=None):
        try:
            check_sum = 0x0000
            unused = 0x00000000

            if icmp_type != 0x05:
                icmp_packet = pack("!" "2B" "H" "I", icmp_type, icmp_code, check_sum, unused)
            else:
                icmp_packet = pack("!" "2B" "H", icmp_type, icmp_code, check_sum)

            if data is not None:
                icmp_packet += data

            check_sum = self.checksum(icmp_packet)

            if icmp_type != 0x05:
                icmp_packet = pack("!" "2B" "H" "I", icmp_type, icmp_code, check_sum, unused)
            else:
                icmp_packet = pack("!" "2B" "H", icmp_type, icmp_code, check_sum)

            if data is not None:
                icmp_packet += data

            eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 2048)
            ip_header = self.ip.make_header(ip_src, ip_dst, len(icmp_packet) - 8, 8, 1)

            return eth_header + ip_header + icmp_packet
        except sock_error:
            return None

    def make_host_unreachable_packet(self, ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, data=None):
        try:
            if data is not None:
                ip_data = self.ip.make_header(ip_dst, ip_src, len(data), 8, 17)
                icmp_data = ip_data + data
            else:
                ip_data = self.ip.make_header(ip_dst, ip_src, 0, 8, 1)
                icmp_data = ip_data

            return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, 0x03, 0x01, icmp_data)
        except sock_error:
            return None

    def make_udp_port_unreachable_packet(self, ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst,
                                         udp_src_port, udp_dst_port, data=None):
        try:
            if data is not None:
                udp_data = self.udp.make_header(udp_src_port, udp_dst_port, len(data))
                ip_data = self.ip.make_header(ip_dst, ip_src, len(udp_data) + len(data), 8, 17)
                icmp_data = ip_data + udp_data + data
            else:
                udp_data = self.udp.make_header(udp_src_port, udp_dst_port, 0)
                ip_data = self.ip.make_header(ip_dst, ip_src, len(udp_data), 8, 17)
                icmp_data = ip_data + udp_data

            return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, 0x03, 0x03, icmp_data)
        except sock_error:
            return None

    def make_ping_request_packet(self, ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst):
        try:
            icmp_data = pack("!Q", int(time()))
            for index in range(0, 32, 1):
                icmp_data += pack("B", index)

            return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, 0x08, 0x00, icmp_data)
        except sock_error:
            return None

    def make_redirect_packet(self, ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, gateway_address,
                             payload_ip_src, payload_ip_dst, payload_port_src=53, payload_port_dst=53):
        icmp_data = inet_aton(gateway_address)
        icmp_data += self.ip.make_header(payload_ip_src, payload_ip_dst, 0, 8, 17)
        icmp_data += self.udp.make_header(payload_port_src, payload_port_dst, 0)
        return self.make_packet(ethernet_src_mac, ethernet_dst_mac, ip_src, ip_dst, 0x05, 0x01, icmp_data)

# endregion


# region Raw DHCP
class DHCP_raw:
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
    # +---------------+---------------+---------------+---------------+
    # |                            xid (4)                            |
    # +-------------------------------+-------------------------------+
    # |           secs (2)            |           flags (2)           |
    # +-------------------------------+-------------------------------+
    # |                          ciaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          yiaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          siaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          giaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          chaddr  (16)                         |
    # |                                                               |
    # |                                                               |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          sname   (64)                         |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          file    (128)                        |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          options (variable)                   |
    # +---------------------------------------------------------------+

    # FIELD      OCTETS       DESCRIPTION
    # -----      ------       -----------
    #
    # op            1  Message op code / message type.
    #                  1 = BOOTREQUEST, 2 = BOOTREPLY
    # htype         1  Hardware address type, see ARP section in "Assigned
    #                  Numbers" RFC; e.g., '1' = 10mb ethernet.
    # hlen          1  Hardware address length (e.g.  '6' for 10mb
    #                  ethernet).
    # hops          1  Client sets to zero, optionally used by relay agents
    #                  when booting via a relay agent.
    # xid           4  Transaction ID, a random number chosen by the
    #                  client, used by the client and server to associate
    #                  messages and responses between a client and a
    #                  server.
    # secs          2  Filled in by client, seconds elapsed since client
    #                  began address acquisition or renewal process.
    # flags         2  Flags (see figure 2).
    # ciaddr        4  Client IP address; only filled in if client is in
    #                  BOUND, RENEW or REBINDING state and can respond
    #                  to ARP requests.
    # yiaddr        4  'your' (client) IP address.
    # siaddr        4  IP address of next server to use in bootstrap;
    #                  returned in DHCPOFFER, DHCPACK by server.
    # giaddr        4  Relay agent IP address, used in booting via a
    #                  relay agent.
    # chaddr       16  Client hardware address.
    # sname        64  Optional server host name, null terminated string.
    # file        128  Boot file name, null terminated string; "generic"
    #                  name or null in DHCPDISCOVER, fully qualified
    #                  directory-path name in DHCPOFFER.
    # options     var  Optional parameters field.  See the options
    #                  documents for a list of defined options.

    eth = None
    ip = None
    udp = None

    def __init__(self):
        self.eth = Ethernet_raw()
        self.ip = IP_raw()
        self.udp = UDP_raw()

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac,
                    ip_src, ip_dst, udp_src_port, udp_dst_port,
                    bootp_message_type, bootp_transaction_id, bootp_flags,
                    bootp_client_ip, bootp_your_client_ip, bootp_next_server_ip,
                    bootp_relay_agent_ip, bootp_client_hw_address, dhcp_options, padding=0):

        try:
            message_type = bootp_message_type  # Boot protocol message type
            hardware_type = 1  # Ethernet
            hardware_address_len = 6  # Ethernet address len
            hops = 0  # Number of hops
            transaction_id = bootp_transaction_id  # Transaction id
            seconds_elapsed = 0  # Seconds elapsed
            flags = bootp_flags  # Flags

            CIADDR = inet_aton(bootp_client_ip)  # Client IP address
            YIADDR = inet_aton(bootp_your_client_ip)  # Your client IP address
            SIADDR = inet_aton(bootp_next_server_ip)  # Next server IP address
            GIADDR = inet_aton(bootp_relay_agent_ip)  # Relay agent IP address
            CHADDR = self.eth.convert_mac(bootp_client_hw_address)  # Client hardware address

            # Test case
            # test_command = bytes("() { :; }; echo test > /tmp/test ")
            # test_command = pack("!%ds" % (len(test_command)), test_command)

            client_hw_padding = ''.join(pack("B", 0) for _ in range(10))  # Client hardware address padding
            server_host_name = ''.join(pack("B", 0) for _ in range(64))  # Server host name
            boot_file_name = ''.join(pack("B", 0) for _ in range(128))  # Boot file name
            magic_cookie = pack("!4B", 99, 130, 83, 99)  # Magic cookie: DHCP

            dhcp_packet = pack("!" "4B" "L" "2H",
                               message_type, hardware_type, hardware_address_len, hops, transaction_id,
                               seconds_elapsed, flags)

            dhcp_packet += pack("!" "4s" "4s" "4s" "4s",
                                CIADDR, YIADDR, SIADDR, GIADDR) + CHADDR

            dhcp_packet += client_hw_padding + server_host_name + boot_file_name + magic_cookie

            if padding != 0:
                dhcp_packet += dhcp_options + ''.join(pack("B", 0) for _ in range(int(padding)))
            else:
                dhcp_packet += dhcp_options + ''.join(pack("B", 0) for _ in range(24))

            eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 2048)
            ip_header = self.ip.make_header(ip_src, ip_dst, len(dhcp_packet), 8, 17)
            udp_header = self.udp.make_header(udp_src_port, udp_dst_port, len(dhcp_packet))

            return eth_header + ip_header + udp_header + dhcp_packet
        except sock_error:
            return None

    def parse_packet(self, packet):
        bootp_packet_length = 236
        bootp_short_packet_length = 34

        dhcp_packet_start = 240
        dhcp_magic_cookie = '63825363'

        if len(packet) < bootp_packet_length:
            return None

        bootp_detailed = unpack("!" "4B" "I" "2H" "4s" "4s" "4s" "4s" "6s",
                                packet[:bootp_short_packet_length])

        bootp_packet = {
            "message-type":            int(bootp_detailed[0]),
            "hardware-type":           int(bootp_detailed[1]),
            "hardware-address-length": int(bootp_detailed[2]),
            "hops":                    int(bootp_detailed[3]),

            "transaction-id":          int(bootp_detailed[4]),

            "seconds-elapsed":         int(bootp_detailed[5]),
            "flags":                   int(bootp_detailed[6]),

            "client-ip-address":       inet_ntoa(bootp_detailed[7]),
            "your-ip-address":         inet_ntoa(bootp_detailed[8]),
            "server-ip-address":       inet_ntoa(bootp_detailed[9]),
            "relay-ip-address":        inet_ntoa(bootp_detailed[10]),

            "client-mac-address":      self.eth.convert_mac(hexlify(bootp_detailed[11]))
        }

        dhcp_packet = {}

        if len(packet) > 240:
            magic_cookie = hexlify(unpack("!4s", packet[bootp_packet_length:dhcp_packet_start])[0])
            if magic_cookie == dhcp_magic_cookie:

                position = dhcp_packet_start

                while position < len(packet) - 1:
                    option_name = int(unpack("B", packet[position:position + 1])[0])
                    position += 1

                    # 255 - End
                    if option_name == 255:
                        break

                    # 12 - Host name
                    elif option_name == 12:
                        option_length = int(unpack("B", packet[position:position + 1])[0])
                        position += 1
                        option_value = "".join([str(x) for x in packet[position:position + option_length]])
                        position += option_length

                    # 50 - Requested IP
                    elif option_name == 50:
                        option_value = inet_ntoa(unpack("4s", packet[position + 1:position + 5])[0])
                        position += 5

                    # 51 - Lease time
                    elif option_name == 51:
                        option_value = int(unpack("I", packet[position + 1:position + 5])[0])
                        position += 5

                    # 53 - Message type
                    elif option_name == 53:
                        option_value = int(unpack("B", packet[position + 1:position + 2])[0])
                        position += 2

                    # 57 - Maximum DHCP message size
                    elif option_name == 57:
                        option_value = int(unpack("H", packet[position + 1:position + 3])[0])
                        position += 3

                    # 61 - Client identifier
                    elif option_name == 61:
                        option_value = self.eth.convert_mac(hexlify(unpack("6s", packet[position + 2:position + 8])[0]))
                        position += 8

                    else:
                        option_length = int(unpack("B", packet[position:position + 1])[0])
                        position += 1
                        option_value = "".join([hexlify(x) for x in packet[position:position + option_length]])
                        position += option_length

                    dhcp_packet[option_name] = option_value

        return {
            "BOOTP": bootp_packet,
            "DHCP": dhcp_packet
        }

    def make_discover_packet(self, ethernet_src_mac, client_mac, host_name=None, relay_ip=None,
                             ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                             ip_src="0.0.0.0", ip_dst="255.255.255.255",
                             udp_src_port=68, udp_dst_port=67, transaction_id=0):

        relay_agent_ip_address = "0.0.0.0"
        if relay_ip is not None:
            relay_agent_ip_address = relay_ip

        option_discover = pack("!3B", 53, 1, 1)
        options = option_discover

        if host_name is not None:
            host_name = bytes(host_name)
            if len(host_name) < 255:
                host_name = pack("!%ds" % (len(host_name)), host_name)
                option_host_name = pack("!2B", 12, len(host_name)) + host_name
                options += option_host_name

        option_param_req_list = pack("!2B", 55, 254)
        for param in range(1, 255):
            option_param_req_list += pack("B", param)

        option_end = pack("B", 255)

        options += option_param_req_list + option_end

        if transaction_id == 0:
            trid = randint(1, 4294967295)
        else:
            trid = transaction_id

        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                ip_src=ip_src, ip_dst=ip_dst,
                                udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                bootp_message_type=1,
                                bootp_transaction_id=trid,
                                bootp_flags=0,
                                bootp_client_ip="0.0.0.0",
                                bootp_your_client_ip="0.0.0.0",
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip=relay_agent_ip_address,
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_request_packet(self, source_mac, client_mac, transaction_id, dhcp_message_type=1, host_name=None,
                            requested_ip=None, option_value=None, option_code=12,
                            client_ip="0.0.0.0", your_client_ip="0.0.0.0", relay_agent_ip="0.0.0.0"):
        option_message_type = pack("!3B", 53, 1, dhcp_message_type)
        options = option_message_type

        if requested_ip is not None:
            option_requested_ip = pack("!" "2B" "4s", 50, 4, inet_aton(requested_ip))
            options += option_requested_ip

        if host_name is not None:
            host_name = bytes(host_name)
            if len(host_name) < 255:
                host_name = pack("!%ds" % (len(host_name)), host_name)
                option_host_name = pack("!2B", 12, len(host_name)) + host_name
                options += option_host_name

        if option_value is not None:
            if len(option_value) < 255:
                if 0 < option_code < 256:
                    option_payload = pack("!" "2B", option_code, len(option_value)) + option_value
                    options += option_payload

        option_param_req_list = pack("!2B", 55, 7)
        for param in [1, 2, 3, 6, 28, 15, 26]:
            option_param_req_list += pack("B", param)

        option_end = pack("B", 255)

        options += option_param_req_list + option_end

        return self.make_packet(ethernet_src_mac=source_mac,
                                ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                                ip_src="0.0.0.0", ip_dst="255.255.255.255",
                                udp_src_port=68, udp_dst_port=67,
                                bootp_message_type=1,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip=client_ip,
                                bootp_your_client_ip=your_client_ip,
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip=relay_agent_ip,
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_release_packet(self, client_mac, server_mac, client_ip, server_ip):
        option_message_type = pack("!3B", 53, 1, 7)
        option_server_id = pack("!" "2B" "4s", 54, 4, inet_aton(server_ip))
        option_end = pack("B", 255)

        options = option_message_type + option_server_id + option_end

        return self.make_packet(ethernet_src_mac=client_mac,
                                ethernet_dst_mac=server_mac,
                                ip_src=client_ip, ip_dst=server_ip,
                                udp_src_port=68, udp_dst_port=67,
                                bootp_message_type=1,
                                bootp_transaction_id=randint(1, 4294967295),
                                bootp_flags=0,
                                bootp_client_ip="0.0.0.0",
                                bootp_your_client_ip="0.0.0.0",
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip="0.0.0.0",
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_decline_packet(self, relay_mac, relay_ip, server_mac, server_ip, client_mac, requested_ip, transaction_id):
        option_message_type = pack("!3B", 53, 1, 4)
        option_requested_ip = pack("!" "2B" "4s", 50, 4, inet_aton(requested_ip))
        option_server_id = pack("!" "2B" "4s", 54, 4, inet_aton(server_ip))
        option_end = pack("B", 255)

        options = option_message_type + option_requested_ip + option_server_id + option_end

        return self.make_packet(ethernet_src_mac=relay_mac,
                                ethernet_dst_mac=server_mac,
                                ip_src=relay_ip, ip_dst=server_ip,
                                udp_src_port=68, udp_dst_port=67,
                                bootp_message_type=1,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip=requested_ip,
                                bootp_your_client_ip="0.0.0.0",
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip=relay_ip,
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_response_packet(self, source_mac, destination_mac, source_ip, destination_ip, transaction_id, your_ip,
                             client_mac, dhcp_server_id, lease_time, netmask, router, dns, dhcp_operation=2,
                             payload=None, proxy=None, domain=None, tftp=None, wins=None, payload_option_code=114):
        option_operation = pack("!3B", 53, 1, dhcp_operation)
        option_server_id = pack("!" "2B" "4s", 54, 4, inet_aton(dhcp_server_id))
        option_lease_time = pack("!" "2B" "L", 51, 4, lease_time)
        option_netmask = pack("!" "2B" "4s", 1, 4, inet_aton(netmask))
        option_router = pack("!" "2B" "4s", 3, 4, inet_aton(router))
        option_dns = pack("!" "2B" "4s", 6, 4, inet_aton(dns))
        option_end = pack("B", 255)

        options = option_operation + option_server_id + option_lease_time + option_netmask + \
                  option_router + option_dns

        if domain is not None:
            if len(domain) < 255:
                option_domain = pack("!" "2B", 15, len(domain)) + domain
                options += option_domain

        if proxy is not None:
            if len(proxy) < 255:
                option_proxy = pack("!" "2B", 252, len(proxy)) + proxy
                options += option_proxy

        if payload is not None:
            if len(payload) < 255:
                if 0 < payload_option_code < 256:
                    option_payload = pack("!" "2B", payload_option_code, len(payload)) + payload
                    options += option_payload

        if tftp is not None:
            if len(tftp) < 255:
                option_tftp = pack("!" "2B" "4s", 150, 4, inet_aton(tftp))
                options += option_tftp

        if wins is not None:
            if len(wins) < 255:
                # NetBIOS over TCP/IP Name Server Option
                # https://tools.ietf.org/html/rfc1533#section-8.5
                option_wins = pack("!" "2B" "4s", 44, 4, inet_aton(wins))

                # NetBIOS over TCP/IP Datagram Distribution Server Option
                # https://tools.ietf.org/html/rfc1533#section-8.6
                option_wins += pack("!" "2B" "4s", 45, 4, inet_aton(wins))

                # NetBIOS over TCP/IP Node Type Option
                # https://tools.ietf.org/html/rfc1533#section-8.7
                # 0x2 - P-node (POINT-TO-POINT (P) NODES)
                # https://tools.ietf.org/html/rfc1001#section-10.2
                option_wins += pack("!" "3B", 46, 1, 0x2)

                # Add WINS option in all options
                options += option_wins

        options += option_end

        return self.make_packet(ethernet_src_mac=source_mac,
                                ethernet_dst_mac=destination_mac,
                                ip_src=source_ip, ip_dst=destination_ip,
                                udp_src_port=67, udp_dst_port=68,
                                bootp_message_type=2,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip="0.0.0.0",
                                bootp_your_client_ip=your_ip,
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip="0.0.0.0",
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_nak_packet(self, source_mac, destination_mac, source_ip, destination_ip, transaction_id, your_ip,
                        client_mac, dhcp_server_id):
        option_operation = pack("!3B", 53, 1, 6)
        option_server_id = pack("!" "2B" "4s", 54, 4, inet_aton(dhcp_server_id))
        option_end = pack("B", 255)
        options = option_operation + option_server_id + option_end

        return self.make_packet(ethernet_src_mac=source_mac,
                                ethernet_dst_mac=destination_mac,
                                ip_src=source_ip, ip_dst=destination_ip,
                                udp_src_port=67, udp_dst_port=68,
                                bootp_message_type=2,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip="0.0.0.0",
                                bootp_your_client_ip=your_ip,
                                bootp_next_server_ip="0.0.0.0",
                                bootp_relay_agent_ip="0.0.0.0",
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)
# endregion


# region Raw DNS
class DNS_raw:

    Base = None
    eth = None
    ip = None
    ipv6 = None
    udp = None

    def __init__(self):
        self.Base = Base()
        self.eth = Ethernet_raw()
        self.ip = IP_raw()
        self.ipv6 = IPv6_raw()
        self.udp = UDP_raw()

    @staticmethod
    def make_dns_name(name):
        name_list = name.split(".")
        result_name = ""
        for part_of_name in name_list:
            if len(part_of_name) > 256:
                return ""
            else:
                result_name += pack("!" "B" "%ds" % (len(part_of_name)), len(part_of_name), part_of_name)
        result_name += "\x00"
        return result_name

    @staticmethod
    def make_dns_ptr(ip_address):
        pass

    def make_response_packet(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, tid, flags,
                             queries=[], answers_address=[], name_servers={}):
        transaction_id = tid
        dns_flags = flags
        questions = len(queries)
        answer_rrs = len(answers_address)
        authority_rrs = len(name_servers.keys())
        additional_rrs = len(name_servers.keys())

        dns_packet = pack("!6H", transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)

        query_type = 1

        for query in queries:
            query_name = query["name"]
            query_type = query["type"]
            query_class = query["class"]

            if query_name.endswith("."):
                query_name = query_name[:-1]

            dns_packet += self.make_dns_name(query_name)
            dns_packet += pack("!2H", query_type, query_class)

        if query_type == 1:
            for address in answers_address:
                if "name" in address.keys():
                    dns_packet += self.make_dns_name(address["name"])
                else:
                    dns_packet += pack("!H", 0xc00c)

                dns_packet += pack("!" "2H" "I" "H" "4s", address["type"], address["class"], address["ttl"],
                                   4, inet_aton(address["address"]))

        if query_type == 28:
            for address in answers_address:
                if "name" in address.keys():
                    dns_packet += self.make_dns_name(address["name"])
                else:
                    dns_packet += pack("!H", 0xc00c)

                dns_packet += pack("!" "2H" "I" "H" "16s", address["type"], address["class"], address["ttl"],
                                   16, inet_pton(AF_INET6, address["address"]))

        if query_type == 12:
            for address in answers_address:
                domain = self.make_dns_name(address["address"])
                if "name" in address.keys():
                    dns_packet += self.make_dns_name(address["name"])
                else:
                    dns_packet += pack("!H", 0xc00c)

                dns_packet += pack("!" "2H" "I" "H", address["type"], address["class"], address["ttl"],
                                   len(domain))
                dns_packet += domain

        if self.Base.ip_address_validation(src_ip):
            eth_header = self.eth.make_header(src_mac, dst_mac, self.ip.header_type)
            network_header = self.ip.make_header(src_ip, dst_ip, len(dns_packet),
                                                 self.udp.header_length, self.udp.header_type)
            transport_header = self.udp.make_header(src_port, dst_port, len(dns_packet))

        elif self.Base.ipv6_address_validation(src_ip):
            eth_header = self.eth.make_header(src_mac, dst_mac, self.ipv6.header_type)
            network_header = self.ipv6.make_header(src_ip, dst_ip, 0,
                                                   len(dns_packet) + self.udp.header_length, self.udp.header_type)
            transport_header = self.udp.make_header_with_ipv6_checksum(src_ip, dst_ip, src_port, dst_port,
                                                                       len(dns_packet), dns_packet)

        else:
            return None

        return eth_header + network_header + transport_header + dns_packet

    def make_request_packet(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, tid, queries=[], flags=0):
        transaction_id = tid
        dns_flags = flags
        questions = len(queries)
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        dns_packet = pack("!6H", transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)
        for query in queries:
            dns_packet += self.make_dns_name(query["name"])
            dns_packet += pack("!2H", query["type"], query["class"])

        eth_header = self.eth.make_header(src_mac, dst_mac, 2048)
        ip_header = self.ip.make_header(src_ip, dst_ip, len(dns_packet), 8, 17)
        udp_header = self.udp.make_header(src_port, dst_port, len(dns_packet))

        return eth_header + ip_header + udp_header + dns_packet

    @staticmethod
    def parse_request_packet(packet):
        dns_minimal_packet_length = 12

        if len(packet) < dns_minimal_packet_length:
            return None

        dns_detailed = unpack("!6H", packet[:dns_minimal_packet_length])

        dns_packet = {
            "transaction-id": int(dns_detailed[0]),
            "flags":          int(dns_detailed[1]),
            "questions":      int(dns_detailed[2]),
            "answer-rrs":     int(dns_detailed[3]),
            "authority-rrs":  int(dns_detailed[4]),
            "additional-rrs": int(dns_detailed[5]),
        }

        queries = []

        if len(packet) > dns_minimal_packet_length:

            number_of_question = 0
            position = dns_minimal_packet_length

            while number_of_question < dns_packet['questions']:

                query_name = ""
                query_name_length = int(unpack("B", packet[position:position + 1])[0])

                while query_name_length != 0:
                    query_name += "".join([str(x) for x in packet[position + 1:position + query_name_length + 1]]) + "."
                    position += query_name_length + 1
                    query_name_length = int(unpack("B", packet[position:position + 1])[0])

                query_type = int(unpack("!H", packet[position + 1:position + 3])[0])
                query_class = int(unpack("!H", packet[position + 3:position + 5])[0])
                position += 5

                queries.append({
                    "name":  query_name,
                    "type":  query_type,
                    "class": query_class
                })

                number_of_question += 1

        dns_packet["queries"] = queries

        return dns_packet

    def make_a_query(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, tid, names=[], flags=0):
        queries = []

        for name in names:
            queries.append({"type": 1, "class": 1, "name": name})

        return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
                                        src_ip=src_ip, dst_ip=dst_ip,
                                        src_port=src_port, dst_port=dst_port,
                                        tid=tid,
                                        flags=flags,
                                        queries=queries)

    def make_any_query(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, tid, names=[], flags=0):
        queries = []

        for name in names:
            queries.append({"type": 255, "class": 1, "name": name})

        return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
                                        src_ip=src_ip, dst_ip=dst_ip,
                                        src_port=src_port, dst_port=dst_port,
                                        tid=tid,
                                        flags=flags,
                                        queries=queries)

# endregion


# region Raw Sniffer
class Sniff_raw:

    # region variables
    Base = None

    eth = None
    arp = None
    ip = None
    ipv6 = None
    udp = None
    icmpv6 = None
    dns = None
    dhcp = None
    dhcpv6 = None

    raw_socket = None
    # endregion

    # region Init
    def __init__(self):
        self.Base = Base()

        self.eth = Ethernet_raw()
        self.arp = ARP_raw()
        self.ip = IP_raw()
        self.ipv6 = IPv6_raw()
        self.udp = UDP_raw()
        self.icmpv6 = ICMPv6_raw()
        self.dns = DNS_raw()
        self.dhcp = DHCP_raw()
        self.dhcpv6 = DHCPv6_raw()
    # endregion

    # region Start sniffer
    def start(self, protocols, prn, filters={}):

        # region Create RAW socket for sniffing
        self.raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        # endregion

        # region Start sniffing
        while True:

            # region Try
            try:

                # region Sniff packets from RAW socket
                packets = self.raw_socket.recvfrom(2048)

                for packet in packets:

                    # region Parse Ethernet header
                    ethernet_header = packet[0:self.eth.header_length]
                    ethernet_header_dict = self.eth.parse_header(ethernet_header)
                    # endregion

                    # region Could not parse Ethernet header - break
                    if ethernet_header_dict is None:
                        break
                    # endregion

                    # region Ethernet filter
                    if 'Ethernet' in filters.keys():

                        if 'source' in filters['Ethernet'].keys():
                            if ethernet_header_dict['source'] != filters['Ethernet']['source']:
                                break

                        if 'destination' in filters['Ethernet'].keys():
                            if ethernet_header_dict['destination'] != filters['Ethernet']['destination']:
                                break

                        if 'not-source' in filters['Ethernet'].keys():
                            if ethernet_header_dict['source'] == filters['Ethernet']['not-source']:
                                break

                        if 'not-destination' in filters['Ethernet'].keys():
                            if ethernet_header_dict['destination'] == filters['Ethernet']['not-destination']:
                                break

                    # endregion

                    # region ARP packet

                    # 2054 - Type of ARP packet (0x0806)
                    if 'ARP' in protocols and ethernet_header_dict['type'] == self.arp.packet_type:

                        # region Parse ARP packet
                        arp_header = packet[self.eth.header_length:self.eth.header_length + self.arp.packet_length]
                        arp_packet_dict = self.arp.parse_packet(arp_header)
                        # endregion

                        # region Could not parse ARP packet - break
                        if arp_packet_dict is None:
                            break
                        # endregion

                        # region ARP filter
                        if 'ARP' in filters.keys():

                            if 'opcode' in filters['ARP'].keys():
                                if arp_packet_dict['opcode'] != filters['ARP']['opcode']:
                                    break

                        # endregion

                        # region Call function with full ARP packet
                        prn({
                            'Ethernet': ethernet_header_dict,
                            'ARP': arp_packet_dict
                        })
                        # endregion

                    # endregion

                    # region IP packet

                    # 2048 - Type of IP packet (0x0800)
                    if 'IP' in protocols and ethernet_header_dict['type'] == self.ip.header_type:

                        # region Parse IP header
                        ip_header = packet[self.eth.header_length:]
                        ip_header_dict = self.ip.parse_header(ip_header)
                        # endregion

                        # region Could not parse IP header - break
                        if ip_header_dict is None:
                            break
                        # endregion

                        # region IP filter
                        if 'IP' in filters.keys():

                            if 'source-ip' in filters['IP'].keys():
                                if ip_header_dict['source-ip'] != filters['IP']['source-ip']:
                                    break

                            if 'destination-ip' in filters['IP'].keys():
                                if ip_header_dict['destination-ip'] != filters['IP']['destination-ip']:
                                    break

                            if 'not-source-ip' in filters['IP'].keys():
                                if ip_header_dict['source-ip'] == filters['IP']['not-source-ip']:
                                    break

                            if 'not-destination-ip' in filters['IP'].keys():
                                if ip_header_dict['destination-ip'] == filters['IP']['not-destination-ip']:
                                    break

                        # endregion

                        # region UDP
                        if 'UDP' in protocols and ip_header_dict['protocol'] == self.udp.header_type:

                            # region Parse UDP header
                            udp_header_offset = self.eth.header_length + (ip_header_dict['length'] * 4)
                            udp_header = packet[udp_header_offset:udp_header_offset + self.udp.header_length]
                            udp_header_dict = self.udp.parse_header(udp_header)
                            # endregion

                            # region Could not parse UDP header - break
                            if udp_header is None:
                                break
                            # endregion

                            # region UDP filter
                            udp_filter_destination_port = 0
                            if 'UDP' in filters.keys():
                                if 'destination-port' in filters['UDP'].keys():
                                    udp_filter_destination_port = filters['UDP']['destination-port']
                            # endregion

                            # region DHCP packet

                            # region Set UDP destination port
                            if udp_filter_destination_port == 0:
                                destination_port = 67
                            else:
                                destination_port = udp_filter_destination_port
                            # endregion

                            if 'DHCP' in protocols and udp_header_dict['destination-port'] == destination_port:

                                # region Parse DHCP packet
                                dhcp_packet_offset = udp_header_offset + self.udp.header_length
                                dhcp_packet = packet[dhcp_packet_offset:]
                                dhcp_packet_dict = self.dhcp.parse_packet(dhcp_packet)
                                # endregion

                                # region Could not parse DHCP packet - break
                                if dhcp_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DHCP packet
                                full_dhcp_packet = {
                                    'Ethernet': ethernet_header_dict,
                                    'IP': ip_header_dict,
                                    'UDP': udp_header_dict
                                }
                                full_dhcp_packet.update(dhcp_packet_dict)

                                prn(full_dhcp_packet)
                                # endregion

                            # endregion

                            # region DNS packet

                            # region Set UDP destination port
                            if udp_filter_destination_port == 0:
                                destination_port = 53
                            else:
                                destination_port = udp_filter_destination_port
                            # endregion

                            if 'DNS' in protocols and udp_header_dict['destination-port'] == destination_port:

                                # region Parse DNS request packet
                                dns_packet_offset = udp_header_offset + self.udp.header_length
                                dns_packet = packet[dns_packet_offset:]
                                dns_packet_dict = self.dns.parse_request_packet(dns_packet)
                                # endregion

                                # region Could not parse DNS request packet - break
                                if dns_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DNS packet
                                prn({
                                    "Ethernet": ethernet_header_dict,
                                    "IP": ip_header_dict,
                                    "UDP": udp_header_dict,
                                    "DNS": dns_packet_dict
                                })
                                # endregion

                            # endregion

                        # endregion

                    # endregion

                    # region IPv6 packet

                    # 34525 - Type of IP packet (0x86dd)
                    if 'IPv6' in protocols and ethernet_header_dict['type'] == self.ipv6.header_type:

                        # region Parse IPv6 header
                        ipv6_header = packet[self.eth.header_length:self.eth.header_length + self.ipv6.header_length]
                        ipv6_header_dict = self.ipv6.parse_header(ipv6_header)
                        # endregion

                        # region Could not parse IPv6 header - break
                        if ipv6_header_dict is None:
                            break
                        # endregion

                        # region IPv6 filter
                        if 'IPv6' in filters.keys():

                            if 'source-ip' in filters['IPv6'].keys():
                                if ipv6_header_dict['source-ip'] != filters['IPv6']['source-ip']:
                                    break

                            if 'destination-ip' in filters['IPv6'].keys():
                                if ipv6_header_dict['destination-ip'] != filters['IPv6']['destination-ip']:
                                    break

                            if 'not-source-ip' in filters['IPv6'].keys():
                                if ipv6_header_dict['source-ip'] == filters['IPv6']['not-source-ip']:
                                    break

                            if 'not-destination-ip' in filters['IPv6'].keys():
                                if ipv6_header_dict['destination-ip'] == filters['IPv6']['not-destination-ip']:
                                    break

                        # endregion

                        # region UDP
                        if 'UDP' in protocols and ipv6_header_dict['next-header'] == self.udp.header_type:

                            # region Parse UDP header
                            udp_header_offset = self.eth.header_length + self.ipv6.header_length
                            udp_header = packet[udp_header_offset:udp_header_offset + self.udp.header_length]
                            udp_header_dict = self.udp.parse_header(udp_header)
                            # endregion

                            # region Could not parse UDP header - break
                            if udp_header is None:
                                break
                            # endregion

                            # region UDP filter
                            udp_filter_destination_port = 0
                            if 'UDP' in filters.keys():
                                if 'destination-port' in filters['UDP'].keys():
                                    udp_filter_destination_port = filters['UDP']['destination-port']
                            # endregion

                            # region DNS packet

                            # region Set UDP destination port
                            if udp_filter_destination_port == 0:
                                destination_port = 53
                            else:
                                destination_port = udp_filter_destination_port
                            # endregion

                            if 'DNS' in protocols and udp_header_dict['destination-port'] == destination_port:

                                # region Parse DNS request packet
                                dns_packet_offset = udp_header_offset + self.udp.header_length
                                dns_packet = packet[dns_packet_offset:]
                                dns_packet_dict = self.dns.parse_request_packet(dns_packet)
                                # endregion

                                # region Could not parse DNS request packet - break
                                if dns_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DNS packet
                                prn({
                                    "Ethernet": ethernet_header_dict,
                                    "IPv6": ipv6_header_dict,
                                    "UDP": udp_header_dict,
                                    "DNS": dns_packet_dict
                                })
                                # endregion

                            # endregion

                            # region DHCPv6 packet

                            # region Set UDP destination port
                            if udp_filter_destination_port == 0:
                                destination_port = 547
                            else:
                                destination_port = udp_filter_destination_port
                            # endregion

                            if 'DHCPv6' in protocols and udp_header_dict['destination-port'] == destination_port:

                                # region Parse DHCPv6 request packet
                                dhcpv6_packet_offset = udp_header_offset + self.udp.header_length
                                dhcpv6_packet = packet[dhcpv6_packet_offset:]
                                dhcpv6_packet_dict = self.dhcpv6.parse_packet(dhcpv6_packet)
                                # endregion

                                # region Could not parse DHCPv6 request packet - break
                                if dhcpv6_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DHCPv6 packet
                                prn({
                                    "Ethernet": ethernet_header_dict,
                                    "IPv6": ipv6_header_dict,
                                    "UDP": udp_header_dict,
                                    "DHCPv6": dhcpv6_packet_dict
                                })
                                # endregion

                            # endregion

                        # endregion

                        # region ICMPv6
                        if 'ICMPv6' in protocols and ipv6_header_dict['next-header'] == self.icmpv6.packet_type:

                            # region Parse ICMPv6 packet
                            icmpv6_packet_offset = self.eth.header_length + self.ipv6.header_length
                            icmpv6_packet = packet[icmpv6_packet_offset:]
                            icmpv6_packet_dict = self.icmpv6.parse_packet(icmpv6_packet)
                            # endregion

                            # region Could not parse ICMPv6 packet - break
                            if icmpv6_packet_dict is None:
                                break
                            # endregion

                            # region Call function with full ICMPv6 packet
                            prn({
                                "Ethernet": ethernet_header_dict,
                                "IPv6": ipv6_header_dict,
                                "ICMPv6": icmpv6_packet_dict
                            })
                            # endregion

                        # endregion

                    # endregion

                # endregion

            # endregion

            # region Exception - KeyboardInterrupt
            except KeyboardInterrupt:
                self.Base.print_info("Exit")
                exit(0)
            # endregion

        # endregion

    # endregion

# endregion
