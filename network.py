from random import choice, randint
from struct import pack
from binascii import unhexlify
from array import array
from socket import inet_aton, htons, IPPROTO_TCP
from re import search


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

    macs = []

    def __init__(self):
        self.macs.append("3c:d9:2b")    # Hewlett Packard
        self.macs.append("9c:8e:99")    # Hewlett Packard
        self.macs.append("b4:99:ba")    # Hewlett Packard
        self.macs.append("00:50:ba")    # Hewlett Packard
        self.macs.append("00:11:0a")    # Hewlett Packard
        self.macs.append("00:11:85")    # Hewlett Packard
        self.macs.append("00:12:79")    # Hewlett Packard
        self.macs.append("00:13:21")    # Hewlett Packard
        self.macs.append("00:14:38")    # Hewlett Packard
        self.macs.append("00:14:c2")    # Hewlett Packard
        self.macs.append("00:15:60")    # Hewlett Packard
        self.macs.append("00:16:35")    # Hewlett Packard
        self.macs.append("00:17:08")    # Hewlett Packard
        self.macs.append("00:18:fe")    # Hewlett Packard
        self.macs.append("00:19:bb")    # Hewlett Packard
        self.macs.append("00:1a:4b")    # Hewlett Packard
        self.macs.append("00:1b:78")    # Hewlett Packard
        self.macs.append("00:1c:c4")    # Hewlett Packard
        self.macs.append("00:1e:0b")    # Hewlett Packard
        self.macs.append("00:1f:29")    # Hewlett Packard
        self.macs.append("00:21:5a")    # Hewlett Packard
        self.macs.append("00:22:64")    # Hewlett Packard
        self.macs.append("00:23:7d")    # Hewlett Packard
        self.macs.append("00:24:81")    # Hewlett Packard
        self.macs.append("00:25:b3")    # Hewlett Packard
        self.macs.append("00:26:55")    # Hewlett Packard
        self.macs.append("00:0d:88")    # D-Link Corporation
        self.macs.append("00:0f:3d")    # D-Link Corporation
        self.macs.append("00:13:46")    # D-Link Corporation
        self.macs.append("00:15:e9")    # D-Link Corporation
        self.macs.append("00:17:9a")    # D-Link Corporation
        self.macs.append("00:19:5b")    # D-Link Corporation
        self.macs.append("00:1b:11")    # D-Link Corporation
        self.macs.append("00:1c:f0")    # D-Link Corporation
        self.macs.append("00:1e:58")    # D-Link Corporation
        self.macs.append("00:21:91")    # D-Link Corporation
        self.macs.append("00:22:b0")    # D-Link Corporation
        self.macs.append("00:24:01")    # D-Link Corporation
        self.macs.append("00:26:5a")    # D-Link Corporation
        self.macs.append("00:0d:88")    # D-Link Corporation
        self.macs.append("00:0f:3d")    # D-Link Corporation
        self.macs.append("00:00:0c")    # Cisco Systems, Inc
        self.macs.append("00:01:42")    # Cisco Systems, Inc
        self.macs.append("00:01:43")    # Cisco Systems, Inc
        self.macs.append("00:01:63")    # Cisco Systems, Inc
        self.macs.append("00:01:64")    # Cisco Systems, Inc
        self.macs.append("00:01:96")    # Cisco Systems, Inc
        self.macs.append("00:01:97")    # Cisco Systems, Inc
        self.macs.append("00:01:c7")    # Cisco Systems, Inc
        self.macs.append("00:01:c9")    # Cisco Systems, Inc
        self.macs.append("00:02:16")    # Cisco Systems, Inc
        self.macs.append("00:02:17")    # Cisco Systems, Inc
        self.macs.append("00:02:4a")    # Cisco Systems, Inc
        self.macs.append("00:02:4b")    # Cisco Systems, Inc
        self.macs.append("00:02:7d")    # Cisco Systems, Inc
        self.macs.append("00:02:7e")    # Cisco Systems, Inc
        self.macs.append("d0:d0:fd")    # Cisco Systems, Inc
        self.macs.append("d4:8c:b5")    # Cisco Systems, Inc
        self.macs.append("d4:a0:2a")    # Cisco Systems, Inc
        self.macs.append("d4:d7:48")    # Cisco Systems, Inc
        self.macs.append("d8:24:bd")    # Cisco Systems, Inc
        self.macs.append("08:63:61")    # Huawei Technologies Co., Ltd
        self.macs.append("08:7a:4c")    # Huawei Technologies Co., Ltd
        self.macs.append("0c:37:dc")    # Huawei Technologies Co., Ltd
        self.macs.append("0c:96:bf")    # Huawei Technologies Co., Ltd
        self.macs.append("10:1b:54")    # Huawei Technologies Co., Ltd
        self.macs.append("10:47:80")    # Huawei Technologies Co., Ltd
        self.macs.append("10:c6:1f")    # Huawei Technologies Co., Ltd
        self.macs.append("20:f3:a3")    # Huawei Technologies Co., Ltd
        self.macs.append("24:69:a5")    # Huawei Technologies Co., Ltd
        self.macs.append("28:31:52")    # Huawei Technologies Co., Ltd
        self.macs.append("00:1b:63")    # Apple Inc
        self.macs.append("00:1c:b3")    # Apple Inc
        self.macs.append("00:1d:4f")    # Apple Inc
        self.macs.append("00:1e:52")    # Apple Inc
        self.macs.append("00:1e:c2")    # Apple Inc
        self.macs.append("00:1f:5b")    # Apple Inc
        self.macs.append("00:1f:f3")    # Apple Inc
        self.macs.append("00:21:e9")    # Apple Inc
        self.macs.append("00:22:41")    # Apple Inc
        self.macs.append("00:23:12")    # Apple Inc
        self.macs.append("00:23:32")    # Apple Inc
        self.macs.append("00:23:6c")    # Apple Inc
        self.macs.append("00:23:df")    # Apple Inc
        self.macs.append("00:24:36")    # Apple Inc
        self.macs.append("00:25:00")    # Apple Inc
        self.macs.append("00:25:4b")    # Apple Inc
        self.macs.append("00:25:bc")    # Apple Inc
        self.macs.append("00:26:08")    # Apple Inc
        self.macs.append("00:26:4a")    # Apple Inc
        self.macs.append("00:26:b0")    # Apple Inc
        self.macs.append("00:26:bb")    # Apple Inc
        self.macs.append("00:11:75")    # Intel Corporate
        self.macs.append("00:13:e8")    # Intel Corporate
        self.macs.append("00:13:02")    # Intel Corporate
        self.macs.append("00:02:b3")    # Intel Corporate
        self.macs.append("00:03:47")    # Intel Corporate
        self.macs.append("00:04:23")    # Intel Corporate
        self.macs.append("00:0c:f1")    # Intel Corporate
        self.macs.append("00:0e:0c")    # Intel Corporate
        self.macs.append("00:0e:35")    # Intel Corporate
        self.macs.append("00:12:f0")    # Intel Corporate
        self.macs.append("00:13:02")    # Intel Corporate
        self.macs.append("00:13:20")    # Intel Corporate
        self.macs.append("00:13:ce")    # Intel Corporate
        self.macs.append("00:13:e8")    # Intel Corporate
        self.macs.append("00:15:00")    # Intel Corporate
        self.macs.append("00:15:17")    # Intel Corporate
        self.macs.append("00:16:6f")    # Intel Corporate
        self.macs.append("00:16:76")    # Intel Corporate
        self.macs.append("00:16:ea")    # Intel Corporate
        self.macs.append("00:16:eb")    # Intel Corporate
        self.macs.append("00:18:de")    # Intel Corporate

    def __enter__(self):
        return self

    def get_random_mac(self):
        mac_prefix = choice(self.macs)
        mac_suffix = ':'.join('{0:02x}'.format(randint(0x00, 0xff), 'x') for _ in range(3))
        return mac_prefix + ':' + mac_suffix

    @staticmethod
    def get_mac_for_dhcp_discover():
        return "00:00:0c:d4:e8:17"

    @staticmethod
    def convert_mac(mac_address):
        if len(mac_address) < 17:
            print "Too short mac address: " + mac_address
            exit(1)
        mac_address = mac_address[:17].lower()
        if search("([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", mac_address):
            return unhexlify(mac_address.replace(':', ''))
        else:
            print "Bad mac address: " + mac_address
            exit(1)

    def make_header(self, source_mac, destination_mac, network_type):
        return self.convert_mac(destination_mac) + self.convert_mac(source_mac) + pack("!" "H", network_type)

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self.macs[:]


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

    def __init__(self):
        pass

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
        srcip = inet_aton(source_ip)        # Source port
        dstip = inet_aton(destination_ip)   # Destination port
        ver = 4                             # IP protocol version
        ihl = 5                             # Internet Header Length
        dscp_ecn = 0                        # Differentiated Services Code Point and Explicit Congestion Notification

        tlen = data_len + transport_protocol_len + 20   # Packet length
        ident = htons(randint(1, 65535))                # Identification
        flg_frgoff = 0                                  # Flags and fragmentation offset
        ptcl = transport_protocol                       # Protocol
        chksm = 0                                       # Checksum

        ip_header = pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                         (ver << 4) + ihl, dscp_ecn, tlen, ident,
                         flg_frgoff, ttl, ptcl, chksm, srcip, dstip)
        chksm = self.checksum(ip_header)
        return pack("!" "2B" "3H" "2B" "H" "4s" "4s",
                    (ver << 4) + ihl, dscp_ecn, tlen, ident,
                    flg_frgoff, ttl, ptcl, chksm, srcip, dstip)


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

    def __init__(self):
        pass

    @staticmethod
    def make_header(source_port, destination_port, data_length):
        if 0 < source_port < 65536 and 0 < destination_port < 65536:
            return pack("!4H", source_port, destination_port, data_length + 8, 0)
        else:
            return 0


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

    def make_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, flag, win, opt_exist=False, opt=None):

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
        tcp_length = len(tcp_header)

        psh = pack("!" "4s" "4s" "2B" "H", source_address, destination_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        chksum = self.checksum(psh)

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

    def make_ack_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr):
        option_nop = pack("!B", 1)
        self.update_timestamp()
        option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, tsecr)
        options = option_nop + option_nop + option_timestamp

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 16, 229, True, options)

    def make_psh_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr):
        option_nop = pack("!B", 1)
        self.update_timestamp()
        option_timestamp = pack("! 2B 2L", 8, 10, self.timestamp_value, tsecr)
        options = option_nop + option_nop + option_timestamp

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 24, 229, True, options)

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

    eth = Ethernet_raw()
    ip = IP_raw()
    udp = UDP_raw()

    def __init__(self):
        pass

    def make_packet(self, ethernet_src_mac, ethernet_dst_mac,
                    ip_src, ip_dst, udp_src_port, udp_dst_port,
                    bootp_message_type, bootp_transaction_id, bootp_flags,
                    bootp_client_ip, bootp_your_client_ip, bootp_next_server_ip,
                    bootp_relay_agent_ip, bootp_client_hw_address, dhcp_options):

        message_type = bootp_message_type       # Boot protocol message type
        hardware_type = 1                       # Ethernet
        hardware_address_len = 6                # Ethernet address len
        hops = 0                                # Number of hops
        transaction_id = bootp_transaction_id   # Transaction id
        seconds_elapsed = 0                     # Seconds elapsed
        flags = bootp_flags                     # Flags

        CIADDR = inet_aton(bootp_client_ip)                     # Client IP address
        YIADDR = inet_aton(bootp_your_client_ip)                # Your client IP address
        SIADDR = inet_aton(bootp_next_server_ip)                # Next server IP address
        GIADDR = inet_aton(bootp_relay_agent_ip)                # Relay agent IP address
        CHADDR = self.eth.convert_mac(bootp_client_hw_address)  # Client hardware address

        client_hw_padding = ''.join(pack("B", 0) for _ in range(10))    # Client hardware address padding
        server_host_name = ''.join(pack("B", 0) for _ in range(64))     # Server host name
        # Test case
        ping_command = bytes("/system/bin/ping 192.168.1.1")
        ping_command = pack("!%ds" % (len(ping_command)), ping_command)
        boot_file_name = ping_command + ''.join(pack("B", 0) for _ in range(128 - len(ping_command)))      # Boot file name
        magic_cookie = pack("!4B", 99, 130, 83, 99)                     # Magic cookie: DHCP

        dhcp_packet = pack("!" "4B" "L" "2H",
                           message_type, hardware_type, hardware_address_len, hops, transaction_id,
                           seconds_elapsed, flags)

        dhcp_packet += pack("!" "4s" "4s" "4s" "4s",
                            CIADDR, YIADDR, SIADDR, GIADDR) + CHADDR

        dhcp_packet += client_hw_padding + server_host_name + boot_file_name + magic_cookie

        dhcp_packet += dhcp_options + ''.join(pack("B", 0) for _ in range(24))

        eth_header = self.eth.make_header(ethernet_src_mac, ethernet_dst_mac, 2048)
        ip_header = self.ip.make_header(ip_src, ip_dst, len(dhcp_packet), 8, 17)
        udp_header = self.udp.make_header(udp_src_port, udp_dst_port, len(dhcp_packet))

        return eth_header + ip_header + udp_header + dhcp_packet

    def make_discover_packet(self, source_mac, client_mac, request_ip, host_name):

        option_discover = pack("!3B", 53, 1, 1)
        option_req_ip = pack("!" "2B" "4s", 50, 4, request_ip)

        host_name = bytes(host_name)
        host_name = pack("!%ds" % (len(host_name)), host_name)
        option_host_name = pack("!2B", 12, len(host_name)) + host_name

        option_param_req_list = pack("!2B", 55, 254)
        for param in range(1, 255):
            option_param_req_list += pack("B", param)

        option_end = pack("B", 255)

        options = option_discover + option_req_ip + option_host_name + option_param_req_list + option_end

        return self.make_packet(ethernet_src_mac=source_mac,
                                ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                                ip_src="0.0.0.0", ip_dst="255.255.255.255",
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

    def make_response_packet(self, source_mac, destination_mac, source_ip, destination_ip, transaction_id, your_ip,
                             client_mac, dhcp_server_id, lease_time, netmask, router, dns, dhcp_operation=2, url=None):

        option_operation = pack("!3B", 53, 1, dhcp_operation)
        option_server_id = pack("!" "2B" "4s", 54, 4, inet_aton(dhcp_server_id))
        option_lease_time = pack("!" "2B" "L", 51, 4, lease_time)
        option_netmask = pack("!" "2B" "4s", 1, 4, inet_aton(netmask))
        option_router = pack("!" "2B" "4s", 3, 4, inet_aton(router))
        option_dns = pack("!" "2B" "4s", 6, 4, inet_aton(dns))
        option_end = pack("B", 255)

        options = option_operation + option_server_id + option_lease_time + option_netmask + \
                  option_router + option_dns

        if url is not None:
            if len(url) < 255:
                option_url = pack("!" "2B", 114, len(url)) + url
                options += option_url

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


class DNS_raw:

    eth = Ethernet_raw()
    ip = IP_raw()
    udp = UDP_raw()

    def __init__(self):
        pass

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

    def make_request_packet(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                            tid, flags, request_name, request_type, request_class):
        transaction_id = tid
        dns_flags = flags
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0
        dns_request_type = request_type
        dns_request_class = request_class

        dns_packet = pack("!6H", transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)
        dns_packet += self.make_dns_name(request_name)
        dns_packet += pack("!2H", dns_request_type, dns_request_class)

        eth_header = self.eth.make_header(src_mac, dst_mac, 2048)
        ip_header = self.ip.make_header(src_ip, dst_ip, len(dns_packet), 8, 17)
        udp_header = self.udp.make_header(src_port, dst_port, len(dns_packet))

        return eth_header + ip_header + udp_header + dns_packet

    def make_a_query(self, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, tid, request_name):
        return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
                                        src_ip=src_ip, dst_ip=dst_ip,
                                        src_port=src_port, dst_port=dst_port,
                                        tid=tid,
                                        flags=256,
                                        request_name=request_name,
                                        request_type=1, request_class=1)
