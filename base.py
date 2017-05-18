from random import choice, randint
from struct import pack
from array import array
from socket import inet_aton, htons


class Ethernet:
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
        mac_suffix = ':'.join(format(randint(0, 255), 'x') for _ in range(3))
        return mac_prefix + ':' + mac_suffix

    @staticmethod
    def make_header(source_mac, destination_mac, network_type):
        source_mac_list = source_mac.split(":")
        destination_mac_list = destination_mac.split(":")
        eth_header = ""
        for part_of_destination_mac in destination_mac_list:
            eth_header += pack("!" "B", int(part_of_destination_mac, 16))   # Destination mac address
        for part_of_source_mac_list in source_mac_list:
            eth_header += pack("!" "B", int(part_of_source_mac_list, 16))   # Source mac address
        eth_header += pack("!" "H", network_type)                           # Network protocol type
        return eth_header

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self.macs[:]


class IP:

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


class UDP:

    def __init__(self):
        pass

    @staticmethod
    def make_header(source_port, destination_port, data_length):
        if 0 < source_port < 65536 and 0 < destination_port < 65536:
            return pack("!4H", source_port, destination_port, data_length + 8, 0)
        else:
            return 0


class DHCP:

    eth = Ethernet()
    ip = IP()
    udp = UDP()

    def __init__(self):
        pass

    def make_discover_packet(self, source_mac, client_mac, request_ip, host_name):
        request_ip = inet_aton(request_ip)
        clientmac_list = client_mac.split(":")
        client_hw_address = ""
        for part_of_srcmac in clientmac_list:
            client_hw_address += pack("!" "B", int(part_of_srcmac, 16))

        message_type = 1                            # Request
        hardware_type = 1                           # Ethernet
        hardware_address_len = 6                    # Ethernet address len
        hops = 0                                    # Number of hops
        transaction_id = randint(1, 4294967295)     # Transaction id
        seconds_elapsed = 0                         # Seconds elapsed
        bootp_flags = 0                             # Flags

        CIADDR = 0  # Client IP address
        YIADDR = 0  # Your client IP address
        SIADDR = 0  # Next server IP address
        GIADDR = 0  # Relay agent IP address
        CHADDR = client_hw_address  # Client hardware address

        dhcp_discover = pack("!" "4B" "L" "2H" "4L",
                             message_type, hardware_type, hardware_address_len, hops, transaction_id,
                             seconds_elapsed, bootp_flags, CIADDR, YIADDR, SIADDR, GIADDR) + CHADDR

        client_hw_padding = ''.join(pack("B", 0) for _ in range(10))    # Client hardware address padding
        server_host_name = ''.join(pack("B", 0) for _ in range(64))     # Server host name
        boot_file_name = ''.join(pack("B", 0) for _ in range(128))      # Boot file name
        magic_cookie = pack("!4B", 99, 130, 83, 99)                     # Magic cookie: DHCP

        option_discover = pack("!3B", 53, 1, 1)
        option_req_ip = pack("!" "2B" "4s", 50, 4, request_ip)

        host_name = bytes(host_name)
        host_name = pack("!%ds" % (len(host_name)), host_name)
        option_host_name = pack("!2B", 12, len(host_name)) + host_name

        option_param_req_list = pack("!2B", 55, 254)
        for param in range(1, 255):
            option_param_req_list += pack("B", param)

        option_end = pack("B", 255)
        padding = ''.join(pack("B", 0) for _ in range(24))

        dhcp_discover += client_hw_padding + server_host_name + boot_file_name + magic_cookie
        dhcp_discover += option_discover + option_req_ip + option_host_name + option_param_req_list + option_end
        dhcp_discover += padding

        eth_header = self.eth.make_header(source_mac, "ff:ff:ff:ff:ff:ff", 2048)
        ip_header = self.ip.make_header("0.0.0.0", "255.255.255.255", len(dhcp_discover), 8, 17)
        udp_header = self.udp.make_header(68, 67, len(dhcp_discover))

        return eth_header + ip_header + udp_header + dhcp_discover
