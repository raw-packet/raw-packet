Raw-packet project
===================

[![Official site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python3 version][python3-versions-label]][python3-versions-link]
[![License][license-label]][license-link]
[![Version][version-label]][version-link]
[![Stability][stability-label]][stability-link]

[site-label]: https://raw-packet.github.io/static/images/labels/site.svg
[site-link]: https://raw-packet.github.io/
[os-label]: https://raw-packet.github.io/static/images/labels/os.svg
[os-link]: https://en.wikipedia.org/wiki/Linux
[python3-versions-label]: https://raw-packet.github.io/static/images/labels/python3.svg
[python3-versions-link]: https://www.python.org/downloads/release/python-374/
[license-label]: https://raw-packet.github.io/static/images/labels/license.svg
[license-link]: https://github.com/raw-packet/raw-packet/blob/master/LICENSE
[version-label]: https://raw-packet.github.io/static/images/labels/version.svg
[version-link]: https://github.com/raw-packet/raw-packet/releases
[stability-label]: https://raw-packet.github.io/static/images/labels/stability.svg
[stability-link]: https://github.com/raw-packet/raw-packet/releases

[![Logo](https://raw-packet.github.io/static/images/logo/logo-caption.png)](https://raw-packet.github.io/)

# Important information:
***This project is created only for educational purposes and can not be used for 
law violation or personal gain.<br/>The author of this project is not responsible for any possible harm caused by the materials of this project.***

# Важная информация:
***Данный проект создан исключительно в образовательных целях, и не может быть использован в целях нарушающих законодательство, в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.<br/>Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# Info
Author: [Vladimir Ivanov](https://github.com/Vladimir-Ivanov-Git)<br/>
SubAuthors: [Ilja Bulatov](https://github.com/barrracud4)<br/>
Project email: [raw.packet.project@gmail.com](mailto:raw.packet.project@gmail.com)<br/>
PGP Public key: [raw.packet.project@gmail.com PGP Public key](https://raw-packet.github.io/static/pgp/Raw-packet.asc)<br/>
Current project version: [0.2.1](https://github.com/raw-packet/raw-packet)<br/>
Last stable release: [0.1.1](https://github.com/raw-packet/raw-packet/releases/tag/v0.1.1)<br/>
Required OS: [Linux based](https://en.wikipedia.org/wiki/Linux)<br/>
Python versions: [3.7](https://www.python.org/downloads/release/python-374/)<br/>
License: [MIT](https://github.com/raw-packet/raw-packet/blob/master/LICENSE)

# Install

## Debian based OS install with apt (recommended):
```
git clone https://github.com/raw-packet/raw-packet && cd ./raw-packet
sudo apt update && sudo apt install -y python3 python3-pip python3-scapy \
                                       python3-netifaces python-ipaddress \
                                       python3-netaddr python3-psutil \
                                       python3-prettytable python3-distro \
                                       python3-xmltodict python3-paramiko \
                                       php lsof net-tools wireless-tools \
                                       nmap aircrack-ng
```

## Debian based OS install with pip:
```
git clone https://github.com/raw-packet/raw-packet && cd ./raw-packet
sudo apt update && sudo apt install -y python3 python3-pip apache2 php \
                                       lsof net-tools wireless-tools \
                                       nmap aircrack-ng
sudo pip3 install -r requirements.txt
```

# Publications

Apple security updates: [https://support.apple.com/en-us/HT209341](https://support.apple.com/en-us/HT209341)<br/>
<br/>
PHDays: [https://www.phdays.com/en/program/reports/apple-all-about-mitm/](https://www.phdays.com/en/program/reports/apple-all-about-mitm/)<br/>
<br/>
Yandex [it sec pro course 2018 #0](https://events.yandex.ru/events/yagosti/09-feb-2018/): [https://events.yandex.ru/lib/talks/5519/](https://events.yandex.ru/lib/talks/5519/)<br/>
<br/>
Xakep.ru: [https://xakep.ru/2017/09/25/wifi-mitm-advanced/](https://xakep.ru/2017/09/25/wifi-mitm-advanced/)<br/>
<br/>
Habr.com:<br/>
[https://habrahabr.ru/company/dsec/blog/333978/](https://habrahabr.ru/company/dsec/blog/333978/)<br/>
[https://habrahabr.ru/post/338860/](https://habrahabr.ru/post/338860/)<br/>
[https://habrahabr.ru/post/338864/](https://habrahabr.ru/post/338864/)<br/>
[https://habrahabr.ru/post/339666/](https://habrahabr.ru/post/339666/)<br/>

# Scapy vs. Raw-packet

Script [time_test.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/time_test.py) results:</br>

| Number of Packets                          | 10                | 100              | 1000            | 10000         |
|--------------------------------------------|-------------------|------------------|-----------------|---------------|
| ARP requests in Scapy (sec)                | 0,0522048473358   | 0,0785529613495  | 0,302206039429  | 2,95294880867 |
| ARP requests in Raw-packet (sec)           | 0,00202298164368  | 0,00270104408264 | 0,090922832489  | 1,3037519455  |
| DHCP discover requests in Scapy (sec)      | 0,397399187088    | 4,16092181206    | 39,5892789364   |       -       |
| DHCP discover requests in Raw-packet (sec) | 0,00177597999573  | 0,0219049453735  | 0,162989854813  |       -       |
| DNS requests in Scapy (sec)                | 0.608256101608    | 6.05325508118    | 58.4151289463   |       -       |
| DNS requests in Raw-packet (sec)           | 0.00274395942688  | 0.0127770900726  | 0.0796978473663 |       -       |

![Scapy vs. Raw-packet ARP requests](https://raw-packet.github.io/static/images/others/ARP_requests_timing.png)

![Scapy vs. Raw-packet DHCP discover requests](https://raw-packet.github.io/static/images/others/DHCP_discover_requests_timing.png)

![Scapy vs. Raw-packet DNS requests](https://raw-packet.github.io/static/images/others/DNS_requests_timing.png)

# Scripts

# Apple attacks

## Script: [apple_mitm.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_mitm.py)

This script automatically finds Apple devices on the local network using an ARP, NMAP or ICMPv6 scan and implements the MiTM attack with the following techniques:
1. ARP Spoofing
1. Second DHCP ACK
1. Predict next DHCP transaction ID
1. Rogue SLAAC/DHCPv6 server
1. NA Spoofing (IPv6)
1. RA Spoofing (IPv6)

```
root@kali:~/raw-packet# python3 Scripts/Apple/apple_mitm.py --help
usage: apple_mitm.py [-h] [-T TECHNIQUE] [-D DISCONNECT] [-l LISTEN_IFACE]
                     [-d DEAUTH_IFACE] [-0 DEAUTH_PACKETS]
                     [-f PHISHING_DOMAIN] [-p PHISHING_DOMAIN_PATH]
                     [-t TARGET_IP] [-n NEW_IP] [-s] [--kill]
                     [--ipv6_prefix IPV6_PREFIX]

MiTM Apple devices in local network

optional arguments:
  -h, --help            show this help message and exit
  -T TECHNIQUE, --technique TECHNIQUE
                        Set MiTM technique:
                        1. ARP Spoofing
                        2. Second DHCP ACK
                        3. Predict next DHCP transaction ID
                        4. Rogue SLAAC/DHCPv6 server
                        5. NA Spoofing (IPv6)
                        6. RA Spoofing (IPv6)
  -D DISCONNECT, --disconnect DISCONNECT
                        Set device Disconnect technique:
                        1. IPv4 network conflict detection
                        2. Send WiFi deauthentication packets
                        3. Do not disconnect device after MiTM
  -l LISTEN_IFACE, --listen_iface LISTEN_IFACE
                        Set interface name for send DHCPACK packets
  -d DEAUTH_IFACE, --deauth_iface DEAUTH_IFACE
                        Set interface name for send wifi deauth packets
  -0 DEAUTH_PACKETS, --deauth_packets DEAUTH_PACKETS
                        Set number of deauth packets (default: 5)
  -f PHISHING_DOMAIN, --phishing_domain PHISHING_DOMAIN
                        Set domain name for social engineering (default="auth.apple.wi-fi.com")
  -p PHISHING_DOMAIN_PATH, --phishing_domain_path PHISHING_DOMAIN_PATH
                        Set local path to for social engineering site 
                        in directory: raw_packet/Utils/Phishing_domains 
                        or use your own directory (default="apple")
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -n NEW_IP, --new_ip NEW_IP
                        Set new IP address for target
  -s, --nmap_scan       Use nmap for Apple device detection
  --kill                Kill all processes and threads
  --ipv6_prefix IPV6_PREFIX
                        Set IPv6 network prefix, default - fd00::/64
```

### Sample script output:
![apple_mitm.py output](https://raw-packet.github.io/static/images/screenshots/apple_mitm.py_screenshot.png)

---


## Script: [apple_arp_dos.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_arp_dos.py)

Disconnect Apple device from the local network using ARP packets

```
root@kali:~/raw-packet# python3 Scripts/Apple/apple_arp_dos.py --help
usage: apple_arp_dos.py [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                        [-n] [-q]

Disconnect Apple device in local network with ARP packets

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -n, --nmap_scan       Use nmap for Apple device detection
  -q, --quit            Minimal output
```

### Sample script output:
![apple_arp_dos.py output](https://raw-packet.github.io/static/images/screenshots/apple_arp_dos.py_screenshot.png)

### Traffic sample generated by this script:
![apple_arp_dos.py traffic](https://raw-packet.github.io/static/images/screenshots/apple_arp_dos.py_traffic.png)

---

## Script: [apple_rogue_dhcp.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_rogue_dhcp.py)

Rogue DHCP server for Apple device with predict next DHCP transaction ID

```
root@kali:~/raw-packet# python3 Scripts/Apple/apple_rogue_dhcp.py --help
usage: apple_rogue_dhcp.py [-h] [-i INTERFACE] -m TARGET_MAC -t TARGET_NEW_IP
                           [-b] [-q]

Rogue DHCP server for Apple devices

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send DHCP reply packets
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address, required!
  -t TARGET_NEW_IP, --target_new_ip TARGET_NEW_IP
                        Set new client IP address, required!
  -b, --broadcast       Send broadcast DHCPv4 responses
  -q, --quiet           Minimal output
```

### Sample script output:
![apple_rogue_dhcp.py output](https://raw-packet.github.io/static/images/screenshots/apple_rogue_dhcp.py_screenshot.png)

---

# ARP

The [Address Resolution Protocol (ARP)](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address.

---

## Script: [arp_scan.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ARP/arp_scan.py)
This script creates and sends ARP requests (Who has?) to search for alive hosts on the local network.

```
root@kali:~/raw-packet# python3 Scripts/ARP/arp_scan.py --help
usage: arp_scan.py [-h] [-i INTERFACE] [-T TARGET_IP] [-t TIMEOUT] [-r RETRY]

ARP scan script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for ARP scanner
  -T TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -t TIMEOUT, --timeout TIMEOUT
                        Set timeout (default=3)
  -r RETRY, --retry RETRY
                        Set number of retry (default=3)
```

### Sample script output:
![arp_scan.py output](https://raw-packet.github.io/static/images/screenshots/arp_scan.py_screenshot.png)

### Traffic sample generated by this script:
![arp_scan.py traffic](https://raw-packet.github.io/static/images/screenshots/arp_scan.py_traffic.png)

---

## Script: [arp_spoof.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ARP/arp_spoof.py)

This script implement the ARP spoofing attack. 
ARP spoofing, ARP cache poisoning or ARP poison routing, is a technique that  an attacker sends fake (spoofed) Address Resolution Protocol (ARP) messages onto a local network.

```
root@kali:~/raw-packet# python3 Scripts/ARP/arp_spoof.py --help
usage: arp_spoof.py [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                    [-g GATEWAY_IP] [-r] [--ipv4_multicast_requests]
                    [--ipv6_multicast_requests] [-R] [-q]

ARP spoofing script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IP address
  -r, --requests        Send only ARP requests
  --ipv4_multicast_requests
                        Send only ARP IPv4 multicast requests
  --ipv6_multicast_requests
                        Send only ARP IPv6 multicast requests
  -R, --broadcast_requests
                        Send only ARP broadcast requests
  -q, --quiet           Minimal output
```

### Sample script output:
![arp_spoof.py output](https://raw-packet.github.io/static/images/screenshots/arp_spoof.py_screenshot.png)

### Traffic sample generated by this script:
![arp_spoof.py traffic](https://raw-packet.github.io/static/images/screenshots/arp_spoof.py_traffic.png)

### Video demo:
[![ARP spoofing demo video](https://raw-packet.github.io/static/images/gifs/arp_spoof.gif)](https://youtu.be/bgm_gDzdd0g)

---

# DHCP

The [Dynamic Host Configuration Protocol (DHCP)](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) is a network management protocol used on UDP/IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks.

## Script: [dhcp_starvation.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCPv4/dhcp_starvation.py)

This script implement the attack - DHCP starvation.
DHCP starvation attack is an attack that targets DHCP servers whereby forged DHCP requests are crafted by an attacker with the intent of exhausting all available IP addresses that can be allocated by the DHCP server.

```
root@kali:~/raw-packet# python3 Scripts/DHCPv4/dhcp_starvation.py --help
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

### Sample script output:
![dhcp_starvation.py output](https://raw-packet.github.io/static/images/screenshots/dhcp_starvation.py_screenshot.png)

### Traffic sample generated by this script:
![dhcp_starvation.py traffic_discover](https://raw-packet.github.io/static/images/screenshots/dhcp_starvation.py_traffic_discover.png)

![dhcp_starvation.py traffic_request](https://raw-packet.github.io/static/images/screenshots/dhcp_starvation.py_traffic_request.png)

### Demo video:
[![DHCP Starvation demo video](https://raw-packet.github.io/static/images/gifs/dhcp_starvation.gif)](https://youtu.be/rp3R-7pkDl4)

---

## Script: [dhcp_rogue_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCPv4/dhcp_rogue_server.py)

This script implements an attack on network clients by using fake DHCP server which answers with malicious configuration faster than legitimate DHCP server. This attack also known as Rogue DHCP Server Attack.

```
root@kali:~/raw-packet# python3 Scripts/DHCPv4/dhcp_rogue_server.py --help
usage: dhcp_rogue_server.py [-h] [-i INTERFACE] [-f FIRST_OFFER_IP]
                            [-l LAST_OFFER_IP] [-t TARGET_MAC] [-T TARGET_IP]
                            [-m NETMASK] [--dhcp_mac DHCP_MAC]
                            [--dhcp_ip DHCP_IP] [--router ROUTER] [--dns DNS]
                            [--tftp TFTP] [--wins WINS] [--proxy PROXY]
                            [--domain DOMAIN] [--lease_time LEASE_TIME] [-s]
                            [-r] [-d DISCOVER_DELAY]
                            [-O SHELLSHOCK_OPTION_CODE]
                            [-c SHELLSHOCK_COMMAND] [-b] [-p BIND_PORT] [-N]
                            [-E] [-R] [-e REVERSE_PORT] [-n] [-B]
                            [--ip_path IP_PATH] [--iface_name IFACE_NAME]
                            [--broadcast_response] [--dnsop] [--exit]
                            [--apple] [-q]

Rogue DHCPv4 server

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
  -T TARGET_IP, --target_ip TARGET_IP
                        Set client IP address with MAC in --target_mac
  -m NETMASK, --netmask NETMASK
                        Set network mask
  --dhcp_mac DHCP_MAC   Set DHCP server MAC address, if not set use your MAC
                        address
  --dhcp_ip DHCP_IP     Set DHCP server IP address, if not set use your IP
                        address
  --router ROUTER       Set router IP address, if not set use your ip address
  --dns DNS             Set DNS server IP address, if not set use your ip
                        address
  --tftp TFTP           Set TFTP server IP address
  --wins WINS           Set WINS server IP address
  --proxy PROXY         Set Proxy URL, example: 192.168.0.1:8080
  --domain DOMAIN       Set domain name for search, default=local
  --lease_time LEASE_TIME
                        Set lease time, default=172800
  -s, --send_discover   Send DHCP discover packets in the background thread
  -r, --discover_rand_mac
                        Use random MAC address for source MAC address in DHCP
                        discover packets
  -d DISCOVER_DELAY, --discover_delay DISCOVER_DELAY
                        Set delay between DHCP discover packets (default=0.5
                        sec.)
  -O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE
                        Set dhcp option code for inject shellshock payload,
                        default=114
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
  --ip_path IP_PATH     Set path to "ip" in shellshock payload, default =
                        /bin/
  --iface_name IFACE_NAME
                        Set iface name in shellshock payload, default = eth0
  --broadcast_response  Send broadcast response
  --dnsop               Do not send DHCP OFFER packets
  --exit                Exit on success MiTM attack
  --apple               Add delay before send DHCP ACK
  -q, --quiet           Minimal output
```

### Sample script output:
![dhcp_rogue_server.py output](https://raw-packet.github.io/static/images/screenshots/dhcp_rogue_server.py_screenshot.png)

### Result:
![dhcp_rogue_server.py result](https://raw-packet.github.io/static/images/screenshots/dhcp_rogue_server.py_result.png)

### Demo video:
[![DHCP Rogue server preview](https://raw-packet.github.io/static/images/gifs/dhcp_rogue_server.gif)](https://youtu.be/qiEvRGyucPc)

---

# DHCPv6

The [Dynamic Host Configuration Protocol version 6 (DHCPv6)](https://en.wikipedia.org/wiki/DHCPv6) is a network protocol for configuring Internet Protocol version 6 (IPv6) hosts with IP addresses, IP prefixes and other configuration data required to operate in an IPv6 network. It is the IPv6 equivalent of the Dynamic Host Configuration Protocol for IPv4.

## Script: [dhcpv6_rogue_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DHCPv6/dhcpv6_rogue_server.py)

This script implements fake DHCPv6 server for performing SLAAC attack/Rogue DHCPv6.

```
root@kali:~/raw-packet# python3 Scripts/DHCPv6/dhcpv6_rogue_server.py --help
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
                        Set client Global IPv6 address with MAC --target_mac
  -D, --disable_dhcpv6  Do not use DHCPv6 protocol
  -d DNS, --dns DNS     Set recursive DNS IPv6 address
  -s DNS_SEARCH, --dns_search DNS_SEARCH
                        Set DNS search list
  --delay DELAY         Set delay between packets
  -q, --quiet           Minimal output
```

### Sample script output:
![dhcpv6_rogue_server.py output](https://raw-packet.github.io/static/images/screenshots/dhcpv6_rogue_server.py_screenshot.png)

### Result:
![dhcpv6_rogue_server.py result](https://raw-packet.github.io/static/images/screenshots/dhcpv6_rogue_server.py_result.png)

### Demo video:
[![DHCPv6 Rogue server preview](https://raw-packet.github.io/static/images/gifs/dhcpv6_rogue_server.gif)](https://youtu.be/4Sd4O35Ykaw)

---

# ICMPv4

## Script: [icmpv4_redirect.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv4/icmpv4_redirect.py)

This script implement the ICMPv4 redirect attack. 

```
root@kali:~/raw-packet# python3 Scripts/ICMPv4/icmpv4_redirect.py -h
usage: icmpv4_redirect.py [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                          [-g GATEWAY_IP] [-r REDIRECT_IP] [-q]

ICMPv4 redirect script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ICMP redirect packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IP address (default: <your_ip_address>)
  -r REDIRECT_IP, --redirect_ip REDIRECT_IP
                        Set IP addresses where to redirect (example:
                        8.8.8.8,1.1.1.1)
  -q, --quiet           Minimal output
```

### Sample script output:
![icmpv4_redirect.py output](https://raw-packet.github.io/static/images/screenshots/icmpv4_redirect.py_screenshot.png)

### Traffic sample generated by this script:
![icmpv4_redirect.py traffic](https://raw-packet.github.io/static/images/screenshots/icmpv4_redirect.py_traffic.png)

---

# ICMPv6

## Script: [icmpv6_scan.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv6/icmpv6_scan.py)

Search for hosts that support IPv6 in local network using ICMPv6 protocol

```
root@kali:~/raw-packet# python3 Scripts/ICMPv6/icmpv6_scan.py --help
usage: icmpv6_scan.py [-h] [-i INTERFACE] [-m TARGET_MAC] [-t TIMEOUT]
                      [-r RETRY] [-s]

ICMPv6 scanner script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for ARP scanner
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -t TIMEOUT, --timeout TIMEOUT
                        Set timeout (default=3)
  -r RETRY, --retry RETRY
                        Set number of retry (default=3)
  -s, --router_search   Search router IPv6 link local address
```

### Sample script output:
![icmpv6_scan.py output](https://raw-packet.github.io/static/images/screenshots/icmpv6_scan.py_screenshot.png)

### Traffic sample generated by this script:
![icmpv6_scan.py traffic](https://raw-packet.github.io/static/images/screenshots/icmpv6_scan.py_traffic.png)

---

## Script: [icmpv6_spoof.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv6/icmpv6_spoof.py)

This script implements Router Advertisement and Neighbor Advertisement spoofing attack

```
root@kali:~/raw-packet# python3 Scripts/ICMPv6/icmpv6_spoof.py --help
usage: icmpv6_spoof.py [-h] [-T TECHNIQUE] [-i INTERFACE] [-t TARGET_IP]
                       [-m TARGET_MAC] [-g GATEWAY_IP] [-p IPV6_PREFIX]
                       [-d DNS_IP] [-n DNS_DOMAIN_SEARCH] [-q]

ICMPv6 spoofing

optional arguments:
  -h, --help            show this help message and exit
  -T TECHNIQUE, --technique TECHNIQUE
                        Set ICMPv6 MiTM technique (example: 1)
                        1. ICMPv6 RA (Router Advertisement) Spoofing
                        2. ICMPv6 NA (Neighbor Advertisement) Spoofing
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv6 link local address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IPv6 link local address
  -p IPV6_PREFIX, --ipv6_prefix IPV6_PREFIX
                        Set IPv6 prefix, default="fde4:8dba:82e1:ffff::/64"
  -d DNS_IP, --dns_ip DNS_IP
                        Set DNS server IPv6 link local address
  -n DNS_DOMAIN_SEARCH, --dns_domain_search DNS_DOMAIN_SEARCH
                        Set DNS domain search; default: "local"
  -q, --quiet           Minimal output
```

## Router Advertisement spoofing

### Sample script output:
![ra_spoof.py output](https://raw-packet.github.io/static/images/screenshots/ra_spoof.py_screenshot.png)

### Traffic sample generated by this script:
![ra_spoof.py traffic](https://raw-packet.github.io/static/images/screenshots/ra_spoof.py_traffic.png)

## Neighbor Advertisement spoofing

### Sample script output:
![na_spoof.py output](https://raw-packet.github.io/static/images/screenshots/na_spoof.py_screenshot.png)

### Traffic sample generated by this script:
![na_spoof.py traffic](https://raw-packet.github.io/static/images/screenshots/na_spoof.py_traffic.png)

---

# DNS

## Script: [dns_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DNS/dns_server.py)

This script implements a simple DNS server (like a [dnschef](https://github.com/iphelix/dnschef)), which is useful in MiTM attacks. You can setup A or AAAA records for several domains. 

```
root@kali:~/raw-packet# python3 Scripts/DNS/dns_server.py --help
usage: dns_server.py [-h] [-i INTERFACE] [-p PORT] [-t TARGET_MAC] [--T4 T4]
                     [--T6 T6] [-c CONFIG_FILE] [--fake_domains FAKE_DOMAINS]
                     [--no_such_domains NO_SUCH_DOMAINS]
                     [--fake_ipv4 FAKE_IPV4] [--fake_ipv6 FAKE_IPV6] [--ipv6]
                     [--disable_ipv4] [--log_file_name LOG_FILE_NAME]
                     [--log_file_format LOG_FILE_FORMAT] [-f] [-q]

DNS server

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send DNS reply packets
  -p PORT, --port PORT  Set UDP port for listen DNS request packets (default:
                        53)
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  --T4 T4               Set target IPv4 address
  --T6 T6               Set target IPv6 address
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Set json config file name, example: --config_file
                        "dns_server_config.json"
  --fake_domains FAKE_DOMAINS
                        Set fake domain regexp or domains, example:
                        --fake_domains ".*apple.com,.*google.com"
  --no_such_domains NO_SUCH_DOMAINS
                        Set no such domain or domains, example:
                        --no_such_domains "apple.com,google.com"
  --fake_ipv4 FAKE_IPV4
                        Set fake IP address or addresses, example: --fake_ipv4
                        "192.168.0.1,192.168.0.2"
  --fake_ipv6 FAKE_IPV6
                        Set fake IPv6 address or addresses, example:
                        --fake_ipv6 "fd00::1,fd00::2"
  --ipv6                Enable IPv6
  --disable_ipv4        Disable IPv4
  --log_file_name LOG_FILE_NAME
                        Set file name for save DNS queries (default:
                        "dns_server_log")
  --log_file_format LOG_FILE_FORMAT
                        Set file format for save results: csv, xml, json, txt
                        (default: "json")
  -f, --fake_answer     Set your IPv4 or IPv6 address in all answers
  -q, --quiet           Minimal output
```

### Sample script configuration:
```json
{
  ".*google.com": {
    "A": ["192.168.0.1", "192.168.0.2"],
    "AAAA": "fd00::1",
    "NS": ["ns1.google.com", "ns2.google.com"],
    "MX": "mail.google.com"
  },
  ".*apple.com": {
    "A": "192.168.0.1",
    "AAAA": ["fd00::1", "fd00::2"],
    "NS": "ns.apple.com",
    "MX": ["mail1.apple.com", "mail2.apple.com"]
  },
  "gooogle.com": {
    "no such domain": true
  },
  "evil.com": {
    "success": true,
    "A": "my ipv4 address",
    "AAAA": "my ipv6 address"
  }
}
```

### Sample script output (without parameters):
![dns_server.py output](https://raw-packet.github.io/static/images/screenshots/dns_server.py_screenshot.png)

### Sample script output (fake answer):
![dns_server.py output_fake_answer](https://raw-packet.github.io/static/images/screenshots/dns_server.py_screenshot_fake_answer.png)

---

# Exploits 

## Script: [dnsmasploit.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Binary/dnsmasploit.py)

This script implements an exploit for CVE-2017-14493 and CVE-2017-14494 vulnerabilities in dnsmasq (DNS Server).

```
root@kali:~/raw-packet# ./dnsmasploit.py -h
usage: dnsmasploit.py [-h] [-i INTERFACE] [-e] [-l] [-f FILE_NAME] -t TARGET
                      [-p TARGET_PORT] [-a ARCHITECTURE] [-v VERSION]
                      [--interpreter INTERPRETER]
                      [--interpreter_arg INTERPRETER_ARG] [--payload PAYLOAD]
                      [--command COMMAND] [--bind_port BIND_PORT]
                      [--reverse_port REVERSE_PORT]
                      [--reverse_host REVERSE_HOST]

Exploit for dnsmasq CVE-2017-14493 and CVE-2017-14494

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send packets
  -e, --exploit         Exploit (CVE-2017-14493) works only if Stack cookie
                        and PIE disabled
  -l, --data_leak       Data leakage (CVE-2017-14494)
  -f FILE_NAME, --file_name FILE_NAME
                        Set file name for leak data
  -t TARGET, --target TARGET
                        Set target IPv6 address
  -p TARGET_PORT, --target_port TARGET_PORT
                        Set target port, default=547
  -a ARCHITECTURE, --architecture ARCHITECTURE
                        Set architecture (i386, amd64 or arm), default=i386
  -v VERSION, --version VERSION
                        Set dnsmasq version (2.70, 2.71, 2.72, 2.73, 2.74,
                        2.75, 2.76, 2.77), default=2.77
  --interpreter INTERPRETER
                        Set path to interpreter on target, default="/bin/bash"
  --interpreter_arg INTERPRETER_ARG
                        Set interpreter argument, default="-c"
  --payload PAYLOAD     Set payload (bind_awk, reverse_awk, reverse_bash,
                        reverse_php, reverse_nc, reverse_nce),
                        default=reverse_nc
  --command COMMAND     Set command for executing on target
  --bind_port BIND_PORT
                        Set bind port, default=4444
  --reverse_port REVERSE_PORT
                        Set reverse port, default=4444
  --reverse_host REVERSE_HOST
                        Set reverse host
```

### Demo video exploit for CVE-2017-14493:
[![dnsmasploit preview](https://j.gifs.com/7LWln8.gif)](https://youtu.be/VWr0zCZlMrE)

### Demo video exploit for CVE-2017-14494:
[![dnsmasploit preview](https://j.gifs.com/1rB5VG.gif)](https://youtu.be/GqMuZ1wMCWQ)

---

# Miscellaneous scripts

## Script: [network_security_check.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/network_security_check.py)

Checking network security mechanisms such as: Dynamic ARP Inspection, DHCP snooping, etc.

```
root@kali:~/raw-packet# python3 Scripts/Others/network_security_check.py -h
usage: network_security_check.py [-h] [-s SEND_INTERFACE]
                                 [-l LISTEN_INTERFACE]
                                 [-n TEST_HOST_INTERFACE] [-t TEST_HOST]
                                 [-m TEST_MAC] [-o TEST_OS] [-u TEST_SSH_USER]
                                 [-p TEST_SSH_PASS] [-k TEST_SSH_PKEY]
                                 [-G GATEWAY_IP] [-g GATEWAY_MAC]
                                 [-r NUMBER_OF_PACKETS]

Checking network security mechanisms

optional arguments:
  -h, --help            show this help message and exit
  -s SEND_INTERFACE, --send_interface SEND_INTERFACE
                        Set interface name for send packets
  -l LISTEN_INTERFACE, --listen_interface LISTEN_INTERFACE
                        Set interface name for listen packets
  -n TEST_HOST_INTERFACE, --test_host_interface TEST_HOST_INTERFACE
                        Set test host network interface for listen packets
  -t TEST_HOST, --test_host TEST_HOST
                        Set test host IP address for ssh connection
  -m TEST_MAC, --test_mac TEST_MAC
                        Set test host MAC address for ssh connection
  -o TEST_OS, --test_os TEST_OS
                        Set test host OS (MacOS, Linux, Windows)
  -u TEST_SSH_USER, --test_ssh_user TEST_SSH_USER
                        Set test host user name for ssh connection
  -p TEST_SSH_PASS, --test_ssh_pass TEST_SSH_PASS
                        Set test host password for ssh connection
  -k TEST_SSH_PKEY, --test_ssh_pkey TEST_SSH_PKEY
                        Set test host private key for ssh connection
  -G GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IP address
  -g GATEWAY_MAC, --gateway_mac GATEWAY_MAC
                        Set gateway MAC address
  -r NUMBER_OF_PACKETS, --number_of_packets NUMBER_OF_PACKETS
                        Set number of network packets for each test
```

### Sample script output:
![network_security_check.py output](https://raw-packet.github.io/static/images/screenshots/network_security_check.py_screenshot.png)

### Traffic sample generated by this script:
![network_security_check.py traffic](https://raw-packet.github.io/static/images/screenshots/network_security_check.py_traffic.png)

### Pcap file: [network_security_check.pcapng](https://raw-packet.github.io/static/traffic/network_security_check.pcapng)

---

## Script: [network_conflict_creator.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/network_conflict_creator.py)

Script for creating network conflicts for various testing.

```
root@kali:~/raw-packet# python3 Scripts/Others/network_conflict_creator.py --help
usage: network_conflict_creator.py [-h] [-i INTERFACE] [-t TARGET_IP]
                                   [-m TARGET_MAC] [--replies] [--requests]
                                   [--broadcast] [-p PACKETS] [-q] [-e]

Network conflict creator script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for listen and send packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  --replies             Send only ARP replies
  --requests            Send only ARP requests
  --broadcast           Send broadcast ARP requests
  -p PACKETS, --packets PACKETS
                        Number of ARP packets (default: 10)
  -q, --quiet           Minimal output
  -e, --exit            Exit on success
```

### Sample script output:
![network_conflict_creator.py output](https://raw-packet.github.io/static/images/screenshots/network_conflict_creator.py_screenshot.png)

### Traffic sample generated by this script:
![network_conflict_creator.py traffic](https://raw-packet.github.io/static/images/screenshots/network_conflict_creator.py_traffic.png)
