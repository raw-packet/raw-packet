Raw-packet project
===================

[![Official site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python versions][python-versions-label]][python-versions-link]
[![Scapy minimal versions][scapy-version-label]][scapy-version-link]
[![License][license-label]][license-link]
[![Version][version-label]][version-link]
[![Stability][stability-label]][stability-link]

[site-label]: https://raw-packet.github.io/static/images/labels/site.svg
[site-link]: https://raw-packet.github.io/
[os-label]: https://raw-packet.github.io/static/images/labels/os.svg
[os-link]: https://en.wikipedia.org/wiki/Linux
[python-versions-label]: https://raw-packet.github.io/static/images/labels/python.svg
[python-versions-link]: https://www.python.org/download/releases/2.7/
[scapy-version-label]: https://raw-packet.github.io/static/images/labels/scapy.svg
[scapy-version-link]: https://scapy.net
[license-label]: https://raw-packet.github.io/static/images/labels/license.svg
[license-link]: https://github.com/raw-packet/raw-packet/blob/master/LICENSE
[version-label]: https://raw-packet.github.io/static/images/labels/version.svg
[version-link]: https://github.com/raw-packet/raw-packet/releases
[stability-label]: https://raw-packet.github.io/static/images/labels/stability.svg
[stability-link]: https://github.com/raw-packet/raw-packet/releases

[![Logo](https://raw-packet.github.io/static/images/logo/logo-caption.png)](https://raw-packet.github.io/)

# Important information:
***This project is created only for education process and can not be used for 
law violation or personal gain.<br/>The author of this project is not responsible for any possible harm caused by the materials of this project.***

# Важная информация:
***Данный проект создан исключительно в образовательных целях, и не может быть использован в целях нарушающих законодательство, в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.<br/>Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# Info
Author: [Vladimir Ivanov](https://github.com/Vladimir-Ivanov-Git)<br/>
Project email: [raw.packet.project@gmail.com](mailto:raw.packet.project@gmail.com)<br/>
PGP Public key: [raw.packet.project@gmail.com PGP Public key](https://raw-packet.github.io/static/pgp/Raw-packet.asc)<br/>
Current project version: [0.0.4](https://github.com/raw-packet/raw-packet)<br/>
Last stable release: [0.0.3](https://github.com/raw-packet/raw-packet/releases/tag/0.0.3)<br/>
Required OS: [Linux based](https://en.wikipedia.org/wiki/Linux)<br/>
Python version: [2.7](https://www.python.org/download/releases/2.7/)<br/>
Scapy version: [2.3.1](https://scapy.net)<br/>
License: [MIT](https://github.com/raw-packet/raw-packet/blob/master/LICENSE)

# Install

### Ubuntu based OS install with apt (recommended):
```
sudo apt update
sudo apt install python python-pip python-scapy python-netifaces python-ipaddress python-netaddr python-psutil
sudo apt install apache2 php lsof net-tools wireless-tools nmap aircrack-ng 
git clone https://github.com/raw-packet/raw-packet
cd ./raw-packet
```

### Ubuntu based OS install with pip:
```
sudo apt update
sudo apt install python python-pip apache2 php lsof net-tools wireless-tools 
sudo apt install nmap aircrack-ng 
git clone https://github.com/raw-packet/raw-packet
cd ./raw-packet
sudo pip install -r requirements.txt
```

# Scripts

# DHCP

## Sript: dhcp_starvation.py
This script implement the attack - [DHCP starvation](https://www.sciencedirect.com/science/article/pii/S0045790612001140).<br/>DHCP starvation attack is an attack that targets DHCP servers whereby forged DHCP requests are crafted by an attacker with the intent of exhausting all available IP addresses that can be allocated by the DHCP server.

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

## Script: dhcp_rogue_server.py
Данный скрипт производит атаку на DHCP-клиентов путем подмены легитимного DHCP-сервера (Rogue DHCP).

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

# Apple

## Script: apple_dhcp_mitmer.py
Данный скрипт в автоматическом режиме обнаруживает Apple устройства в сети и с помощью протокола DHCP изменяет IP-адреса маршрутизатора и DNS-сервера на всех устройствах на ваш IP-адрес.

```
root@kali:~/raw-packet# ./apple_dhcp_mitmer.py -h
usage: apple_dhcp_mitmer.py [-h] [-i LISTEN_IFACE] [-r AIREPLAY_IFACE]
                            [-d DEAUTH]

Apple DHCP MiTM creator

optional arguments:
  -h, --help            show this help message and exit
  -i LISTEN_IFACE, --listen_iface LISTEN_IFACE
                        Set interface name for send DHCPACK packets
  -c, --use_network_conflict
                        Use network conflict technique
  -r AIREPLAY_IFACE, --aireplay_iface AIREPLAY_IFACE
                        Set interface name for aireplay
  -d DEAUTH, --deauth DEAUTH
                        Set number of deauth packets (dafault=35)
```

### Demo video with deauth packets technique:
[![Apple WiFi MiTM preview](https://j.gifs.com/nZnOX5.gif)](https://youtu.be/MmPluMxOyMk)

### Demo video with network conflict technique:
[![Apple network conflict MiTM](https://j.gifs.com/2v43V1.gif)](https://youtu.be/-vg2gNiQ53s)

# Binary exploits

## Script: dnsmasploit.py
Данный скрипт предназначен для эксплуатации уязвимостей CVE-2017-14493 и CVE-2017-14494.

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
