[Raw-packet project](https://raw-packet.github.io/)
===================

[![Official site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python versions][python-versions-label]][python-versions-link]
[![Scapy minimal versions][scapy-version-label]][scapy-version-link]
[![License][license-label]][license-link]
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
[license-link]: https://github.com/Vladimir-Ivanov-Git/raw-packet/blob/master/LICENSE
[stability-label]: https://raw-packet.github.io/static/images/labels/stability.svg
[stability-link]: https://github.com/Vladimir-Ivanov-Git/raw-packet/releases

# Important information:
***This project is created only for education process and can not be used for 
law violation or personal gain. The author of this project is not responsible for any possible harm caused by the materials of this project.***

# Важная информация:
***Данный проект создан исключительно в образовательных целях, и не может быть использован в целях нарушающих законодательство, в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.
Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# dhcp_starvation.py
Данный скрипт производит атаку на DHCP-сервер путем переполнения пула свободных IP-адресов.

```
root@kali:~/raw-packet# ./dhcp_starvation.py -h
usage: dhcp_starvation.py [-h] [-i INTERFACE] [-d DELAY] [-t TIMEOUT] [-n]
                          [-v DHCP_OPTION_VALUE] [-c DHCP_OPTION_CODE] [-f]

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
```

## Аргументы скрипта dhcp_starvation.py:
1. ```-h, --help```: вывод помощи;
2. ```-i INTERFACE, --interface INTERFACE```: используемый сетевой интерфейс, данный параметр не обязательно выставлять, если вы его не выставите скрипт выведет список активных сетевых интерфейсов и вы выберете интерфейс из этого списка;
3. ```-d DELAY, --delay DELAY```: время ожидания между отправкой DHCPDISCOVER пакетов в секундах;
4. ```-t TIMEOUT, --timeout TIMEOUT```: время ожидания DHCPACK от сервера в секундах, после чего скрипт остановится;
5. ```-n, --not_send_hostname```: не отправлять имя компьютера в DHCP-запросах, по умолчанию это рандомная строка из 8 символов;
6. ```-v DHCP_OPTION_VALUE, --dhcp_option_value DHCP_OPTION_VALUE```: значение DHCP-опции, если вы хотите добавить ее во все запросы;
7. ```-c DHCP_OPTION_CODE, --dhcp_option_code DHCP_OPTION_CODE```: код DHCP-опции, если вы хотите добавить ее во все запросы;
8. ```-f, --find_dhcp```: найти DHCP-сервер в сети без проведения атаки.

## Video
[![DHCP Starvation preview](https://j.gifs.com/GZGgEJ.gif)](https://youtu.be/Nc8lRo9LbKQ)

# dhcp_rogue_server.py
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

## Аргументы скрипта dhcp_rogue_server.py:
1. ```-h, --help```: вывод помощи;
2. ```-i INTERFACE, --interface INTERFACE```: используемый сетевой интерфейс для прослушивания DHCP-запросов, данный параметр не обязательно выставлять, если вы его не выставите скрипт выведет список активных сетевых интерфейсов и вы выберете интерфейс из этого списка;
3. ```-f FIRST_OFFER_IP, --first_offer_ip FIRST_OFFER_IP```: первый IP-адрес который будет выдан DHCP-клиентам;
4. ```-l LAST_OFFER_IP, --last_offer_ip LAST_OFFER_IP```: последний IP-адрес который будет выдан DHCP-клиентам;
5. ```-t TARGET_MAC, --target_mac TARGET_MAC```: MAC-адрес цели, если данный параметр будет задан то будет осущевляться перехват DHCP-запросов только от данного MAC-адреса;
6. ```-I TARGET_IP, --target_ip TARGET_IP```: IP-адрес, который необходимо назначить для MAC-адреса: --target_mac TARGET_MAC;
7. ```-q, --quiet```: минимальный вывод скрипта;
8. ```--apple```: специальный параметр для проведения MiTM для устройств компании Apple;
9. ```--broadcast_response```:  отправлять только широковещательные ответы;
10. ```--force```: параметр для новых клиентов или клиентов после DHCP DECLINE;
11. ```--not_exit```: не выходить в случае успешного проведения MiTM атаки;
12. ```-c SHELLSHOCK_COMMAND, --shellshock_command SHELLSHOCK_COMMAND```: команда, которая будет выполнена на уязвимом DHCP-клиенте;
13. ```-b, --bind_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать bind shell (awk);
14. ```-p BIND_PORT, --bind_port BIND_PORT```: порт, который будет прослушиваться на уязвимом DHCP-клиенте;
15. ```-N, --nc_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc);
16. ```-E, --nce_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc -e);
17. ```-e REVERSE_PORT, --reverse_port REVERSE_PORT```: порт вашего хоста, к которому будут поключаться уязвимые DHCP-клиенты при использовании на них reverse shell;
18. ```-n, --without_network```: при эксплуатации уязвимости shellshock на DHCP-клиенте не настраивать сетевой интерфейс;
19. ```-B, --without_base64```: при эксплуатации уязвимости shellshock на DHCP-клиенте не кодировать нагрузку в base64;
20. ```-O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE```: DHCP-опция в которой будет находится полезная нагрузка.
21. ```--ip_path IP_PATH ```: путь до программы ip на уязвимом DHCP-клиенте, по умолчанию - /bin/;
22. ```--iface_name IFACE_NAME```: имя сетевого интерфейса на уязвимом DHCP-клиенте, по умолчанию - eth0;
23. ```--dhcp_mac DHCP_MAC```: MAC-адрес DHCP-сервера;
24. ```--dhcp_ip DHCP_IP```: IP-адрес DHCP-сервера;
25. ```--router ROUTER```: IP-адрес шлюза по умолчанию;
26. ```--netmask NETMASK```: маска подсети;
27. ```--broadcast BROADCAST```: широковещательный адрес в подсети;
28. ```--dns DNS```: IP-адрес DNS-сервера;
29. ```--lease_time LEASE_TIME```: время аренды IP-адреса;
30. ```--domain DOMAIN```: домен;
31. ```--proxy PROXY```: IP-адрес прокси сервера;
32. ```--tftp TFTP```: IP-адрес TFTP сервера.

## Video
[![DHCP Rogue server preview](https://j.gifs.com/2R6OEz.gif)](https://youtu.be/OBXol-o2PEU)

# apple_dhcp_mitmer.py
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

## Аргументы скрипта apple_dhcp_mitmer.py:
1. ```-h, --help```: вывод помощи;
2. ```-i LISTEN_IFACE, --listen_iface LISTEN_IFACE```: используемый сетевой интерфейс для прослушивания DHCP-запросов, данный параметр не обязательно выставлять, если вы его не выставите скрипт выведет список активных сетевых интерфейсов и вы выберете интерфейс из этого списка;
3. ```-c, --use_network_conflict```: использовать протокол обнаружения конфликта IP-адресов в сети;
4. ```-r AIREPLAY_IFACE, --aireplay_iface AIREPLAY_IFACE```: используемый сетевой интерфейс для отправки deauth пакетов, данный параметр не обязательно выставлять, если вы его не выставите скрипт выведет список активных сетевых интерфейсов и вы выберете интерфейс из этого списка;
5. ```-d DEAUTH, --deauth DEAUTH```: количество deauth пакетов для отправки.

## Video with deauth packets technique
[![Apple WiFi MiTM preview](https://j.gifs.com/nZnOX5.gif)](https://youtu.be/MmPluMxOyMk)

## Video with network conflict technique
[![Apple network conflict MiTM](https://j.gifs.com/2v43V1.gif)](https://youtu.be/-vg2gNiQ53s)

# dnsmasploit.py
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

## Video (CVE-2017-14493)
[![dnsmasploit preview](https://j.gifs.com/7LWln8.gif)](https://youtu.be/VWr0zCZlMrE)

## Video (CVE-2017-14494)
[![dnsmasploit preview](https://j.gifs.com/1rB5VG.gif)](https://youtu.be/GqMuZ1wMCWQ)
