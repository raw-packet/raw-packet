# Важная информация:
***Данный проект создан исключительно в образовательных целях, и не может быть использован в целях нарушающих законодательство, в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.
Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# Проект raw-packet
Данный проект содержит интрументы для низкоуровневой сборки и отправки сетевых пакетов.

В настоящий момент поддерживается отправка пакетов по протоколам: ARP, DHCP, DNS.
При этом возможность отправки данных пакетов возможна только на Linux системах и только с правами суперпользователя.

# dhcp_starvation.py
Данный скрипт производит атаку на DHCP сервер путем переполнения пула свободных IP-адресов на нем (DHCP starvation attack).

```
root@desktop:~/raw-packet# ./dhcp_starvation.py -h
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

## Видео проведения атаки
[![DHCP Starvation preview](https://j.gifs.com/GZGgEJ.gif)](https://youtu.be/Nc8lRo9LbKQ)

# dhcp_rogue_server.py
Данный скрипт производит атаку на DHCP-клиентов путем подмены легитимного DHCP-сервера (Rogue DHCP).

```
root@desktop:~/raw-packet# ./dhcp_rogue_server.py -h
usage: dhcp_rogue_server.py [-h] [-i INTERFACE] [-f FIRST_OFFER_IP]
                            [-l LAST_OFFER_IP] [-t TARGET_MAC] [-I TARGET_IP]
                            [-q] [--apple] [-c SHELLSHOCK_COMMAND] [-b]
                            [-p BIND_PORT] [-N] [-E] [-R] [-e REVERSE_PORT]
                            [-n] [-B] [-O SHELLSHOCK_OPTION_CODE]
                            [--ip_path IP_PATH] [--iface_name IFACE_NAME]
                            [--dhcp_mac DHCP_MAC] [--dhcp_ip DHCP_IP]
                            [--router ROUTER] [--netmask NETMASK]
                            [--broadcast BROADCAST] [--dns DNS]
                            [--lease_time LEASE_TIME] [--domain DOMAIN]
                            [--proxy PROXY]

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
  --proxy PROXY         Set proxy
```

## Аргументы скрипта dhcp_rogue_server.py:
1. ```-h, --help```: вывод помощи;
2. ```-i INTERFACE, --interface INTERFACE```: используемый сетевой интерфейс для прослушивания DHCP-запросов, данный параметр не обязательно выставлять, если вы его не выставите скрипт выведет список активных сетевых интерфейсов и вы выберете интерфейс из этого списка;
3. ```-f FIRST_OFFER_IP, --first_offer_ip FIRST_OFFER_IP```: первый IP-адрес который будет выдан DHCP-клиентам;
4. ```-l LAST_OFFER_IP, --last_offer_ip LAST_OFFER_IP```: последний IP-адрес который будет выдан DHCP-клиентам;
5. ```-t TARGET_MAC, --target_mac TARGET_MAC```: MAC-адрес цели, если данный параметр будет задан то будет осущевляться перехват DHCP-запросов только от данного MAC-адреса;
6. ```-I TARGET_IP, --target_ip TARGET_IP```: IP-адрес, который необходимо назначить для MAC-адреса: --target_mac TARGET_MAC;
7. ```-q, --quiet```: минимальный вывод скрипта;
8. ```--apple```: специальный параметр для проведения MiTM для устройств Apple;
9. ```-c SHELLSHOCK_COMMAND, --shellshock_command SHELLSHOCK_COMMAND```: команда, которая будет выполнена на уязвимом DHCP-клиенте;
10. ```-b, --bind_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать bind shell (awk);
11. ```-p BIND_PORT, --bind_port BIND_PORT```: порт, который будет прослушиваться на уязвимом DHCP-клиенте;
12. ```-N, --nc_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc);
13. ```-E, --nce_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc -e);
14. ```-e REVERSE_PORT, --reverse_port REVERSE_PORT```: порт вашего хоста, к которому будут поключаться уязвимые DHCP-клиенты при использовании на них reverse shell;
15. ```-n, --without_network```: при эксплуатации уязвимости shellshock на DHCP-клиенте не настраивать сетевой интерфейс;
16. ```-B, --without_base64```: при эксплуатации уязвимости shellshock на DHCP-клиенте не кодировать нагрузку в base64;
17. ```-O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE```: DHCP-опция в которой будет находится полезная нагрузка.
18. ```--ip_path IP_PATH ```: путь до программы ip на уязвимом DHCP-клиенте, по умолчанию - /bin/;
19. ```--iface_name IFACE_NAME```: имя сетевого интерфейса на уязвимом DHCP-клиенте, по умолчанию - eth0;
20. ```--dhcp_mac DHCP_MAC```: MAC-адрес DHCP-сервера;
21. ```--dhcp_ip DHCP_IP```: IP-адрес DHCP-сервера;
22. ```--router ROUTER```: IP-адрес шлюза по умолчанию;
23. ```--netmask NETMASK```: маска подсети;
24. ```--broadcast BROADCAST```: широковещательный адрес в подсети;
25. ```--dns DNS```: IP-адрес DNS-сервера;
26. ```--lease_time LEASE_TIME```: время аренды IP-адреса;
27. ```--domain DOMAIN```: домен;
28. ```--proxy PROXY```: прокси.

## Видео проведения атаки
[![DHCP Rogue server preview](https://j.gifs.com/2R6OEz.gif)](https://youtu.be/OBXol-o2PEU)

# apple_dhcp_mitmer.py
Данный скрипт в автоматическом режиме обнаруживает Apple устройства в WiFi сети и с помощью протокола DHCP изменяет IP-адреса маршрутизатора и DNS-сервера на всех устройствах на ваш IP-адрес.

```
root@desktop:~/raw-packet# ./apple_wifi_mitmer.py -h
usage: apple_wifi_mitmer.py [-h] [-i LISTEN_IFACE] [-r AIREPLAY_IFACE]
                            [-d DEAUTH]

Apple WiFi DHCP MiTM creator

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

## Видео проведения атаки с использованием deauth пакетов
[![Apple WiFi MiTM preview](https://j.gifs.com/nZnOX5.gif)](https://youtu.be/MmPluMxOyMk)

## Видео проведения атаки с использованием протокола обнаружения конфликта IP-адресов в сети
[![Apple network conflict MiTM](https://j.gifs.com/2v43V1.gif)](https://youtu.be/-vg2gNiQ53s)

# dnsmasploit.py
Данный скрипт предназначен для эксплуатации уязвимости CVE-2017-14493 (Stack Based overflow).

```
root@desktop:~/raw-packet# ./dnsmasploit.py -h
usage: dnsmasploit.py [-h] -t TARGET [-p TARGET_PORT] [-c CAPACITY]
                      [-v VERSION] [--interpreter INTERPRETER]
                      [--interpreter_arg INTERPRETER_ARG] [--payload PAYLOAD]
                      [--command COMMAND] [--bind_port BIND_PORT]
                      [--reverse_port REVERSE_PORT]
                      [--reverse_host REVERSE_HOST]

Exploit for dnsmasq CVE-2017-14493 (Stack Based overflow)

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Set target IPv6 address
  -p TARGET_PORT, --target_port TARGET_PORT
                        Set target port, default=547
  -c CAPACITY, --capacity CAPACITY
                        Set capacity (x86 or x86_64), default=x86
  -v VERSION, --version VERSION
                        Set dnsmasq version (2.75, 2.76, 2.77), default=2.77
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
                        Set reverse host, default="127.0.0.1"
```

## Видео проведения атаки с использованием dnsmasploit
[![dnsmasploit preview](https://j.gifs.com/N9x0wN.gif)](https://youtu.be/PfuGGwZdhVs)
