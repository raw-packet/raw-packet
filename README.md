# Важная информация:
***Данный проект создан исключительно для ознакомления и изучения сетевых протоколов, и не может быть использован в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.
Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# Проект raw-packet
Данный проект содержит интрументы для низкоуровневой сборки и отправки сетевых пакетов.

В настоящий момент поддерживается отправка пакетов по протоколам: ARP, DHCP, DNS.
При этом возможность отправки данных пакетов возможна только на Linux системах и только с правами суперпользователя.

# dhcp_starvation.py
Данный скрипт производит атаку на DHCP сервер путем переполнения пула свободных IP-адресов на нем (DHCP starvation attack).

```
root@desktop:~/raw-packet# ./dhcp_starvation.py -h
usage: dhcp_starvation.py [-h] [-i INTERFACE] [-p PACKETS] [-m CLIENT_MAC]
                          [-d DELAY] [-n] [-v DHCP_OPTION_VALUE]
                          [-c DHCP_OPTION_CODE] [-f]

DHCP Starvation attack script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send discover packets
  -p PACKETS, --packets PACKETS
                        Number of packets (default: 100000)
  -m CLIENT_MAC, --client_mac CLIENT_MAC
                        Set client MAC address
  -d DELAY, --delay DELAY
                        Set delay time in seconds (default: 1)
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
3. ```-p PACKETS, --packets PACKETS```: количество DHCPDISCOVER пакетов для отправки, по смолчанию - 100000;
4. ```-m CLIENT_MAC, --client_mac CLIENT_MAC```: MAC-адрес клиента в DHCP-запросах;
5. ```-d DELAY, --delay DELAY```: время ожидания между отправкой DHCPDISCOVER пакетов в секундах;
6. ```-n, --not_send_hostname```: не отправлять имя компьютера в DHCP-запросах, по умолчанию это рандомная строка из 8 символов;
7. ```-v DHCP_OPTION_VALUE, --dhcp_option_value DHCP_OPTION_VALUE```: значение DHCP-опции, если вы хотите добавить ее во все запросы;
8. ```-c DHCP_OPTION_CODE, --dhcp_option_code DHCP_OPTION_CODE```: код DHCP-опции, если вы хотите добавить ее во все запросы;
9. ```-f, --find_dhcp```: найти DHCP-сервер в сети без проведения атаки.

## Видео проведения атаки
[![DHCP Starvation preview](https://j.gifs.com/lOzoB5.gif)](http://www.youtube.com/watch?v=yrMqg6xp6qQ)

# dhcp_rogue_server.py
Данный скрипт производит атаку на DHCP-клиентов путем подмены легитимного DHCP-сервера (Rogue DHCP).

```
root@desktop:~/raw-packet# ./dhcp_rogue_server.py -h
usage: dhcp_rogue_server.py [-h] [-i INTERFACE] -f FIRST_OFFER_IP -l
                            LAST_OFFER_IP [-t TARGET_MAC]
                            [-c SHELLSHOCK_COMMAND] [-b] [-p BIND_PORT] [-N]
                            [-E] [-R] [-e REVERSE_PORT] [-n] [-B]
                            [-O SHELLSHOCK_OPTION_CODE] [--ip_path IP_PATH]
                            [--iface_name IFACE_NAME] [--router ROUTER]
                            [--netmask NETMASK] [--broadcast BROADCAST]
                            [--dns DNS] [--lease_time LEASE_TIME]
                            [--domain DOMAIN] [--proxy PROXY]

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
6. ```-c SHELLSHOCK_COMMAND, --shellshock_command SHELLSHOCK_COMMAND```: команда, которая будет выполнена на уязвимом DHCP-клиенте;
7. ```-b, --bind_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать bind shell (awk);
8. ```-p BIND_PORT, --bind_port BIND_PORT```: порт, который будет прослушиваться на уязвимом DHCP-клиенте;
9. ```-N, --nc_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc);
10. ```-E, --nce_reverse_shell```: при эксплуатации уязвимости shellshock на DHCP-клиенте использовать reverse shell (nc -e);
11. ```-e REVERSE_PORT, --reverse_port REVERSE_PORT```: порт вашего хоста, к которому будут поключаться уязвимые DHCP-клиенты при использовании на них reverse shell;
12. ```-n, --without_network```: при эксплуатации уязвимости shellshock на DHCP-клиенте не настраивать сетевой интерфейс;
13. ```-B, --without_base64```: при эксплуатации уязвимости shellshock на DHCP-клиенте не кодировать нагрузку в base64;
14. ```-O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE```: DHCP-опция в которой будет находится полезная нагрузка.
15. ```--ip_path IP_PATH ```: путь до программы ip на уязвимом DHCP-клиенте, по умолчанию - /bin/;
16. ```--iface_name IFACE_NAME```: имя сетевого интерфейса на уязвимом DHCP-клиенте, по умолчанию - eth0;
17. ```--router ROUTER```: IP-адрес шлюза по умолчанию;
18. ```--netmask NETMASK```: маска подсети;
19. ```--broadcast BROADCAST```: широковещательный адрес в подсети;
19. ```--lease_time LEASE_TIME```: время аренды IP-адреса;
19. ```--domain DOMAIN```: домен;
19. ```--proxy PROXY```: прокси.
