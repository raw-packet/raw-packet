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
