# Introduction

cfwd - Implementation a Simple DPDK-Based Packet Forwarder (based on l2fwd sample).
In accordance with the requirements, changes were made to the l2fwd source code,
which can be viewed in the commit history

Поставляемые фичи:
1. Multi-core support (Для демонстрации используется двух ядерная настройка)
2. Multi-queue support (Для демонстрации используется 2 очереди для каждого порта)
3. Packet Processing Logic: гибкая система ACL фильтрации основанная на
   подсистеме DPDK RTE ACL; парсер текстовых ACL правил c собственным userfriendly форматом
4. Periodic real time traffic statistics: отображение пропускной способности, 
   переданый байтов, пакетов и т.п. с помощью внешних утилит, bmon 4.0 например
5. Parse incoming packets to extract basic Ethernet/IP header information.
   Реализовано жесткое условие 'только IPv4' при обработке трафика.
6. Modifycation packet headers (change the destination MAC address)
7. Logging & Debugging: добавлена поддержка библиотеки логирования основанной
   на открытом проекте log.c

# Preparing for compilation, resolving dependencies

You must have DPDK pre-installed
and you must also install the following additional packages:

```bash
sudo apt install linux-headers-6.11.0-25-generic
sudo apt install tcpreplay
```

# Setting up the DPDK environment

For efficient operation of DPDK it is recommended to use hugetlb pages.
To allocate hugetlb at the time of loading the Linux operating system kernel,
it is necessary to configure grub accordingly:

Open the GRUB config file as root:

```bash
sudo nano /etc/default/grub
```

Find the line that starts with GRUB_CMDLINE_LINUX_DEFAULT and add the following parameters:

```bash
GRUB_CMDLINE_LINUX_DEFAULT="... default_hugepagesz=2M hugepagesz=2M hugepages=1024"
```

Apply the changes by updating the GRUB configuration:

```bash
sudo update-grub
```

Reboot the System

```bash
sudo reboot
```

or you can allocate hugetlb after kernel load

```bash
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
dpdk-hugepages.py -p 1G --setup 2G
```

# Build

make

# Run the application

Command line to run the application:

```bash

sudo ./sfwd --no-pci -l 0-1 -n 4 
    --vdev=net_tap0,iface=tap0
    --vdev=net_tap1,iface=tap1 
    -- -p 0x3 
    --rule_ipv4=/home/sk/work/sfwd/acl.rules 
    --rule_ipv6=/home/sk/work/sfwd/acl.rules 
    --config="(0,0,0),(0,1,0),(1,0,1),(1,1,1)"
```

since it would be more convenient to use virtual network devices for development and debugging.
And since DPDK can work with some virtual network devices, such as tap, for example.
For debugging purposes, we will build such a test stand, based on TAP devices.

                ┌──────────┐
                │ tcpreplay│
                └────┬─────┘
                     │
                ┌────▼─────┐
                │   tap0   │
                └────┬─────┘
                     │
                ┌────▼─────┐
                │          │  cpu0 recieve packets from port0 in 2 quene
                │  cfwd    │      and sent it into port1
                │          │  cpu1 recieve packets from port1 in 2 quene
                └────┬─────┘      and sent it into port0
                     │
                ┌────▼─────┐
                │   tap1   │
                └────┬─────┘
                     │
                ┌────▼─────┐
                │ tcpdump  │
                └──────────┘

# Параметры командной строки

Все параметры, которые находятся до разграничителя '--' это опции DPDK EAL
здесь используются некоторые из них:

    -l 0-1
    CPU core list — какие логические ядра будут использоваться для работы DPDK.
    Здесь указаны ядра 0 и 1.

    -n 4
    Количество каналов памяти (memory channels) для доступа к памяти (часто связано с числом каналов 
    памяти на платформе). Обычно 4 — стандартное значение для производительности.

    --no-pci
    Отключает сканирование физических PCI устройств (сетевая карта, NIC).

    --vdev=net_tap0,iface=tap0
    Создаёт первое виртуальное сетевое устройство TAP с именем tap0.

    --vdev=net_tap1,iface=tap1
    Создаёт второе виртуальное сетевое устройство TAP с именем tap1.

Параметры приложения cfwd (через --)

    --
    Разделитель между параметрами EAL и параметрами самого приложения (cfwd).

    -p 0x3
    Port mask — битовая маска, указывающая какие порты будут использоваться приложением.
    0x3 в двоичном виде — 11, т.е. первые два порта (0 и 1) активны.
    В данном случае это соответствуют tap0 и tap1.

    --rule_ipv4
    --rule_ipv6
    Используются для указания пути к ACL правилам фильтрации для протоколов 
    IPv4 и IPv6 соответственно

    --config (CPU, )
    конфигурация для packet forwarding. 

# Command line options

All options before '--' delimiter are DPDK EAL options
Some of them are used here:

    -l 0-1
    CPU core list — which logical cores will be used for DPDK operation.
    Here cores 0 and 1 are specified.

    -n 4
    The number of memory channels for memory access (often related to the 
    number of memory channels on the platform). Usually 4 is a standard value for performance.

    --no-pci
    Disables scanning of physical PCI devices (network card, NIC).

    --vdev=net_tap0,iface=tap0
    Creates the first virtual TAP network device named tap0.

    --vdev=net_tap1,iface=tap1
    Creates the second virtual TAP network device named tap1.

    --rule_ipv4
    option specifies the reading of IPv4 rules sets from the configuration file

    --rule_ipv6
    option specifies the reading of IPv6 rules sets from the configuration file

    --config (port,queue,lcore)[,(port,queue,lcore)]: 
    Determines which queues from which ports are mapped to which cores.

cfwd application parameters (via --)

    --
    Separator between standart EAL parameters and application parameters (cfwd).

    -p 0x3
    Port mask — bit mask indicating which ports will be used by the application.
    0x3 in binary is 11, i.e. the first two ports (0 and 1) are active.
    In this case, these correspond to tap0 and tap1.

# Debuging 

after launching the application 
После запуска приложения мы можем наблюдать отладосную информацию о правильности
выделения пулов памяти, активации нужных ядер, использования правильных очередей


```bash
sudo ./sfwd --no-pci -l 0-1 -n 4 --vdev=net_tap0,iface=tap0 --vdev=net_tap1,iface=tap1 -- -p 0x3 --rule_ipv4=/home/sk/work/sfwd/acl.rules --rule_ipv6=/home/sk/work/sfwd/acl.rules --config="(0,0,0),(0,1,0),(1,0,1),(1,1,1)"
EAL: Detected CPU lcores: 12
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: No free 2048 kB hugepages reported on node 0
TELEMETRY: No legacy callbacks, legacy socket not created
Neither ACL, LPM, EM, or FIB selected, defaulting to LPM
Initializing port 0 ... Creating queues: nb_rxq=2 nb_txq=2... Port 0 modified RSS hash function based on hardware support,requested:0x3bffc configured:0x3afbc
Address:26:2F:6F:5A:94:3F, Destination:02:00:00:00:00:00, Allocated mbuf pool on socket 0
ACL options are:
rule_ipv4: /home/sk/work/sfwd/acl.rules
rule_ipv6: /home/sk/work/sfwd/acl.rules
alg: default
L3FWDACL: IPv4 Route entries 0:
L3FWDACL: IPv4 ACL entries 0:
L3FWDACL: IPv6 Route entries 0:
L3FWDACL: IPv6 ACL entries 0:
txq=0,0,0 txq=1,1,0
Initializing port 1 ... Creating queues: nb_rxq=2 nb_txq=2... Port 1 modified RSS hash function based on hardware support,requested:0x3bffc configured:0x3afbc
Address:E2:82:58:D9:7C:3F, Destination:02:00:00:00:00:01, txq=0,0,0 txq=1,1,0

Initializing rx queues on lcore 0 ... rxq=0,0,0 rxq=0,1,0
Initializing rx queues on lcore 1 ... rxq=1,0,0 rxq=1,1,0

Checking link statusdone
Port 0 Link up at 10 Gbps FDX Fixed
Port 1 Link up at 10 Gbps FDX Fixed
L3FWD: >>>> entering main loop on lcore 1
L3FWD:  -- lcoreid=1 portid=1 rxqueueid=0
L3FWD:  -- lcoreid=1 portid=1 rxqueueid=1
L3FWD: >>>> entering main loop on lcore 0
L3FWD:  -- lcoreid=0 portid=0 rxqueueid=0
L3FWD:  -- lcoreid=0 portid=0 rxqueueid=1
```


we can forward the recorded traffic sample
(samples can be taken from https://wiki.wireshark.org/SampleCaptures) to tap0

```bash
sudo tcpreplay --intf1=tap0 --multiplier=50 --loop=0 http.cap
```

and see what comes to tap1

```bash
sk@sk:~$ sudo tcpdump -i tap1
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tap1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
22:08:38.655921 IP6 sk.mdns > ff02::fb.mdns: 0*- [0q] 2/0/0 (Cache flush) PTR sk.local., (Cache flush) AAAA fe80::a4da:d3ff:fe2a:49f (134)
22:08:38.679611 IP6 sk > ip6-allrouters: ICMP6, router solicitation, length 16
22:08:38.679680 IP6 sk > ip6-allrouters: ICMP6, router solicitation, length 16
22:08:39.038868 IP6 sk.mdns > ff02::fb.mdns: 0*- [0q] 2/0/0 (Cache flush) PTR sk.local., (Cache flush) AAAA fe80::44:76ff:fee3:8045 (134)
20:27:27.491018 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [P.], seq 12421:13801, ack 480, win 6432, length 1380: HTTP
20:27:27.493222 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 13801, win 9660, length 0
20:27:27.493423 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 13801:15181, ack 480, win 6432, length 1380: HTTP
20:27:27.496029 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 15181:16561, ack 480, win 6432, length 1380: HTTP
20:27:27.496031 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 16561, win 9660, length 0
20:27:27.498834 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 16561:17941, ack 480, win 6432, length 1380: HTTP
20:27:27.498836 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 17941, win 9660, length 0
20:27:27.504447 IP 216.239.59.99.http > dialin-145-254-160-237.pools.arcor-ip.net.3371: Flags [P.], seq 1:1431, ack 721, win 31460, length 1430: HTTP: HTTP/1.1 200 OK
20:27:27.504449 IP dialin-145-254-160-237.pools.arcor-ip.net.3371 > 216.239.59.99.http: Flags [.], ack 1591, win 8760, length 0
20:27:27.505850 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [P.], seq 17941:18365, ack 480, win 6432, length 424: HTTP
20:27:27.509264 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 18365, win 9236, length 0
20:27:27.767064 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [F.], seq 18365, ack 480, win 6432, length 0
20:27:27.767068 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 18366, win 9236, length 0
20:27:28.010221 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [F.], seq 480, ack 18366, win 9236, length 0
20:27:28.016831 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], ack 481, win 6432, length 0
20:27:28.016834 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [S], seq 951057939, win 8760, options [mss 1460,nop,nop,sackOK], length 0
20:27:28.035077 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [S.], seq 290218379, ack 951057940, win 5840, options [mss 1380,nop,nop,sackOK], length 0
20:27:28.035080 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 1, win 9660, length 0
20:27:28.035084 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [P.], seq 1:480, ack 1, win 9660, length 479: HTTP: GET /download.html HTTP/1.1
20:27:28.046307 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], ack 480, win 6432, length 0
20:27:28.050515 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 1:1381, ack 480, win 6432, length 1380: HTTP: HTTP/1.1 200 OK
20:27:28.053121 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 1381, win 9660, length 0
20:27:28.053123 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 1381:2761, ack 480, win 6432, length 1380: HTTP
20:27:28.057128 IP dialin-145-254-160-237.pools.arcor-ip.net.3372 > 65.208.228.223.http: Flags [.], ack 2761, win 9660, length 0
tcpdump: pcap_loop: The interface disappeared
3103 packets captured
3382 packets received by filter
260 packets dropped by kernel
```


В процессе работы собранного тестового стенда можно наблюдать статистику
переданных байт

Показать картинку 

```bash

```
