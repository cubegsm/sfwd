# Introduction

sfwd — A Simple DPDK-Based Packet Forwarder (based on the l2fwd and l3fwd sample).
This application is a modified version of the standard DPDK samples to meet 
custom requirements. All modifications can be reviewed in the Git commit history.

## Features

**Multi-core support**
- Demonstrated with a dual-core configuration.

**Multi-queue support**
- Each port is configured with 2 RX/TX queues for demonstration purposes.

**Implemented interface statistics collection**
- Real-time monitoring support 
- Configurable display update interval 
- Lock-free aggregation of statistics across all queues

**Implemented a simple packet port rate limiting**
- It is based on the classic token bucket algorithm for controlling 
the packet reception rate on a port, allowing an average processing 
rate of no more than rate_pps packets per second, while permitting 
short bursts of up to burst packets.

**Packet processing logic**
- A flexible ACL filtering system based on DPDK’s RTE ACL subsystem. 
Includes a parser for user-friendly text-based ACL rule files.
  For demonstration purposes, sfwd was launched with ACL filtering enabled 
for both IPv4 and IPv6 traffic, according to the following rules:

acl_v4.rules:
```bash
@192.168.0.0/16 10.0.0.0/8 1000 : 2000 80 : 80 6/0xff 123
```

acl_v6.rules:
```bash
@2001:0db8:0000:0000:0000:0000:0000:0000/32 2001:0db8:1234:0000:0000:0000:0000:0000/48 1000 : 2000 443 : 443 6/0xff 1
```

IPv4 addresses are specified in CIDR format as specified in RFC 4632. 
For ACL they consist of the dot notation for the address and a prefix 
length separated by ‘/’. For example, 192.168.0.34/32, where the address 
is 192.168.0.34 and the prefix length is 32.

The application parses the rules from the file, it ignores empty and comment 
lines and parses and validates the rules it reads. If errors are detected, the 
application exits with messages to identify the errors encountered. The ACL rules 
save the index to the specific rules in the userdata field, while route rules 
save the forwarding port number.

**External periodic real-time traffic statistics support**
- Bandwidth, packet, and byte counters can be observed using external tools
such as bmon, amon, atop, top, etc

**Packet parsing**
- Parses incoming packets to extract Ethernet/IP headers. 
Only IPv4 packets are processed; non-IPv4 traffic is dropped. 
In addition, the IP packet was checked for compliance with RFC 1812

**Header modification**
- Supports modification of packet headers, such as destination MAC address.

**Logging & debugging**
- Integrated with a lightweight logging library based on the open-source project log.c.

# Preparing for compilation, resolving dependencies

Ensure that DPDK is pre-installed on your system.
You also need the following additional packages:

```bash
sudo apt install linux-headers-6.11.0-25-generic
sudo apt install tcpreplay
sudo apt install bmon
```

# Setting up the DPDK environment

To optimize DPDK performance, it's recommended to use hugepages.
You can set these up either at boot time or after system startup.

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

```bash
mkdir build
cd build
cmake ..
make
```

# Running the Application

Command line to run the application:

```bash

sudo ./sfwd --no-pci -l 0-1 -n 4 \
    --vdev=net_tap0,iface=tap0 \
    --vdev=net_tap1,iface=tap1  \
    -- -p 0x3 \
    --stats_period 1 \
    --rule_ipv4=/home/sk/work/sfwd/acl_v4.rules \ 
    --rule_ipv6=/home/sk/work/sfwd/acl_v6.rules \
    --config="(0,0,0),(0,1,0),(1,0,1),(1,1,1)"
```

To simplify development and debugging, virtual TAP devices are used. Since DPDK 
supports virtual interfaces like TAP, we use the following setup:

## Testbed Overview:

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
                │   cfwd   │      and sent it into port1
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

# Command line options

### DPDK EAL Options (before --)

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

### cfwd Application Options (after --)

    --
    Separator between standart EAL parameters and application parameters (cfwd).

    -p 0x3
    Port mask — bit mask indicating which ports will be used by the application.
    0x3 in binary is 11, i.e. the first two ports (0 and 1) are active.
    In this case, these correspond to tap0 and tap1.

    --stats_period
    Determines the frequency of interface statistics output

# Debuging 

After launching, the application outputs detailed logs showing memory pool allocation,
core assignments, queue configurations, and more:

### Example output:


```bash
sudo ./sfwd --no-pci -l 0-1 -n 4 --vdev=net_tap0,iface=tap0 --vdev=net_tap1,iface=tap1 -- --stats_period 1 -p 0x3 --rule_ipv4=/home/sk/work/sfwd/acl_v4.rules --rule_ipv6=/home/sk/work/sfwd/acl_v6.rules --config="(0,0,0),(0,1,0),(1,0,1),(1,1,1)"
EAL: Detected CPU lcores: 12
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: No free 2048 kB hugepages reported on node 0
TELEMETRY: No legacy callbacks, legacy socket not created
Stats period 1 sec
Initializing port 0 ... Creating queues: nb_rxq=2 nb_txq=2... Port 0 modified RSS hash function based on hardware support,requested:0x3bffc configured:0x3afbc
 Address:7E:E2:EE:F4:B5:A6, Destination:02:00:00:00:00:00, Allocated mbuf pool on socket 0
ACL options are:
rule_ipv4: /home/sk/work/sfwd/acl_v4.rules
rule_ipv6: /home/sk/work/sfwd/acl_v6.rules
alg: default
L3FWDACL: IPv4 Route entries 0:
L3FWDACL: IPv4 ACL entries 1:
	1:192.168.0.0/16 10.0.0.0/8 1000 : 2000 80 : 80 0x6/0xff 0xffffffff-0x1fffffff-0xf0000000 
L3FWDACL: IPv6 Route entries 0:
L3FWDACL: IPv6 ACL entries 1:
	1:2001:0db8:0000:0000:0000:0000:0000:0000/32 2001:0db8:1234:0000:0000:0000:0000:0000/48 1000 : 2000 443 : 443 0x6/0xff 0xffffffff-0x1fffffff-0xf0000000 
acl context <l3fwd-acl-ipv40>@0x17e030300
  socket_id=0
  alg=3
  first_load_sz=4
  max_rules=100000
  rule_size=96
  num_rules=1
  num_categories=1
  num_tries=1
acl context <l3fwd-acl-ipv60>@0x17cdde340
  socket_id=0
  alg=3
  first_load_sz=4
  max_rules=100000
  rule_size=192
  num_rules=1
  num_categories=1
  num_tries=1
txq=0,0,0 txq=1,1,0 
Initializing port 1 ... Creating queues: nb_rxq=2 nb_txq=2... Port 1 modified RSS hash function based on hardware support,requested:0x3bffc configured:0x3afbc
 Address:0A:A2:F8:AC:F1:8E, Destination:02:00:00:00:00:01, txq=0,0,0 txq=1,1,0 

Initializing rx queues on lcore 0 ... rxq=0,0,0 rxq=0,1,0 
Initializing rx queues on lcore 1 ... rxq=1,0,0 rxq=1,1,0 

Checking link statusdone
Port 0 Link up at 10 Gbps FDX Fixed
Port 1 Link up at 10 Gbps FDX Fixed
Port 0: rx 00000001 pkts, 000000000000 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000000 pkts, 000000000000 bytes; tx 00000000 pkts, 000000000000 bytes
19:02:20 TRACE sfwd_acl.c:1002: entering main loop on lcore 1
19:02:20 TRACE sfwd_acl.c:1007:  -- lcoreid=1 portid=1 rxqueueid=0
19:02:20 TRACE sfwd_acl.c:1007:  -- lcoreid=1 portid=1 rxqueueid=1
19:02:20 TRACE sfwd_acl.c:1002: entering main loop on lcore 0
19:02:20 TRACE sfwd_acl.c:1007:  -- lcoreid=0 portid=0 rxqueueid=0
19:02:20 TRACE sfwd_acl.c:1007:  -- lcoreid=0 portid=0 rxqueueid=1

Port 0: rx 00000005 pkts, 000000000266 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000003 pkts, 000000000266 bytes; tx 00000000 pkts, 000000000000 bytes

Port 0: rx 00010809 pkts, 000006297804 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000017 pkts, 000006297804 bytes; tx 00010785 pkts, 000000000000 bytes

Port 0: rx 00021531 pkts, 000012548584 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000018 pkts, 000012548584 bytes; tx 00021505 pkts, 000000000000 bytes

Port 0: rx 00032243 pkts, 000018799219 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000018 pkts, 000018799219 bytes; tx 00032216 pkts, 000000000000 bytes

Port 0: rx 00042956 pkts, 000025049996 bytes; tx 00000000 pkts, 000000000000 bytes
Port 1: rx 00000019 pkts, 000025049996 bytes; tx 00042927 pkts, 000000000000 bytes
^C

Signal 2 received, preparing to exit...
Closing port 0... Done
Closing port 1... Done
Bye...
```

# Traffic Replay and Verification

Replay captured traffic to tap0:

```bash
sudo tcpreplay --mbps 50 --intf1=tap0 --loop=0 http.cap
```

Capture forwarded traffic on tap1:

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


Expected output shows Ethernet, IPv4, 
and HTTP traffic being forwarded and captured successfully.

for tap0 device:
![tap0 interface stat](https://github.com/cubegsm/sfwd/blob/main/demo/Screenshot%20from%202025-06-05%2016-01-43.png)

for tap1 device:
![alt text](https://github.com/cubegsm/sfwd/blob/main/demo/Screenshot%20from%202025-06-05%2016-01-37.png)

we can also view statistics using ifconfig

tap0:

```bash
ifconfig tap0
tap0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet6 fe80::d4c7:35ff:fe81:49c0  prefixlen 64  scopeid 0x20<link>
ether d6:c7:35:81:49:c0  txqueuelen 1000  (Ethernet)
RX packets 0  bytes 0 (0.0 B)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 395977  bytes 231045883 (231.0 MB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

tap1:

```bash
ifconfig tap1
tap1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet6 fe80::7c87:41ff:fee7:b509  prefixlen 64  scopeid 0x20<link>
ether 7e:87:41:e7:b5:09  txqueuelen 1000  (Ethernet)
RX packets 395954  bytes 231043103 (231.0 MB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 23  bytes 2780 (2.7 KB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

# Performance Report and Conclusions

### Test Environment:

    Laptop Model: RedmiBook 2024
    Processor: AMD Ryzen 5 5500U (6 cores / 12 threads)
    Memory: 16GB DDR5
    Network Interface: Virtual TAP interface

### Test Configuration:

Packet transmission was conducted over a virtual TAP interface using two queues. 
CPU affinity was set such that CPU0 and CPU1 were utilized—logical threads mapped 
to the same physical core (due to simultaneous multithreading being enabled).

### Performance Results:

Under these conditions, the system achieved a maximum throughput of 500Mbit/s. 
This result reflects the performance limit when using half of a physical CPU core for 
both packet transmission and reception in a virtualized TAP setup.

![alt text](https://github.com/cubegsm/sfwd/blob/main/demo/Screenshot%20from%202025-06-06%2021-08-52.png)

The peak transmission rate was identified through iterative testing, 
defined as the highest rate at which a low but noticeable rate of transmission errors 
from the tap0 interface started to occur.

```bash
ifconfig tap0
tap0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet6 fe80::4401:70ff:fe1b:7ebf  prefixlen 64  scopeid 0x20<link>
ether 46:01:70:1b:7e:bf  txqueuelen 1000  (Ethernet)
RX packets 0  bytes 0 (0.0 B)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 4633199  bytes 2703045399 (2.7 GB)
TX errors 0  dropped 37742 overruns 0  carrier 0  collisions 0
```
