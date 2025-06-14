#!/bin/bash

../cmake-build-debug/sfwd --no-pci -l 0-1 -n 4 \
                              --vdev=net_tap0,iface=tap0 \
                              --vdev=net_tap1,iface=tap1  \
                              -- -p 0x3 \
                              --stats_period 1 \
                              --rule_ipv4=/home/sk/work/sfwd/acl_v4.rules \
                              --rule_ipv6=/home/sk/work/sfwd/acl_v6.rules \
                              --config="(0,0,0),(0,1,0),(1,0,1),(1,1,1)"
