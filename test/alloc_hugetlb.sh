#!/bin/bash

sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
dpdk-hugepages.py -p 2M --setup 512M
