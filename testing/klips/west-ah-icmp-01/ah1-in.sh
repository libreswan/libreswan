#!/bin/sh

: ==== start ====

TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

authkey=0x98765876587658765876587658765876

ipsec spi --af inet --edst 192.1.2.45 --spi 0x91234567 --proto ah --src 192.1.2.23 --ah hmac-md5-96 --authkey $authkey

ipsec spi --af inet --edst 192.1.2.45 --spi 0x91234567 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4

ipsec spigrp inet 192.1.2.45 0x91234567 tun inet 192.1.2.45 0x91234567 ah

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

#arp -s 192.1.2.23 10:00:00:64:64:45
#arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look

# magic route command
route add -host 192.0.2.1 gw 192.1.2.23 dev ipsec0

: ==== end ====
