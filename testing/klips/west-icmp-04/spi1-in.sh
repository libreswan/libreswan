#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x8765876587658765876587658765876587658765
ipsec klipsdebug --set pfkey
#ipsec klipsdebug --set verbose

ipsec spi --af inet --edst 192.1.2.45 --spi 0xD1234567 --proto esp --src 192.1.2.23 --esp 3des-sha1-96 --enckey $enckey --authkey $authkey

ipsec spi --af inet --edst 192.1.2.45 --spi 0xD1234567 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4

ipsec spigrp inet 192.1.2.45 0xD1234567 tun inet 192.1.2.45 0xD1234567 esp 

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

#arp -s 192.1.2.23 10:00:00:64:64:45
#arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look

# magic route command
route add -host 192.0.2.1 gw 192.1.2.23 dev ipsec0
: ==== end ====

