#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

#ipsec klipsdebug --set pfkey
#ipsec klipsdebug --set verbose

enckey1=0x43434545464649494a4a4c4c4f4f51515252545457575840
authkey1=0x65876587658765876587658765876587

# set up for outer key only, as inner stuff will just emerge 
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey1 --authkey $authkey1

ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4

ipsec spigrp inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp 

# we record second key here, but we will use it in the tcpdump.
enckey2=0x434545464649494a4a4c4c4f4f5151525254545757584043
authkey2=0x87658765876587658765876587658765

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

#arp -s 192.1.2.23 10:00:00:64:64:45
#arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look

# magic route command
route add -host 192.0.2.1 gw 192.1.2.23 dev ipsec0
: ==== end ====

