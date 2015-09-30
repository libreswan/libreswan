#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

# 0x12345678@192.1.2.45
enckey1=0x43434545464649494a4a4c4c4f4f51515252545457575840
authkey1=0x65876587658765876587658765876587

ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey1 --authkey $authkey1

ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4

# 0xabcdabcd@192.0.1.1
enckey2=0x434545464649494a4a4c4c4f4f5151525254545757584043
authkey2=0x87658765876587658765876587658765

ipsec spi --af inet --edst 192.0.1.1 --spi 0xabcdabcd --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey2 --authkey $authkey2

ipsec spi --af inet --edst 192.0.1.1 --spi 0xabcdabcd --proto tun --src 192.1.2.23 --dst 192.0.1.1 --ip4

ipsec spigrp 	inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp
ipsec spigrp 	inet 192.0.1.1  0xabcdabcd esp inet 192.1.2.45 0x12345678 tun
ipsec spigrp    inet 192.0.1.1  0xabcdabcd tun inet 192.0.1.1  0xabcdabcd esp

ipsec eroute --add --eraf inet --src 192.0.2.1/32 --dst 192.0.1.1/32 --said tun0xabcdabcd@192.0.1.1

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.23 netmask 0xffffff00 broadcast 192.1.2.255 up

arp -s 192.1.2.45 10:00:00:64:64:45
arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look

# magic route command
route add -host 192.0.1.1 gw 192.1.2.45 dev ipsec0
: ==== end ====

