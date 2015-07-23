#!/bin/sh

TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey1=0x4043434545464649494a4a4c4c4f4f515152525454575758
enckey2=0x5464649494a4a4c4c4f4f515152525454575758404343454
authkey1=0x87658765876587658765876587658765
authkey2=0x65876587658765876587658765876587

: set up SPI 1
ipsec spi --af inet --edst 192.1.2.45 --spi 0x88447755 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey1 --authkey $authkey1 --saref

ipsec spi --af inet --edst 192.1.2.45 --spi 0x88447755 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4 --saref

ipsec spigrp inet 192.1.2.45 0x88447755 tun inet 192.1.2.45 0x88447755 esp

: set up SPI 2
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey2 --authkey $authkey2 --saref

ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4 --saref

ipsec spigrp inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp


ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

# magic route command
route add -host 192.0.1.1 gw 192.1.2.45 dev ipsec0

ipsec eroute --add --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x88447755@192.1.2.45

echo Send packet set 1
read ans

ipsec eroute --del --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24

ipsec eroute --add --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x12345678@192.1.2.45

echo Send packet set 2
read ans



#arp -s 192.1.2.23 10:00:00:64:64:45
#arp -s 192.1.2.254 10:00:00:64:64:45

