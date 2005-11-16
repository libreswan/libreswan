#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758

inspi=0x01000583
outspi=$inspi

eastip=192.1.2.23
westip=192.1.2.45

source=192.0.2.0/24
dst=192.0.1.0/24

#        0123456789abcdef0123456789abcdef0123456789abcdef
#
#        48 bytes = 192 bits
#
# gateway is: 216.209.86.50

# outbound SPI
ipsec spi --af inet --edst $eastip  --spi $outspi --proto esp --src $westip --esp 3des --enckey $enckey 
ipsec spi --af inet --edst $eastip  --spi $outspi --proto tun --src $westip --dst $eastip --ip4
ipsec spigrp inet $eastip $outspi tun inet $eastip $outspi esp 

ipsec eroute --add --eraf inet --src $source --dst $dst --said tun$inspi@$eastip

# inbound SPI
ipsec spi --af inet --edst $westip --spi $inspi  --proto esp --src $eastip --esp 3des --enckey $enckey 
ipsec spi --af inet --edst $westip --spi $inspi  --proto tun --src $eastip --dst $westip --ip4
ipsec spigrp inet $westip $inspi tun inet $westip $inspi esp 

route add -net 192.0.1.0 netmask 255.255.255.0 gw 192.1.2.45 dev ipsec0

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

arp -s 192.0.1.1  10:00:00:ab:cd:01
arp -s 192.1.2.23 10:00:00:64:64:23
arp -s 192.1.2.254 10:00:00:64:64:23

ipsec look

ipsec klipsdebug --all 
: ==== end ====

