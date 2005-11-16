#!/bin/sh
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
ipsec spi --af inet --edst $westip  --spi $outspi --proto esp --src $eastip --esp 3des --enckey $enckey 
ipsec spi --af inet --edst $westip  --spi $outspi --proto tun --src $eastip --dst $westip --ip4
ipsec spigrp inet $westip $outspi tun inet $westip $outspi esp 

ipsec eroute --add --eraf inet --src $source --dst $dst --said tun$inspi@$westip

# inbound SPI
ipsec spi --af inet --edst $eastip --spi $inspi  --proto esp --src $westip --esp 3des --enckey $enckey 
ipsec spi --af inet --edst $eastip --spi $inspi  --proto tun --src $westip --dst $eastip --ip4
ipsec spigrp inet $eastip $inspi tun inet $eastip $inspi esp 

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.23 netmask 0xffffff00 broadcast 192.1.2.255 up

arp -s 192.1.2.45 10:00:00:64:64:45
arp -s 192.1.2.254 10:00:00:64:64:45

route add -net 192.0.1.0 netmask 255.255.255.0 gw 192.1.2.45 dev ipsec0

