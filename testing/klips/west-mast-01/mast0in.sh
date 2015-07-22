: ==== start ====
#!/bin/sh
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x87658765876587658765876587658765
saref=3745
nfsaref=$(printf "%d" $(( ($saref * 65536) | 0x80000000 )))

# set up the SA itself
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey --authkey $authkey

ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4

ipsec spigrp inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp

# we do *NOT* need to setup an EROUTE, because mast0 accepts packets based
# the SAref# and encrypt them appropriately.
ifconfig mast0 inet 192.1.2.45 netmask 255.255.255.255 up

arp -s 192.1.2.23  10:00:00:64:64:45
arp -s 192.1.2.254 10:00:00:64:64:45
#arp -s 192.0.1.1 10:00:00:32:32:01

ipsec look

echo 0xffffffff >/proc/sys/net/ipsec/debug_xform
echo 0xffffffff >/proc/sys/net/ipsec/debug_rcv

: ==== end ====

