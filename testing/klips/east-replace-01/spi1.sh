#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x87658765876587658765876587658765

#ipsec klipsdebug --set pfkey

# make first SA.
ipsec spi --saref --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey --authkey $authkey
ipsec spi --saref --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4
ipsec spigrp inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp

# make second SA.
ipsec spi --saref --af inet --edst 192.1.2.44 --spi 0x23456789 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey --authkey $authkey
ipsec spi --saref --af inet --edst 192.1.2.44 --spi 0x23456789 --proto tun --src 192.1.2.23 --dst 192.1.2.44 --ip4
ipsec spigrp inet 192.1.2.44 0x23456789 tun inet 192.1.2.44 0x23456789 esp


ipsec eroute

ipsec eroute --add --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x12345678@192.1.2.45
: added
ipsec eroute

ipsec eroute --del --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x12345678@192.1.2.45
: removed
ipsec eroute

ipsec eroute --add --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x12345678@192.1.2.45
: added
ipsec eroute


ipsec eroute --replace --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x23456789@192.1.2.44
: replaced
ipsec eroute

ipsec eroute --del --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x12345678@192.1.2.44
: removed
ipsec eroute

ipsec eroute --replace --eraf inet --src 192.0.2.0/24 --dst 192.0.1.0/24 --said tun0x23456789@192.1.2.44
: replaced again
ipsec eroute

echo done
