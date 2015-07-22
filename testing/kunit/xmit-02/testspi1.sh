#!/bin/sh
TZ=GMT export TZ

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x87658765876587658765876587658765

ipsec spi --del --af inet --edst 205.150.200.252 --spi 0x12345678 --proto esp
ipsec spi --del --af inet --edst 205.150.200.252 --spi 0x12345678 --proto tun

ipsec spi --af inet --edst 205.150.200.252 --spi 0x12345678 --proto esp --src 205.150.200.232 --esp 3des-md5-96 --enckey $enckey --authkey $authkey

ipsec spi --af inet --edst 205.150.200.252 --spi 0x12345678 --proto tun --src 205.150.200.232 --dst 205.150.200.252 --ip4

ipsec spigrp inet 205.150.200.252 0x12345678 tun inet 205.150.200.252 0x12345678 esp

ipsec eroute --del --eraf inet --src 205.150.200.163/32 --dst 205.150.200.252/32
ipsec eroute --add --eraf inet --src 205.150.200.163/32 --dst 205.150.200.252/32 --said tun0x12345678@205.150.200.252

# magic route command
ip route add 205.150.200.252 via 205.150.200.238 src 205.150.200.163 dev ipsec0


