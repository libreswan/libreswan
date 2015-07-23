#!/bin/sh

enckey=0xaaaabbbbccccdddd4043434545464649
authkey=0x8765876587658765876587658765876587658765

ipsec spi --af inet --edst 205.150.200.180 --spi 0xED123456 --proto esp --src 205.150.200.246 --esp aes128-sha1-96 --enckey $enckey --authkey $authkey
ipsec spi --af inet --edst 192.1.2.45 --spi 0xED123456 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4
ipsec spi --af inet --edst 205.150.200.180 --spi 0xED123456 --proto tun --src 205.150.200.246 --dst 205.150.200.180 --ip4
ipsec spigrp inet 205.150.200.180 0xED123456 tun inet 205.150.200.180 0xED123456 esp
ipsec eroute --add --eraf inet --src 205.150.200.246/32 --dst 205.150.200.180/32 --said tun0xED123456@205.150.200.180

