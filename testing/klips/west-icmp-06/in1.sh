#!/bin/sh

enckey=0xaaaabbbbccccdddd4043434545464649
authkey=0x8765876587658765876587658765876587658765

ipsec spi --af inet --edst 205.150.200.180 --spi 0xed123456 --proto esp --src 205.150.200.246 --esp aes128-sha1-96 --enckey $enckey --authkey $authkey

ipsec spi --af inet --edst 205.150.200.180 --spi 0xed123456 --proto tun --src 205.150.200.246 --dst 205.150.200.180 --ip4

ipsec spigrp inet 205.150.200.180 0xed123456 tun inet 205.150.200.180 0xed123456 esp 

