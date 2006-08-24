#!/bin/sh
: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

ipsec klipsdebug --set pfkey
ipsec klipsdebug --set xform

ROOT= export ROOT

: allocate, and delete
ipsec spi --saref --af inet --edst 30.122.14.231 --spi 0x3989876 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 30.122.14.231 --spi 0x3989876 --proto esp --del

: allocate a second and third, and delete second
ipsec spi --saref --af inet --edst 250.128.167.40 --spi 0x7078247 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 76.30.241.132 --spi 0x2578363 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 250.128.167.40 --spi 0x7078247 --proto esp --del

: allocate a fourth, and delete second
ipsec spi --saref --af inet --edst 117.30.250.38 --spi 0x3147647 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 76.30.241.132 --spi 0x2578363 --proto esp --del

: allocate a bunch.
ipsec spi --saref --af inet --edst 16.125.20.100 --spi 0x5871399 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 244.130.69.6 --spi 0x12063530 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 221.166.143.219 --spi 0x9083808 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 156.96.102.246 --spi 0x928066 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 190.3.105.114 --spi 0x3624918 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 137.41.189.19 --spi 0x15420208 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 149.255.75.187 --spi 0x1754290 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 32.97.52.61 --spi 0x5686174 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765
ipsec spi --saref --af inet --edst 69.42.155.116 --spi 0x12595525 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey 0x4043434545464649494a4a4c4c4f4f515152525454575758 --authkey 0x87658765876587658765876587658765

: delete one in the middle
ipsec spi --saref --af inet --edst 149.255.75.187 --spi 0x1754290 --proto esp --del

