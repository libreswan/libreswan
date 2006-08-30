#!/bin/sh

: ==== start ====

TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

: ==== end ====
