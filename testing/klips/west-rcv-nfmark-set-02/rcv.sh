#!/bin/sh

: ==== start ====

TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey1=0x4043434545464649494a4a4c4c4f4f515152525454575758
enckey2=0x5464649494a4a4c4c4f4f515152525454575758404343454
authkey1=0x87658765876587658765876587658765
authkey2=0x65876587658765876587658765876587

: set up SPI 1
sa1=`ipsec spi --af inet --edst 192.1.2.45 --spi 0x88447755 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey1 --authkey $authkey1 --saref | cut -d '=' -f2`
echo SA1 $sa1

sa2=`ipsec spi --af inet --edst 192.1.2.45 --spi 0x88447755 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4 --saref | cut -d '=' -f2`
echo SA2 $sa2

ipsec spigrp inet 192.1.2.45 0x88447755 tun inet 192.1.2.45 0x88447755 esp 


: set up SPI 2
sa3=`ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey2 --authkey $authkey2 --saref | cut -d '=' -f2`
echo SA3 $sa3

sa4=`ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto tun --src 192.1.2.23 --dst 192.1.2.45 --ip4 --saref | cut -d '=' -f2`
echo SA4 $sa4

ipsec spigrp inet 192.1.2.45 0x12345678 tun inet 192.1.2.45 0x12345678 esp 

ipsec look

sa1=$(printf "0x%08x" $(expr $sa1 '*' 65536))
sa2=$(printf "0x%08x" $(expr $sa2 '*' 65536))
sa3=$(printf "0x%08x" $(expr $sa3 '*' 65536))
sa4=$(printf "0x%08x" $(expr $sa4 '*' 65536))

echo SA1 $sa1
echo SA2 $sa2
echo SA3 $sa3
echo SA4 $sa4

: now setup of the nfmark based switching

mkdir -p /etc/iproute2

echo '11  sa1' >>/etc/iproute2/rt_tables
echo '12  sa2' >>/etc/iproute2/rt_tables
echo '13  sa3' >>/etc/iproute2/rt_tables
echo '14  sa4' >>/etc/iproute2/rt_tables

ip rule add fwmark $sa2 table sa2
ip route add default via 192.1.2.254 dev eth1 table sa2

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet 192.1.2.45 netmask 0xffffff00 broadcast 192.1.2.255 up

# stuff the ARP table for the destinations involved
arp -s 192.1.2.23 10:00:00:64:64:23
arp -s 192.1.2.254 10:00:00:64:64:fe
arp -s 192.0.1.1  10:00:00:32:32:01
arp -s 192.9.2.254 10:00:00:99:99:fe

: ==== end ====


