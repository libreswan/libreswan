: ==== start ====
#!/bin/sh
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x87658765876587658765876587658765
saref=4562
nfsaref=$(printf "%d" $(( ($saref * 65536) | 0x80000000 )))

# set up the SA itself -- transport mode.
ipsec spi --af inet --edst 192.1.2.45 --spi 0x1bbdd678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey --authkey $authkey  --saref $saref

# we do *NOT* need to setup an EROUTE, because mast0 accepts packets based
# the SAref# and encrypt them appropriately.
ifconfig mast0 inet 192.1.2.23 netmask 255.255.255.255 mtu 1460 up

arp -s 192.1.2.45  10:00:00:64:64:45
arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look

# now arrange for some stuff to go to mast0

ip rule add fwmark 0x80000000/0x80000000 table 51
ip route add 0.0.0.0/0 dev mast0 table 51

iptables -I OUTPUT 1 -o eth1 -t mangle -p udp --src 192.1.2.23/32 --dst 192.1.2.45/32 --dport 9 -j MARK --set-mark $nfsaref

