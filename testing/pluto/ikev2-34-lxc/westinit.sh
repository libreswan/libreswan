#!/bin/sh
/testing/guestbin/swan-prep --hostname east
killall -9 pluto  2>/dev/null
killall -9 pluto  2>/dev/null
ip netns del nswest
ip netns del nseast
#
# load netkey stack on host
ipsec _stackmanager start
ipsec version |grep klips && echo you need netkey
mkdir -p  /var/run/netnspluto/nswest
mkdir -p  /var/run/netnspluto/nseast
mkdir -p  /var/run/pluto
rm -fr /var/run/netnspluto/nseast/*
rm -fr /var/run/netnspluto/nswest/*
mkdir /etc/netns/nseast/
rsync  -aPv ../../baseconfigs/east/etc/ipsec.d /etc/netns/nseast/
rsync  -aPv east.conf /etc/netns/nseast/ipsec.conf
rsync  -aPv east.secrets /etc/netns/nseast/ipsec.secrets
#
mkdir /etc/netns/nswest/
rsync  -aPv west.conf /etc/netns/nswest/ipsec.conf
rsync  -aPv west.secrets /etc/netns/nswest/ipsec.secrets
#
echo setting up namespaces for east and west with a single interface
#create name space  nswest and nseast
ip netns add nswest
ip netns exec nswest ip link set lo up
ip netns add nseast
ip netns exec nseast ip link set lo up
# create interface
# in the host hweth1
# in the guest weth1
ip link add hweth1 type veth peer name weth1
ip link set hweth1 up
ip link set weth1 netns nswest
ip netns exec nswest ip link set dev weth1 name eth1
ip netns exec nswest ip addr add 192.1.2.45/24 dev eth1
ip netns exec nswest ip link set eth1 up
#
ip link add hweth0 type veth peer name weth0
ip link set hweth0 up
ip link set weth0  netns nswest
ip netns exec nswest ip link set dev weth0 name eth0
ip netns exec nswest ip addr add 192.0.1.254/24 dev eth0
ip netns exec nswest ip route add 192.0.2.0/24 via 192.1.2.23
ip netns exec nswest ip link set eth1 up
#
ip link add heeth1 type veth peer name eeth1
ip link set heeth1 up
ip link set eeth1 netns nseast
ip netns exec nseast ip link set dev eeth1 name eth1
ip netns exec nseast ip addr add 192.1.2.23/24 dev eth1
ip netns exec nseast ip link set eth1 up

#
ip link add heeth0 type veth peer name eeth0
ip link set heeth0 up
ip link set eeth0 netns nseast
ip netns exec nseast ip link set dev eeth0 name eth0
ip netns exec nseast ip addr add 192.0.2.254/24 dev eth0
ip netns exec nseast ip link set eth0 up
ip netns exec nseast ip route add 192.0.1.0/24 via 192.1.2.45
#
# add interfaces to a bridge
brctl addbr br192_1_2
brctl addif br192_1_2 hweth1 heeth1
ip link set br192_1_2 up
ip addr add 192.1.2.11/24 dev br192_1_2
ip netns exec nseast ping -c 2 192.1.2.45
ip netns exec nseast ping -c 2 -I 192.0.2.254 192.0.1.254
#
#
#start pluto
ip netns exec nswest ipsec pluto --config /etc/ipsec.conf
ip netns exec nseast ipsec pluto --config /etc/ipsec.conf
#wait for pluto
sleep 8
ip netns exec nswest ipsec whack --listen
ip netns exec nswest ipsec whack --listen
ip netns exec nseast ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ipsec whack --initiate --name westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ipsec status
ip netns exec nseast ipsec status
ip netns exec nswest ping -n -c 4 -I 192.0.1.254 192.0.2.254
ip netns exec nswest ipsec whack --trafficstatus
echo "initdone"
