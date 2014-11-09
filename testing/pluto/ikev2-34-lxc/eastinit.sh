#!/bin/sh
/testing/guestbin/swan-prep
killall -9 pluto  2>/dev/null
killall -9 pluto  2>/dev/null
rm -fr /tmp/east/pluto.pid
rm -fr /tmp/west/pluto.pid
# load netkey stack on host
ipsec _stackmanager start
ipsec version |grep klips && echo you need netkey 
# prep host for two pluto's
mkdir -p /tmp/west/ipsec.d /tmp/east/ipsec.d
echo hit return a few times for certutil
certutil -N -d /tmp/west/ipsec.d
certutil -N -d /tmp/east/ipsec.d
echo setting up namespaces for east and west with a single interface
# create namespaces east and west
ip netns list
ip netns add west
ip netns add east
# add interface to west
ip link add virwest type veth peer name west
ip link set west netns west
# add interface to east
ip link add vireast type veth peer name east
ip link set east netns east
# bring interfaces up on the host
ifconfig virwest up
ifconfig vireast up
# add interfaces to a bridge
brctl addbr br192_1_2
brctl addif br192_1_2 virwest vireast
ip link set br192_1_2 up
ip addr add 192.1.2.11/24 dev br192_1_2
ping -c 2 192.1.2.45
ping -c 2 192.1.2.23
# configure guest network
ip netns exec west ifconfig west 192.1.2.45 netmask 255.255.255.0 up
ip netns exec east ifconfig east 192.1.2.23 netmask 255.255.255.0 up
ip netns exec  west ping -c 2 192.1.2.23
ip netns exec  east ping -c 2 192.1.2.45
ip netns exec west ipsec pluto --ctlbase /tmp/west/pluto --config /testing/pluto/ikev2-34-lxc/west.conf --secretsfile /testing/pluto/ikev2-34-lxc/west.secrets --ipsecdir /tmp/west/ipsec.d
ip netns exec east ipsec pluto --ctlbase /tmp/east/pluto --config /testing/pluto/ikev2-34-lxc/east.conf --secretsfile /testing/pluto/ikev2-34-lxc/east.secrets --ipsecdir /tmp/east/ipsec.d
ipsec addconn --ctlbase /tmp/west/pluto.ctl westnet-eastnet-ipv4-psk-ikev2 --config /testing/pluto/ikev2-34-lxc/west.conf
ipsec addconn --ctlbase /tmp/east/pluto.ctl westnet-eastnet-ipv4-psk-ikev2 --config /testing/pluto/ikev2-34-lxc/east.conf
ip netns exec west ipsec whack --ctlbase /tmp/west/pluto --initiate --name westnet-eastnet-ipv4-psk-ikev2
ip netns exec west ipsec addconn --ctlbase /tmp/west/pluto.ctl westnet-eastnet-ipv4-psk-ikev2
ip netns exec east ipsec addconn --ctlbase /tmp/east/pluto.ctl westnet-eastnet-ipv4-psk-ikev2
ip netns exec west ipsec whack --ctlbase /tmp/east/pluto --status
ip netns exec west ipsec whack --ctlbase /tmp/west/pluto --status
ip netns exec west ipsec whack --ctlbase /tmp/west/pluto --initiate --name westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
