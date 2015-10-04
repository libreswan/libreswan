#!/bin/sh
/testing/guestbin/swan-prep --hostname east
killall -9 pluto  2>/dev/null
killall -9 pluto  2>/dev/null
rm -fr /tmp/east/pluto.pid
rm -fr /tmp/west/pluto.pid
# load netkey stack on host
ipsec _stackmanager --config /testing/pluto/ikev2-34-lxc/west.conf start
ipsec version |grep klips && echo you need netkey
# prep host for two pluto's
mkdir -p /tmp/west/ipsec.d /tmp/east/ipsec.d
echo hit return a few times for certutil
certutil -N -d sql:/tmp/west/ipsec.d
certutil -N -d sql:/tmp/east/ipsec.d
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
ip link set weth1 up
ip link set hweth1 up
ip link set weth1 up netns nswest
ip netns exec nswest ip addr add 192.1.2.45/24 dev weth1
#
ip link add hweth0 type veth peer name weth0
ip link set weth0 up
ip link set hweth0 up
ip link set weth0 up netns nswest
ip netns exec nswest ip addr add 192.0.1.254/24 dev weth1
ip netns exec nswest ip route add 192.0.2.0/24 via 192.1.2.23
#
ip link add heeth1 type veth peer name eeth1
ip link set eeth1 up
ip link set heeth1 up
ip link set eeth1 up netns nseast
ip netns exec nseast ip addr add 192.1.2.23/24 dev eeth1
#
ip link add heeth0 type veth peer name eeth0
ip link set eeth0 up
ip link set heeth0 up
ip link set eeth0 up netns nseast
ip netns exec nseast ip addr add 192.0.2.254/24 dev eeth0
ip netns exec nseast ip route add  192.0.1.0/24 via 192.1.2.45
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
ip netns exec nswest ipsec pluto --ctlbase /tmp/west/pluto --config /testing/pluto/ikev2-34-lxc/west.conf --secretsfile /testing/pluto/ikev2-34-lxc/west.secrets --ipsecdir /tmp/west/ipsec.d
ip netns exec nseast ipsec pluto --ctlbase /tmp/east/pluto --config /testing/pluto/ikev2-34-lxc/east.conf --secretsfile /testing/pluto/ikev2-34-lxc/east.secrets --ipsecdir /tmp/east/ipsec.d
#wait for pluto
sleep 8
ip netns exec nswest ipsec whack --ctlbase /tmp/east/pluto --listen
ip netns exec nswest ipsec whack --ctlbase /tmp/west/pluto --listen
ipsec addconn --ctlbase /tmp/west/pluto.ctl westnet-eastnet-ipv4-psk-ikev2 --config /testing/pluto/ikev2-34-lxc/west.conf
ipsec addconn --ctlbase /tmp/east/pluto.ctl westnet-eastnet-ipv4-psk-ikev2 --config /testing/pluto/ikev2-34-lxc/east.conf
ip netns exec nswest ipsec whack --ctlbase /tmp/west/pluto --initiate --name westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ipsec addconn --ctlbase /tmp/west/pluto.ctl  --config /testing/pluto/ikev2-34-lxc/west.conf westnet-eastnet-ipv4-psk-ikev2
ip netns exec nseast ipsec addconn --ctlbase /tmp/east/pluto.ctl --config /testing/pluto/ikev2-34-lxc/east.conf westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ipsec whack --ctlbase /tmp/east/pluto --status
ip netns exec nswest ipsec whack --ctlbase /tmp/west/pluto --status
ip netns exec nswest ipsec whack --ctlbase /tmp/west/pluto --initiate --name westnet-eastnet-ipv4-psk-ikev2
ip netns exec nswest ping -n -c 4 -I 192.0.1.254 192.0.2.254
ip netns exec nswest ipsec whack --ctlbase /tmp/west/pluto --trafficstatus
echo "initdone"
