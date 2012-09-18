#!/bin/bash

# if using libvirt, you can use network-libvirt.sh instead

TESTING=`readlink -f $0  | sed "s/libvirt.*$/libvirt/"`
pushd $TESTING


for net in br-192_0_1 br-192_0_2 br-192_1_2 br-192_9_2 br-192_9_4
do
  ip tuntap add dev $net-nic mode tap
  ip link set dev $net-nic promisc on up
  echo 1 > /proc/sys/net/ipv4/conf/$net-nic/proxy_arp
  brctl addbr $net
  brctl addif $net $net-nic
  ip link set dev $net promisc on up
done
# west
ip tuntap add dev west_eth0 mode tap
brctl addif br-192_0_1 west_eth0
ip tuntap add dev west_eth1 mode tap
brctl addif br-192_1_2 west_eth1
ip tuntap add dev west_eth2 mode tap
brctl addif br-192_9_4 west_eth2

# east
ip tuntap add dev east_eth0 mode tap
brctl addif br-192_0_2 east_eth0
ip tuntap add dev east_eth1 mode tap
brctl addif br-192_1_2 east_eth1
ip tuntap add dev east_eth2 mode tap
brctl addif br-192_9_2 east_eth2

popd

