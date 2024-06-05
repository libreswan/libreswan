#!/bin/sh
# arg is namespace number
i=$1
num="$i"
name="space$i"
vhost="veth$i"

# host config
ip netns add $name
ip link add $vhost type veth peer name br-$vhost
# ip addr add 192.168.$num.254/24 dev $vhost
ip link set $vhost netns $name
sysctl -w net.ipv4.conf.br-$vhost.rp_filter=0
sysctl -w net.ipv4.conf.br-$vhost.forwarding=1
sysctl -w net.ipv4.conf.br-$vhost.proxy_arp=1
echo waiting on bridge to settle
sleep 1
ip link set br-$vhost up
ip link set br-$vhost master brrw

# guest config
ip netns exec $name ip addr add 192.168.0.$num/24 dev $vhost
ip netns exec $name ip addr add 127.0.0.1/8 dev lo
ip netns exec $name ip link set dev lo up
ip netns exec $name ip link set dev $vhost up
ip netns exec $name ../../guestbin/ip.sh route add 0.0.0.0/0 via 192.168.0.254
ip netns exec $name sysctl -w net.ipv4.conf.$vhost.rp_filter=0
ip netns exec $name sysctl -w net.ipv4.conf.all.rp_filter=0

# /tmp is still from host
mkdir /tmp/nss$num; ipsec initnss --nssdir /tmp/nss$num
pk12util -i /testing/x509/pkcs12/mainca/user$num.p12 -W foobar -d sql:/tmp/nss$num/
ip netns exec $name ipsec pluto --logfile /tmp/pluto$num.log --rundir /tmp/run$num --nssdir /tmp/nss$num --debug-all
ip netns exec $name ipsec whack --rundir /tmp/run$num --name user$num  --encrypt --pfs --no-esn --tunnel --host 192.168.0.$num --id @user$num.testing.libreswan.org  --rsasig --ikev2-allow --cert user$num  --sendcert always --allow-narrowing --modecfgclient --to --host 192.1.2.23 --client 192.0.2.0/24
