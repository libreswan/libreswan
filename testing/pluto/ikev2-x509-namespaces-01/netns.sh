#!/bin/sh
# arg is namespace number
i=$1
num="$i"
name="space$i"
vhost="host$i"
vguest="guest$i"

#host config
ip netns add $name
ip link add $vhost type veth peer name $vguest
ip addr add 192.168.$num.254/24 dev $vhost
ip link set $vhost up
ip link set $vguest netns $name
sysctl -w net.ipv4.conf.$vhost.rp_filter=0
sysctl -w net.ipv4.conf.$vhost.forwarding=1
sysctl -w net.ipv4.conf.$vhost.proxy_arp=1

###brctl addif rw $vhost
# guest config
ip netns exec $name ip addr add 192.168.$num.1/24 dev $vguest
ip netns exec $name ip addr add 127.0.0.1/8 dev lo
ip netns exec $name ip link set dev lo up
ip netns exec $name ip link set dev $vguest up
ip netns exec $name ip route add 0.0.0.0 via 192.168.$num.254
# just in case :/
ip netns exec $name sysctl -p
ip netns exec $name sysctl -w net.ipv4.conf.$vguest.rp_filter=0
ip netns exec $name sysctl -w net.ipv4.conf.all.rp_filter=0

# some testing inside the namespace
ip netns exec $name ip addr
ip netns exec $name ip route
ip netns exec $name arping -c2 192.168.$num.254
ip netns exec $name ping -c2 192.168.$num.254
# why does this fail?
ip netns exec $name ping -c2 192.1.3.209


exit
# /tmp is still from host
mkdir /tmp/nss$num; ipsec initnss --nssdir /tmp/nss$num
pk12util -i /testing/x509/pkcs12/mainca/user$num.p12 -W foobar -d sql:/tmp/nss$num/
ip netns exec $name ipsec pluto --logfile /tmp/pluto$num.log --listen 192.168.66.254.$num --rundir /tmp/run$num --nssdir /tmp/nss$num
ip netns exec $name ipsec whack --rundir /tmp/run$num --name user$num  --encrypt --tunnelipv4 --host 192.1.3.$num --id @user$num.testing.libreswan.org  --rsasig --ikev2-allow --cert user$num  --sendcert always --allow-narrowing --modecfgclient --to --host 192.1.2.23 
