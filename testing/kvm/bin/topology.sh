#!/bin/bash

# This script defines a bunch of shell variables that describe
# libreswan's test network.  It's a feable attempt at eliminating the
# test network values scattered across various scripts.

hosts=$(basename -s .xml $(dirname ${BASH_SOURCE[0]})/../vm/*.xml) # includes nic
echo hosts=${hosts} 1>&2

# same platforms as KVM
platforms=$(basename -s .sh $(dirname ${BASH_SOURCE[0]})/../upgrade/[a-z]*.sh)
echo platforms=${platforms} 1>&2

# PREFIXES

net4=198.18
net6=2001:db8

# NETWORKS

# public network, name is arbitrary

internet=2
internet4=192.1.2		# ${net4}.2
internet6=${net6}:1:2		# ${net6}:2

# NIC's private network - gets NATed

nicnet=3
nicnet4=192.1.3			# ${net4}.3.
nicnet6=${net6}:1:3		# ${net6}:3

# EAST's private network

eastnet=20
eastnet4=192.0.2		# ${net4}.20
eastnet6=${net6}:0:2		# ${net6}:20

# WEST's private network

westnet=40
westnet4=192.0.1		# ${net4}.40
westnet6=${net6}:0:1		# ${net6}:40

# NORTH's private network

nortnet=66
northnet4=192.0.3		# ${net4}.66
northnet6=${net6}:0:3		# ${net6}:66

# BEHIND RISE-SET

darknet=1
darknet4=${net4}.${darknet}
darknet6=${net6}:${darknet}

# HOSTs

pole_eth0=(northnet 90)

north_eth0=(northnet 254)
north_eth1=(nicnet 33)

road_eth0=(nicnet 209)

nic_eth0=(nicnet 254)
nic_eth1=(internet 254)

east_eth1=(internet 23)
east_eth0=(eastnet 254)

west_eth1=(internet 45)
west_eth0=(westnet 254)

set_eth1=(westnet 15)
set_eth0=(darknet 15)

rise_eth1=(eastnet 12)
rise_eth0=(darknet 12)

# define
#
#   ${network}[45]=PREFIX
#   ${host}_${network}[46]=ADDRESS

for v in 4 6 ; do
    case $v in
	4 ) s=. ;;
	6 ) s=:: ;;
    esac
    for eth in eth0 eth1 ; do
	for host in poll north road nic east west rise set ; do
	    net=$(eval echo \${${host}_${eth}[0]})
	    ip=$(eval echo \${${host}_${eth}[1]})
	    netv=$(eval echo \${${net}${v}})
	    if test -n "${net}" ; then
		host_net=${host}_${net}${v}
		eval "${host_net}=${netv}${s}${ip}"
		eval echo "${host_net}=\${${host_net}}" 1>&2
	    fi
	done
    done
done
