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

# BETWEEN SET-RISE

darknet=1
darknet4=${net4}.${darknet}
darknet6=${net6}:${darknet}

# HOSTs

# 12:P:O:L:E:0n
pole_eth=("eth0 northnet 90 12:50:4F:4C:45:01")

north_eth=("eth0 northnet 254 12:00:00:de:cd:49"
	   "eth1 nicnet    33 12:00:00:96:96:49")

road_eth=("eth0 nicnet 209 12:00:00:AB:CD:02")

nic_eth=("eth1 internet 254 12:00:00:de:ad:ba"
	 "eth2 nicnet 254 12:00:00:32:64:ba")

east_eth=("eth1 internet 23 12:00:00:64:64:23"
	  "eth2 eastnet 254 12:00:00:dc:bc:ff")

west_eth=("eth0 westnet 254 12:00:00:ab:cd:ff"
	  "eth1 internet 45 12:00:00:64:64:45")

# 12:00:S:E:T:0n
set_eth=("eth0 darknet 15 12:00:53:45:54:02"
	 "eth1 westnet 15 12:00:53:45:54:01")

# 12:R:I:S:E:0n
rise_eth=("eth0 darknet 12 12:52:49:53:45:02"
	  "eth1 eastnet 12 12:52:49:53:45:01")

# define
#
#   ${network}[45]=PREFIX
#   ${host}_${network}[46]=ADDRESS

for host in ${hosts} ; do
    declare -n host_eth=${host}_eth
    # echo ${host}: "${host_eth[@]}"
    for iface in "${host_eth[@]}" ; do
	declare -a if=(${iface})
	eth=${if[0]}
	net=${if[1]}
	ip=${if[2]}
	phy=${if[3]}
	for netv in ${net}4 ${net}6 ; do
	    case $netv in
		*4 ) s=. ;;
		*6 ) s=:: ;;
	    esac
	    declare -n netip=${netv}
	    host_net=${host}_${netv}
	    eval "${host_net}=${netip}${s}${ip}"
	    eval echo "${host_net}=\${${host_net}}" 1>&2
	done
    done
done
