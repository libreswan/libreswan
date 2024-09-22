#
# valid device; <<ip link>> then <<ipsec add>>
#

ipsec start
../../guestbin/wait-until-pluto-started

ip link add dev ipsec1 type xfrm dev eth1 if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6

ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1 # still there
ipsec stop
ip link del dev ipsec1 >/dev/null 2>&1 # bug, ipsec stop deletes it


#
# valid device; <<ipsec add>> then <<ip link>>
#

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip link add dev ipsec1 type xfrm dev eth1 if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6

ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1 # still there
ipsec stop
ip link del dev ipsec1 >/dev/null 2>&1 # bug, ipsec stop deletes it

echo done
