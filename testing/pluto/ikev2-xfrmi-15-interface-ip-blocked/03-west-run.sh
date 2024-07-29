#
# valid device; <<ipsec add>> is before <<ip link>>
#

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip link add dev ipsec1 type xfrm dev eth1 if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6
ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1
ip link del dev ipsec1
ip --color=never link show ipsec1

#
# invalid device; <<ipsec add>> is before <<ip link>>
#

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip link add dev ipsec1 type xfrm if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6
ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1
ip link del dev ipsec1
ip --color=never link show ipsec1
