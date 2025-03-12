#
# Existing ipsec-interface with address
#
# Neither the ipsec-interface nor the address are created by pluto, so
# pluto leaves both behind.

ip link add dev ipsec1 type xfrm if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ip link del dev ipsec1


#
# Existing ipsec-interface with no address
#
# Pluto deletes the address it added, but leaves the pre-existing
# interface alone.

ip link add dev ipsec1 type xfrm if_id 0x1

ip --color=never link show ipsec1 # interface

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # missing addresses

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # missing addresses

ip link del dev ipsec1


#
# missing ipsec-interface, yet with addresses
#
# Pluto deletes the address it added, but leaves the pre-existing
# interface alone.

ip --color=never link show ipsec1 # missing interface

ipsec add westnet4-eastnet4
ipsec add westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # missing addresses

ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1

ipsec up westnet4-eastnet4
ipsec up westnet6-eastnet6

ip --color=never link show ipsec1 # interface
ip --color=never addr show ipsec1 # addresses

ipsec delete westnet4-eastnet4
ipsec delete westnet6-eastnet6

ip --color=never link show ipsec1 # missing interface

echo done
