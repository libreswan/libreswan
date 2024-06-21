ip link add dev ipsec1 type xfrm if_id 0x1
ip addr add 192.0.1.251/24 dev ipsec1
ip addr add 2001:db8:0:1::251/64 dev ipsec1
ipsec auto --up westnet4-eastnet4
ipsec auto --up westnet6-eastnet6
ipsec auto --down westnet4-eastnet4
ipsec auto --delete westnet4-eastnet4
ipsec auto --down westnet6-eastnet6
ipsec auto --delete westnet6-eastnet6
echo done
