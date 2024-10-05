../../guestbin/prep.sh

../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 1
../../guestbin/ip.sh addr add 192.0.45.1/24 dev ipsec1
../../guestbin/ip.sh link set ipsec1 up

../../guestbin/ip.sh addr show ipsec1
../../guestbin/ip.sh link show ipsec1
../../guestbin/ipsec-kernel-policy.sh

ip -4 route add 192.0.23.0/24 dev ipsec1
