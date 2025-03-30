../../guestbin/prep.sh

../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth2 if_id 0x1
../../guestbin/ip.sh addr add 198.18.15.15/24 dev ipsec1
../../guestbin/ip.sh link set ipsec1 up

../../guestbin/ip.sh addr show ipsec1
../../guestbin/ip.sh link show ipsec1
ipsec _kernel policy

ip -4 route add 198.18.12.0/24 dev ipsec1
