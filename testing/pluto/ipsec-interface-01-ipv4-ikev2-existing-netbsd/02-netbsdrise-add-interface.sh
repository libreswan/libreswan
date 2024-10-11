../../guestbin/prep.sh

ifconfig ipsec1 create
ifconfig ipsec1 -link2
ifconfig ipsec1 inet tunnel 198.18.1.12 198.18.1.15
ifconfig ipsec1 inet 198.18.12.12/24 198.18.15.15

ifconfig ipsec1
../../guestbin/ipsec-kernel-policy.sh
