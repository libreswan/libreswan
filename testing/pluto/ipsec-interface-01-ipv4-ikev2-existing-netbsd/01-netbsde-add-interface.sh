../../guestbin/prep.sh

ifconfig ipsec1 create
ifconfig ipsec1 -link2
ifconfig ipsec1 inet tunnel 192.1.2.23 192.1.2.45
ifconfig ipsec1 inet 192.0.23.1/24 192.0.45.1

ifconfig ipsec1
../../guestbin/ipsec-kernel-policy.sh
