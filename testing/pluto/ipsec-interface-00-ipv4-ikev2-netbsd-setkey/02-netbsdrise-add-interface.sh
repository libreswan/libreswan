../../guestbin/prep.sh

ifconfig ipsec1 create
ifconfig ipsec1 -link2
ifconfig ipsec1 inet tunnel 198.18.1.123 198.18.1.145
ifconfig ipsec1 inet 198.18.123.123/24 198.18.145.145

ifconfig ipsec1
../../guestbin/ipsec-kernel-policy.sh
