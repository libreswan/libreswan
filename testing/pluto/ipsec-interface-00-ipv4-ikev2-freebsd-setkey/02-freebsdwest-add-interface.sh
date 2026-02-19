../../guestbin/prep.sh

ifconfig ipsec1 create reqid 100
ifconfig ipsec1 inet tunnel 192.1.2.45 192.1.2.23
ifconfig ipsec1 inet 198.18.45.45/24 198.18.23.23

ifconfig ipsec1
ipsec _kernel state
ipsec _kernel policy
