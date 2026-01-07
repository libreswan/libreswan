../../guestbin/prep.sh

ifconfig sec1 create
ifconfig sec1 inet 198.18.45.45/24 198.18.23.23
ifconfig sec1 up

ifconfig sec1
ipsec _kernel state
ipsec _kernel policy
