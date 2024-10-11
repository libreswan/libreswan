../../guestbin/prep.sh

ifconfig sec1 create
ifconfig sec1 inet 198.18.145.145/24 198.18.123.123
ifconfig sec1 up

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
