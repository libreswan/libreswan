../../guestbin/prep.sh

ifconfig sec1 create
ifconfig sec1 inet 192.0.23.1/24 192.0.45.1
ifconfig sec1 up

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
