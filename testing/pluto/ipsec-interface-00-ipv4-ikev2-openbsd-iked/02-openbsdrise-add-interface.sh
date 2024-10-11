../../guestbin/prep.sh

ifconfig sec1 create
ifconfig sec1 inet 198.18.12.12/24 198.18.15.15
ifconfig sec1 up

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
