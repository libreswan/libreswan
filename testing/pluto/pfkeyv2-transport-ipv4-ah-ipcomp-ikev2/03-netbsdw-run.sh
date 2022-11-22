ipsec auto --up eastnet-westnet-ikev2
../../guestbin/kernel-policy.sh
../../guestbin/ping-once.sh --up 192.1.2.23
../../guestbin/kernel-state.sh
../../guestbin/ping-once.sh --medium --up 192.1.2.23
../../guestbin/kernel-state.sh
dmesg | grep ipsec
