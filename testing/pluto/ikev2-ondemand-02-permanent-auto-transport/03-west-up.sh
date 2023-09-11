# trap installed
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match west -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

# wait for larval state to clear; hack
../../guestbin/wait-for.sh --no-match 0x00000000 ../../guestbin/ipsec-kernel-state.sh

# real policy installed
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
