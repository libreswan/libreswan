# trap installed
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match west -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

# real policy installed
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
