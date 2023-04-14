# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match west -- ipsec trafficstatus

../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh

../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
ipsec trafficstatus

ipsec auto --down west
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh

