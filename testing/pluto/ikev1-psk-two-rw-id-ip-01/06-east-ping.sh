# on east this should show 2 sets of in/fwd/out policies
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# check both connections still work on east
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up 192.0.2.101
# so counts do not match
../../guestbin/ping-once.sh --up 192.0.2.102
../../guestbin/ping-once.sh --up 192.0.2.102
ipsec whack --trafficstatus
