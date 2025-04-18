# bring up OE
../../guestbin/ping-once.sh --forget 2001:db8:1:2::23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up 2001:db8:1:2::23
ipsec whack --trafficstatus
# confirm we got transport mode, not tunnel mode
ipsec _kernel state | grep mode
echo done
