# one ping will get lost in the ondemand as only TCP is cached
../../guestbin/ping-once.sh --forget -I 2001:db8:1:2::45 2001:db8:1:2::23
../../guestbin/wait-for.sh --match v6-transport -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
echo done
