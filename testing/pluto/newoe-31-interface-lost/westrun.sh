# bring up OE
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

# take it down
ipsec down '"private-or-clear#192.1.2.0/24"'

# now loose the interface 192.1.2.0/24; this should cause that OE
# connection to be deleted.
ifconfig eth1 down
ipsec listen

# restore eth1
ifconfig eth1 192.1.2.45 up
ipsec listen
