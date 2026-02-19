# lost interface with no connection

# now loose the interface 192.1.2.0/24
ifconfig eth1 down
ipsec listen

# restore eth1
ifconfig eth1 192.1.2.45 up
ipsec listen

# bring up OE
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

# lost interface with OE connection

# now loose the interface 192.1.2.0/24
ifconfig eth1 down
ipsec listen

# restore eth1
ifconfig eth1 192.1.2.45 up
ipsec listen

# bring up OE
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.2.45 192.1.2.23
