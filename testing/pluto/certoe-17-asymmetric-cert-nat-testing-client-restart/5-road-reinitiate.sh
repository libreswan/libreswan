# trigger ping, this will be lost
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
