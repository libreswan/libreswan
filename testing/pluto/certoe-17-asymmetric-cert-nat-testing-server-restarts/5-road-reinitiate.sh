# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# trigger ping, this will be lost
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh '#4: initiator established Child SA using #3'
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
