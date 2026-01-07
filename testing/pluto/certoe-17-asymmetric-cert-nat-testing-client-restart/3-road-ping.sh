# check traffic and shunt status
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# trigger ping, this will be lost
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match '#2' -- ipsec whack --trafficstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo "waiting for road to restart client cleanly"
