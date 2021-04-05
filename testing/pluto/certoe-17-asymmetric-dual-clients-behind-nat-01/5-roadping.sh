# check traffic and shunt status
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
# trigger ping, this will be lost
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# sending pings
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
