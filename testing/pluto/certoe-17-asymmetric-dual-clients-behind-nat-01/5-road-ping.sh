# check traffic and shunt status
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# trigger ping, this will be lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
# wait for tunnel then send ping; count changes
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
