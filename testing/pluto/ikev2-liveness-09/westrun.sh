#!/bin/sh
ipsec auto --up westnet-eastnet-ikev2
ping -q -n -c 4 -I 192.0.1.254 192.0.2.254
# Tunnel should be up
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 15
# Setting up block
ip route add unreachable 192.1.2.23
../../pluto/bin/wait-until-alive 192.1.2.23
sleep 45
# livness/dpd should have triggered now
# Tunnel should be down with %trap or %hold preventing packet leaks
# But shuntstatus only shows bare shunts, not connection shunts :(
conntrack -L -n
conntrack -F
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec status | grep westnet-eastnet-ikev2
# ping should be caught ip route unreachable
ping -w 2 -q -n -c 3 -I 192.0.1.254 192.0.2.254
# Remove the null route
ip route del unreachable 192.1.2.23
../../pluto/bin/wait-until-alive 192.1.2.23
ping -q -n -c 1 -I 192.0.1.254 192.0.2.254
sleep 2
# ping should reply
ping -q -n -c 4 -I 192.0.1.254 192.0.2.254
# Tunnel should be back up now even without triggering traffic
ipsec whack --trafficstatus
ipsec whack --shuntstatus
grep -E "liveness action|acquire" OUTPUT/west.pluto.log
grep -E "liveness: action|acquire" OUTPUT/west.pluto.log
echo done
