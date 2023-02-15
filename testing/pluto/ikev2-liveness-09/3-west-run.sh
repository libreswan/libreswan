#!/bin/sh
ipsec auto --up westnet-eastnet-ikev2
# Tunnel should be up
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 15
# Setting up block
ip route add unreachable 192.1.2.23
../../guestbin/ping-once.sh --error 192.1.2.23
# wait for liveness/dpd to trigger: tunnel should be down with %trap
# or %hold preventing packet leaks But shuntstatus only shows bare
# shunts, not connection shunts :(
../../guestbin/wait-for.sh --timeout 90 --no-match '.' -- ipsec trafficstatus
conntrack -L -n
conntrack -F
ipsec whack --shuntstatus
ipsec status | grep westnet-eastnet-ikev2
# ping should be caught ip route unreachable
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
# Remove the null route; things should recover without a trigger
ip route del unreachable 192.1.2.23
../../guestbin/wait-until-alive 192.1.2.23
../../guestbin/wait-for.sh --match ':' -- ipsec trafficstatus
# Tunnel should be back up now even without triggering traffic
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec shuntstatus
grep -E "^[^|].*(liveness action|acquire|on-demand)" OUTPUT/west.pluto.log
echo done
