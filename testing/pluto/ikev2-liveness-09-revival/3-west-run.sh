#!/bin/sh
ipsec up westnet-eastnet-ikev2

# Tunnel should be up
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# Let R_U_THERE packets flow
sleep 15

# Setting up block; because the tunnel is up the ping doesn't trigger
# a trap
../../guestbin/ip.sh route add unreachable 192.1.2.23
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ping-once.sh --error 192.1.2.23

# wait for liveness/dpd to trigger: tunnel should be down with a %trap
# preventing packet leaks
../../guestbin/wait-for.sh --timeout 90 --no-match westnet-eastnet-ikev2 -- ipsec trafficstatus
conntrack -L -n
conntrack -F
ipsec shuntstatus
ipsec connectionstatus westnet-eastnet-ikev2
../../guestbin/ipsec-kernel-policy.sh

# now let the revival kick in; the trap should be replaced by a %hold(block)
ipsec whack --async --impair trigger_revival:1
ipsec connectionstatus westnet-eastnet-ikev2
../../guestbin/ipsec-kernel-policy.sh

# Remove the null route; things should recover (after a few
# retransmits) without a trigger
../../guestbin/ip.sh route del unreachable 192.1.2.23
../../guestbin/wait-for.sh --timeout 90 --match westnet-eastnet-ikev2 -- ipsec trafficstatus

# Tunnel should be back up now even without triggering traffic
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec shuntstatus

# now acquire expected as recovery done by revival
grep -E "^[^|].*(liveness action|acquire|on-demand)" OUTPUT/west.pluto.log

echo done
