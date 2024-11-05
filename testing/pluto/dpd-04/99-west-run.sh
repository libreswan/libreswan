# wait for west-east
../../guestbin/wait-for.sh --match '"west-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# trigger westnet-east
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.1.2.23
../../guestbin/wait-for.sh --match '"westnet-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
# trigger west-eastnet
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.0.2.254
../../guestbin/wait-for.sh --match '"west-eastnet"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
# Tunnels should be back up now
ipsec whack --trafficstatus
echo done
