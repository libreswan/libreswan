ipsec auto --up v6-tunnel-east-road
../../guestbin/ping-once.sh --up 2001:db8:1:2::23
ipsec whack --trafficstatus
echo done
