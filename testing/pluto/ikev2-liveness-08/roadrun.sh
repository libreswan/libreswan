ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.1.2.23
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.1.2.23
ipsec whack --trafficstatus
echo "initdone"
