ipsec whack --debug-all
ipsec auto --up road-east-psk
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
echo done
