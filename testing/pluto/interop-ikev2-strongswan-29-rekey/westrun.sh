# bring up the tunnel
strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "sleep 30 sec to ike to rekey "
sleep 30
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
