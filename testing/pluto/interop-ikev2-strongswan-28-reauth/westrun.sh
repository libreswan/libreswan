strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "sleep 90 sec to ike to rekey "
sleep 50
sleep 40
echo done
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
