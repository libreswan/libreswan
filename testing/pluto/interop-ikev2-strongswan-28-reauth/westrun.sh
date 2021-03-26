strongswan up westnet-eastnet-ikev2
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "sleep 80 sec to ike to rekey "
sleep 50
sleep 30
echo done
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
