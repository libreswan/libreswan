strongswan up westnet-eastnet-ikev2
strongswan up westnet-eastnet2-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
strongswan down "westnet-eastnet-ikev2{1}"
sleep 1
strongswan down "westnet-eastnet2-ikev2{2}"
sleep 3
echo done
