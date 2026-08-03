strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "sleep 20+10 so IKE re-authenticates"
sleep 30
echo done
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
