ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus 
sleep 60
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
