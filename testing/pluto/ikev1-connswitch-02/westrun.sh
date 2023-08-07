ipsec auto --up westnet-eastnet-ikev1
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
echo done
