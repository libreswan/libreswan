ipsec auto --up road-eastnet-ikev2
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec traffic
ipsec auto --down road-eastnet-ikev2
# give east time to re-trigger to us due to auto=keep
sleep 3
ipsec status |grep STATE_
ipsec traffic
echo done
