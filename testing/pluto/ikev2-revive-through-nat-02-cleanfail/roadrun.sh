ipsec auto --up road-eastnet-ikev2
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec traffic
ipsec auto --delete road-eastnet-ikev2
# give east time to re-trigger to us due to auto=keep
# we check in final to see if east cleaned up properly
sleep 20
echo done
