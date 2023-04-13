ipsec auto --ondemand westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
sleep 3
# No states should show.
# The larval state should have been replaced with esp state, which got deleted.
ip xfrm state
ip xfrm policy
echo done
