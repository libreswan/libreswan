# setup authenticated static conn
ipsec auto --up authenticated
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --impair send-no-delete
ipsec auto --delete authenticated
sleep 5
# the ping triggers an OE authnull attempt. It should fail because
# east should not replace an authenticated conn with an authnull conn
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# There should NOT be an IPsec SA, and a partial OE attempt going?
sleep 5
ipsec status |grep STATE_
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
