# setup authenticated static conn
# should established tunnel and no bare shunts
# ping should succeed through tunnel
ipsec auto --up authenticated
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# now delete the authenticated sa
ipsec whack --impair send-no-delete
ipsec auto --delete authenticated

# the ping triggers an OE authnull attempt. It should fail because
# east should not replace an authenticated conn with an authnull conn
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match '^".*#3: IKE SA authentication request rejected by peer' -- cat /tmp/pluto.log
# There should NOT be an IPsec SA, and a partial OE attempt going?
ipsec showstates
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
