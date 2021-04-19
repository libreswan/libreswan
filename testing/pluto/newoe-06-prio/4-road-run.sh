ipsec auto --route road-east-ikev2
# hopefully trigger road-east-ikev2 - not the OE authnull conn
# The ping should also get a reply, proving the IPsec SA was
# preferred over the OE trap policy
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match road-east-ikev2 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
echo done
