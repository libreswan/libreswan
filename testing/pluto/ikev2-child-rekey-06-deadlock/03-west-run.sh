ipsec auto --status | grep west
ipsec auto --up west
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec trafficstatus

# This rekey, #2->#3, should succeed
ipsec whack --rekey-child --name west

# This rekey, #3->#4, should fail.  The message is blocked by firewall
# rules added in 02-west-init.sh
ipsec whack --rekey-child --name west
