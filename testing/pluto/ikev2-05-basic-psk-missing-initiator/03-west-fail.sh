# expected to fail - initiator's password is missing
ipsec up westnet-eastnet-ipv4-psk-ikev2
# expect block/trap (even when reviving)
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
echo done
