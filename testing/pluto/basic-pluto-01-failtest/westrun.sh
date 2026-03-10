ipsec up westnet-eastnet # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
# cause cleartext failure
ip xfrm policy flush
# should cause failures on east
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
echo done
