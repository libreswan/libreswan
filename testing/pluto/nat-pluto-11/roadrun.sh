# Should show "ESP" and not "ESP/NAT"
ipsec whack --name road-eastnet-nonat --initiate # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo done
