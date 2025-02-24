# create a partial state on east, don't hold the hack for retransmit
ipsec auto --up west-east # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
echo done
