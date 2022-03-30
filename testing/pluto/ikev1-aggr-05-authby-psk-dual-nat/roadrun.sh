# bring up server behind NAT "road"
ipsec auto --add road-east
ipsec auto --up road-east
# sleep 3
ipsec trafficstatus
# emulate bringing up second server behind same NAT "runner"
ipsec whack --impair send-no-delete
ipsec auto --delete road-east
ipsec auto --add runner-east
ipsec auto --up runner-east
echo done
