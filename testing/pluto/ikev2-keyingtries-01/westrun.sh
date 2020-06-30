ipsec whack --impair ke-payload:omit
ipsec whack --impair revival
# keyingtries=1, 3s
ipsec auto --up westnet-eastnet-k1
sleep 5
ipsec auto --delete westnet-eastnet-k1
# keyingtries=3, 9s
ipsec auto --up westnet-eastnet-k3
sleep 15
ipsec auto --delete westnet-eastnet-k3
# keyingtries=0 (default, forever)
ipsec auto --up westnet-eastnet
# give whack released connection some time to do a few keyingtries
sleep 30
ipsec stop
# head -37 is magic to make logging more predictable
grep "keying attempt" OUTPUT/west.pluto.log | head -37
echo done
