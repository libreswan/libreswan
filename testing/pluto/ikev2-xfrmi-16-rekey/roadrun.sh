ipsec auto --up road
sleep 2
../../guestbin/tcpdump.sh --start -i ipsec1
ipsec whack --rekey-ipsec --name road
# wait till the previous one is deleted
sleep 5
ipsec whack --rekey-ipsec --name road
sleep 5
ipsec auto --add road
ipsec auto --up road
echo done
