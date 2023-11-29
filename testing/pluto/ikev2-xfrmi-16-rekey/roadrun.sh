ipsec up road
sleep 2
../../guestbin/tcpdump.sh --start -i ipsec1
# do not send a ping yet. It would confuse the tcpdump output
# ../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --rekey-ipsec --name road
# wait till the previous one is deleted
sleep 5
ipsec whack --rekey-ipsec --name road
sleep 5
ipsec add road
ipsec up road
echo done
