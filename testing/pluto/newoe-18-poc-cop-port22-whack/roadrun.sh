ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23 --oppoproto 6 --oppodport 22
# wait on OE retransmits and rekeying
sleep 5
# should show tunnel and no shunts, and zero traffic count
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# generate some traffic to be encrypted
echo TRIGGER-OE | nc -s 192.1.3.209 192.1.2.23 22
sleep 1
# show non-zero counters
ipsec whack --trafficstatus
echo done
