# make this end think it is seeing retransmits
ipsec whack --impair suppress-retransmits
ipsec whack --impair replay-duplicates
ipsec auto --up  westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# check we didnt fail on retransmits from east
grep "unexpected message received in state" /tmp/pluto.log
echo done
