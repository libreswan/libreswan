ping -n -c 4 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec status | grep "STATE_" 
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
#
grep "STATE_" OUTPUT/road.console.verbose.txt
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
