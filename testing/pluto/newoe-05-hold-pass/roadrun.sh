ping -n -c 4 -I 192.1.3.209 192.1.2.23
ping -n -c 2 -I 192.1.3.209 7.7.7.7
# wait on OE retransmits and rekeying - shuntstatus is empty because shunt not bare
sleep 3
ipsec whack --shuntstatus
ipsec whack --trafficstatus
# 7.7.7.7 shunt is not bare and its conn negotiationshunt=hold, so ping should fail
ping -n -c 2 -I 192.1.3.209 7.7.7.7
# letting acquire time out
sleep 60
../../pluto/bin/ipsec-look.sh
# conn timed out, shunt is now failureshunt=pass and should show up, ping will work
ipsec whack --shuntstatus
ping -n -c 2 -I 192.1.3.209 7.7.7.7
# let failureshunt expire - both from bare shunt list as as kernel policy
sleep 60
../../pluto/bin/ipsec-look.sh
ipsec whack --shuntstatus
sleep 60
../../pluto/bin/ipsec-look.sh
ipsec whack --shuntstatus
sleep 60
../../pluto/bin/ipsec-look.sh
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done
