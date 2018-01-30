ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec look
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
killall -9 pluto
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# a new tunnel should be established
echo done
