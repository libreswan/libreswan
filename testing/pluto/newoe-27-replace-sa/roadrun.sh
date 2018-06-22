ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
killall -9 pluto
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# give OE time to establish
sleep 5
# test the new tunnel works properly
ping -n -c 3 -I 192.1.3.209 192.1.2.23
echo done
