# setup static conn
ipsec auto --up authenticated
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
# there should be no partial or established states, and a fail shunt
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
