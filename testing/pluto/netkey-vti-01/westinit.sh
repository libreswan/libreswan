/testing/guestbin/swan-prep
# We want to test without a specific existing non-device route,
# so we remove the regular route for 192.0.2.0/24, and add default route 
../../guestbin/route.sh del 192.0.2.0/24
../../guestbin/route.sh del default
../../guestbin/route.sh add 0.0.0.0/0 via 192.1.2.23 dev eth1
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-vti
echo "initdone"
