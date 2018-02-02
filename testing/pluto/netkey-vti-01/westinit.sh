/testing/guestbin/swan-prep
# We want to test without a specific existing non-device route,
# so we remove the regular route for 192.0.2.0/24, and add default route 
ip route del 192.0.2.0/24
ip route del default
ip route add 0.0.0.0/0 via 192.1.2.23 dev eth1
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-vti
echo "initdone"
