/testing/guestbin/swan-prep --userland strongswan
ip addr add 192.0.100.254/24 dev eth0:1
ip route add 192.0.200.0/24 via 192.1.2.23  dev eth1
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 192.0.100.254 192.0.200.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -A INPUT -i eth1 -s 192.0.200.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 192.0.100.254 192.0.200.254
strongswan starter --debug-all
echo "initdone"
