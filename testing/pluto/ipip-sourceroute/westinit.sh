/testing/guestbin/swan-prep

/sbin/ip tunnel add ip.tun mode ipip remote 192.1.2.23 local 192.1.2.45
/sbin/ifconfig ip.tun 2.2.2.3 pointopoint 1.1.1.3 netmask 0xffffffff
/sbin/ip link set ip.tun up

# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
ping -n -c 4 -I 2.2.2.3 1.1.1.3
# make sure that clear text does not get through
#iptables -A INPUT -i eth1 -s 192.1.2.23/32 -j LOGDROP #eth1?
#iptables -A INPUT -i ip.tun -s 1.1.1.3/32 -j LOGDROP
# confirm with a ping
#ping -n -c 4 -I 192.1.2.45 192.1.2.23
#ping -n -c 4 -I 2.2.2.3 1.1.1.3

ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ipip-sourceroute
ipsec auto --status
echo "initdone"
