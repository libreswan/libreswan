/testing/guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# adding some routes to sow confusion on purpose
../../guestbin/ip.sh route add 192.168.1.1 via 192.0.1.254 dev eth0
../../guestbin/ip.sh route add 192.168.1.2 via 192.1.2.45 dev eth1
../../guestbin/ip.sh route add 192.168.1.16/28 via 192.1.2.45 dev eth1
../../guestbin/ip.sh route add 25.1.0.0/16 via 192.0.1.254
../../guestbin/ip.sh route add 25.2.0.0/16 via 192.1.2.45
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-all
../../guestbin/ip.sh route list
for i in `seq 1 12`; do ipsec auto --add orient$i; done
ipsec auto --status |grep "[.][.][.]"
ipsec whack --impair suppress_retransmits
echo "initdone"
