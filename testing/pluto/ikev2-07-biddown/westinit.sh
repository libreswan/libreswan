/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# drop a bunch of IKE packets
iptables -F OUTPUT
iptables -A OUTPUT -o eth1 -p udp --dport 500 -m recent --rcheck --hitcount 6 -j ACCEPT
iptables -A OUTPUT -o eth1 -p udp --dport 500 -m recent --set -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ipv4
echo "initdone"
