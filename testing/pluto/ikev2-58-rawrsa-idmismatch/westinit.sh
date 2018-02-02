/testing/guestbin/swan-prep
# confirm that the network is alive
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-westnet-eastnet
ipsec auto --listpubkeys
ipsec auto --status | grep west-westnet-eastnet
echo "initdone"
