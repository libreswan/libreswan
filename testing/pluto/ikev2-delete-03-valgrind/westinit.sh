/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 2 -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping
ping -n -c 1 -I 192.0.1.254 192.0.2.254
ipsec _stackmanager start
valgrind  --trace-children=yes --leak-check=full ipsec pluto --nofork  --config /etc/ipsec.conf &
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
