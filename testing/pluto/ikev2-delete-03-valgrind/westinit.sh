/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm clear text does not get through
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
valgrind  --trace-children=yes --leak-check=full ipsec pluto --nofork  --config /etc/ipsec.conf &
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
