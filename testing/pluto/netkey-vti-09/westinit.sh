/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -A INPUT -i eth1 -s 10.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# remove this address from eth0. It will come back on vti
../../guestbin/ip.sh address show dev eth0 | grep 192.0.1.254 && ../../guestbin/ip.sh address del 192.0.1.254/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-vti-01
ipsec auto --add westnet-eastnet-vti-02
# remove the regular route for 192.0.2.0/24
../../guestbin/ip.sh route del 192.0.2.0/24
echo "initdone"
