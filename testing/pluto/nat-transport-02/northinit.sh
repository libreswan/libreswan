/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.1.2.23
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23 -p tcp --sport 3 -j REJECT
iptables -A OUTPUT -o eth1 -d 192.1.2.23 -p tcp --dport 3 -j REJECT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-port3
ipsec auto --add north-east-pass
echo done
