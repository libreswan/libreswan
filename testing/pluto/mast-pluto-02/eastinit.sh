: ==== start ====
TESTNAME=mast-pluto-02
source /testing/pluto/bin/eastlocal.sh

# make sure that clear text does not get through
iptables -I INPUT 1 -i eth1  -s 192.1.2.45/32 -j DROP

# let ESP and port 500
iptables -I INPUT 1 -i eth1 -p 50 	       -j ACCEPT
iptables -I INPUT 1 -i eth1 -p udp --dport 500  -j ACCEPT
iptables -I INPUT 1 -i eth1 -p udp --dport 4500 -j ACCEPT

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east
ipsec whack --debug-control --debug-controlmore --debug-klips
