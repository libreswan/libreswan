: ==== start ====
TESTNAME=transport-02
source /testing/pluto/bin/westlocal.sh

iptables -F INPUT
iptables -F OUTPUT

# confirm that the network is alive
ping -n -c 4 192.0.2.254
telnet east-out 3 | wc -l
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23 -p tcp --sport 3 -j REJECT
iptables -A OUTPUT -o eth1 -d 192.1.2.23 -p tcp --dport 3 -j REJECT

# confirm with a ping to east-in
ping -n -c 4 192.0.2.254
telnet east-out 3 | wc -l

ipsec setup start
ipsec auto --add west--east-port3
ipsec auto --add west--east-pass
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --route west--east-pass
ipsec eroute
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

