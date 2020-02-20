/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
tcpdump -s 0 -i eth1 -w OUTPUT/east.eth1.cap & echo $! > OUTPUT/east.tcpdump.pid
echo "initdone"
