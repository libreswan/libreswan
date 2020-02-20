/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
rm -fr /tmp/east.ikev2-xfrmi-02-responder.pcap
tcpdump -s 0 -i eth1 -w /tmp/east.ikev2-xfrmi-02-responder.pcap > /dev/nulll & echo $! > /tmp/east.ikev2-xfrmi-02-responder.pid
echo "initdone"
