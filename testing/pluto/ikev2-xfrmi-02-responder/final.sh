../bin/xfrmcheck.sh
ipsec whack --trafficstatus
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
: ==== cut ====
hostname | grep east > /dev/null && kill -TERM -p $(cat /tmp/east.ikev2-xfrmi-02-responder.pid) ; (sleep 5; sync; cp /tmp/east.ikev2-xfrmi-02-responder.pcap OUTPUT/)
: ==== tuc ====
hostname | grep east > /dev/null && tcpdump -n -r OUTPUT/east.ikev2-xfrmi-02-responder.pcap not arp and not ip6 and not stp
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
