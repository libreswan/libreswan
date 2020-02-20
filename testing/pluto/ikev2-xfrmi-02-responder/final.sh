../bin/xfrmcheck.sh
ipsec whack --trafficstatus
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
hostname | grep east > /dev/null && kill -TERM -p $(cat OUTPUT/east.tcpdump.pid) 
hostname | grep east > /dev/null && tcpdump -n -r OUTPUT/east.eth1.cap not arp and not ip6
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
