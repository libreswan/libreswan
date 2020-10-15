../bin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
../bin/tcpdump.sh --stop --host east
hostname | grep east > /dev/null && ip -s link show ipsec1
hostname | grep east > /dev/null && ip rule show
hostname | grep east > /dev/null && ip route show table 50
hostname | grep east > /dev/null && ip route
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
