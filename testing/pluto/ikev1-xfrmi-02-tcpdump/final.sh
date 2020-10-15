../bin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
../bin/tcpdump.sh --stop
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
