ipsec whack --trafficstatus
ipsec status | grep "STATE_"
: ==== cut ====
ipsec status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
