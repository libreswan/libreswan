ipsec whack --trafficstatus
: ==== tuc ====
ipsec auto --status
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
