# No tunnels should have established but a shunt should exist
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
hostname | grep nic > /dev/null || ipsec whack --shuntstatus
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
