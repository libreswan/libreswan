ipsec whack --trafficstatus
# ESP should show TFC for west and east
grep " IPsec SA established tunnel mode" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
